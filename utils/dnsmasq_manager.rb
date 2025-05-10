#!/usr/bin/env ruby
# frozen_string_literal: true

# DNSMASQ manager for MacRouter utilities
# Provides functionality for managing DNSMASQ configuration

require_relative 'system_manager'
require_relative 'template_renderer'
require 'ipaddr'

module MacRouterUtils
  # Manages DNSMasq configuration
  class DNSMasqManager < SystemManager
    DNSMASQ_CONF = '/opt/homebrew/etc/dnsmasq.conf'
    RESOLV_CONF = '/etc/resolv.dnsmasq'
    DHCP_HOST_REGEX = /^dhcp-host=([^,]+),([^,]+),([^,\s]+)/

    def initialize(lan, ip, dhcp_range, domain, dns, add_mappings = [], remove_mappings = [], force = false, dns_options = {})
      @lan = lan
      @ip = ip
      @dhcp_range = dhcp_range
      @domain = domain
      @dns = dns
      @add_mappings = add_mappings
      @remove_mappings = remove_mappings
      @force = force

      # DNS caching configuration options
      @cache_size = dns_options[:cache_size] || 1000
      @min_ttl = dns_options[:min_ttl] || 60
      @max_ttl = dns_options[:max_ttl] || 3600
      @dns_servers = dns_options[:dns_servers] || [@dns]
      @resolv_file = RESOLV_CONF
    end

    def configure(nat_only_mode = false)
      begin
        # First check if Internet Sharing is enabled
        if internet_sharing_enabled?
          if nat_only_mode || @force
            # In NAT-only mode or force mode, just warn but continue
            logger.warn "===== INTERNET SHARING DETECTED (CONTINUING ANYWAY) ====="
            logger.warn "macOS Internet Sharing appears to be enabled, which normally conflicts"
            logger.warn "with our DNSMASQ DHCP server."
            logger.warn ""
            if nat_only_mode
              logger.warn "Since you're in NAT-only mode, we'll continue without starting DNSMASQ."
              logger.warn "This allows your Internet Sharing to handle DHCP while we manage NAT."
            else
              logger.warn "Since you used --force, we'll attempt to continue despite the conflict."
              logger.warn "This may cause DHCP issues if Internet Sharing is actually running."
            end
            logger.warn "================================================"

            # In NAT-only mode, we actually want to skip DNSMASQ setup entirely
            if nat_only_mode
              logger.info "Skipping DNSMASQ configuration in NAT-only mode"
              return true
            end
          else
            # In normal mode, error out
            logger.error "===== INTERNET SHARING CONFLICT DETECTED ====="
            logger.error "macOS Internet Sharing is currently enabled, which runs its own DHCP server (bootpd)."
            logger.error "This will conflict with our DNSMASQ DHCP server and prevent it from starting."
            logger.error ""
            logger.error "Please disable Internet Sharing in System Settings > Sharing before continuing."
            logger.error "After disabling Internet Sharing, try running this script again."
            logger.error "Options:"
            logger.error "1. Disable Internet Sharing and try again"
            logger.error "2. Use --only-nat to skip DNSMASQ and just set up NAT"
            logger.error "3. Use --force to attempt to continue anyway (not recommended)"
            logger.error "================================================"
            raise "Internet Sharing is enabled and will conflict with DNSMASQ DHCP server"
          end
        end

        # First ensure dnsmasq is installed before any verification check
        # This fixes the "config file missing" error on first run
        ensure_dnsmasq_installed

        # Set up directories first - this helps prevent verification failures
        # on the first run when directories don't exist yet
        FileUtils.mkdir_p(File.dirname(DNSMASQ_CONF))
        execute_command_with_output('sudo mkdir -p /opt/homebrew/var/lib/misc')
        execute_command_with_output('sudo mkdir -p /opt/homebrew/var/log')

        # Now check if our DNSMASQ is already running with current config
        is_running = verify_running
        if is_running && !config_changed?
          logger.info "DNSMASQ already running with current configuration, skipping reconfiguration"
          return
        end

        # Process static mappings
        process_static_mappings

        # Ensure log file has proper permissions
        execute_command_with_output('sudo touch /opt/homebrew/var/log/dnsmasq.log')

        # Generate and write config using sudo
        config_content = generate_config

        # Write to a temporary file first
        temp_conf = "/tmp/dnsmasq_config_#{Process.pid}.conf"
        File.write(temp_conf, config_content)

        # Use sudo to move it to the final location
        execute_command("sudo cp #{temp_conf} #{DNSMASQ_CONF}", "Failed to write to #{DNSMASQ_CONF}")
        execute_command("sudo chmod 644 #{DNSMASQ_CONF}", "Failed to set permissions on #{DNSMASQ_CONF}")
        File.unlink(temp_conf) if File.exist?(temp_conf)

        # Ensure log file permissions are set correctly
        execute_command_with_output('sudo touch /opt/homebrew/var/log/dnsmasq.log')
        execute_command_with_output('sudo chmod 644 /opt/homebrew/var/log/dnsmasq.log')
        execute_command_with_output('sudo chown nobody /opt/homebrew/var/log/dnsmasq.log')

        # Write resolv.conf with sudo since it's in a system directory
        temp_file = '/tmp/resolv.dnsmasq.tmp'

        # Support multiple DNS servers
        resolv_content = ""
        dns_servers = @dns_servers.is_a?(Array) ? @dns_servers : [@dns]

        # Make sure we have at least one known working DNS server
        if dns_servers.empty? || (dns_servers.size == 1 && dns_servers.first.nil?)
          # Add reliable fallback DNS servers
          dns_servers = ["1.1.1.1", "8.8.8.8"]
          logger.info "Using default DNS servers: #{dns_servers.join(', ')}"
        end

        # Add each DNS server to resolv.conf
        dns_servers.each do |server|
          next unless server && !server.empty?
          resolv_content += "nameserver #{server}\n"
        end

        # Add search domain if present
        resolv_content += "search #{@domain}\n" if @domain && !@domain.empty?

        logger.info "Setting up DNS resolvers: #{dns_servers.join(', ')}"
        File.write(temp_file, resolv_content)
        execute_command("sudo mv #{temp_file} #{RESOLV_CONF}", "Failed to write to #{RESOLV_CONF}")
        execute_command("sudo chmod 644 #{RESOLV_CONF}", "Failed to set permissions on #{RESOLV_CONF}")

        # If already running but config changed, just restart
        if is_running
          logger.info "DNSMASQ already running but configuration changed, restarting service"
          execute_command('sudo brew services restart dnsmasq', 'Failed to restart dnsmasq service')
          sleep(1)
          logger.info 'DNSMASQ restarted with new configuration'
          return
        end

        # For new installations or non-running service
        # Check service status
        service_status = execute_command_with_output('sudo brew services list | grep dnsmasq')

        # If the service is in an error state, try to repair it
        if service_status[:stdout].include?('error')
          logger.warn "DNSMASQ service is in error state, attempting to repair..."
          repair_dnsmasq_service
        end

        # Start or restart dnsmasq service
        execute_command('sudo brew services restart dnsmasq', 'Failed to restart dnsmasq service')

        # Give it a moment to start
        sleep(1)

        # Check if it's actually running
        unless verify_running
          # Try repair and restart
          logger.warn 'DNSMASQ not running after restart, attempting to repair and start again...'
          repair_dnsmasq_service
          execute_command('sudo brew services start dnsmasq', 'Failed to start dnsmasq service')
          sleep(2)

          # Check again and provide more detailed error if it fails
          unless verify_running
            # Get service logs for debugging
            logs = execute_command_with_output('brew services log dnsmasq')[:stdout]
            raise "DNSMASQ service failed to start. Log output: #{logs}"
          end
        end

        logger.info 'DNSMASQ configured and restarted'
      rescue StandardError => e
        logger.error "Failed to configure DNSMASQ: #{e.message}", exception: e
        raise
      end
    end

    def uninstall
      begin
        # Stop and unload both homebrew and custom dnsmasq services
        execute_command('sudo brew services stop dnsmasq', 'Failed to stop dnsmasq service')
        logger.info 'Homebrew DNSMASQ service stopped'

        # Check and unload custom service if it exists
        custom_service_check = execute_command_with_output('sudo launchctl list | grep custom.dnsmasq')
        if custom_service_check[:success]
          execute_command('sudo launchctl unload -w /Library/LaunchDaemons/custom.dnsmasq.plist', 'Failed to unload custom dnsmasq service')
          execute_command('sudo rm -f /Library/LaunchDaemons/custom.dnsmasq.plist', 'Failed to remove custom dnsmasq plist')
          logger.info 'Custom DNSMASQ service stopped and removed'
        end

        # Kill any remaining processes
        execute_command_with_output('sudo pkill -f dnsmasq || true')

        # Remove configuration files
        if File.exist?(DNSMASQ_CONF)
          File.delete(DNSMASQ_CONF)
          logger.info "Removed #{DNSMASQ_CONF}"
        end

        if File.exist?(RESOLV_CONF)
          execute_command("sudo rm #{RESOLV_CONF}", "Failed to remove #{RESOLV_CONF}")
          logger.info "Removed #{RESOLV_CONF}"
        end

        # Cleanup any log files
        execute_command_with_output('sudo rm -f /tmp/dnsmasq.stderr /tmp/dnsmasq.stdout')
      rescue StandardError => e
        logger.error "Failed to uninstall DNSMASQ: #{e.message}", exception: e
        raise
      end
    end

    def list_static_mappings
      mappings = read_existing_mappings

      puts "\nStatic MAC to IP Mappings:"
      puts "=========================="

      if mappings.empty?
        puts "No static mappings configured."
        return
      end

      # Parse and display each mapping
      mappings.each do |mapping|
        parts = mapping.split(',')
        mac = parts[0]
        name = parts[1].sub(/^set:/, '') if parts[1]
        ip = parts[2] if parts[2]

        puts "MAC: #{mac} | Name: #{name} | IP: #{ip}"
      end

      puts "\nUse --add-static-mapping to add a mapping"
      puts "Use --remove-static-mapping to remove a mapping"
    end

    def verify_running
      logger.info "Performing comprehensive DNSMASQ service verification"

      # Step 1: Check if dnsmasq process is running (most reliable method)
      process_check = execute_command_with_output('pgrep -l dnsmasq')

      # If we find a dnsmasq process, that's the most reliable indicator it's running
      process_running = process_check[:success] && !process_check[:stdout].empty?
      if process_running
        # Found dnsmasq process - confirm the PID for logging
        pid = process_check[:stdout].split.first.strip rescue "unknown"
        logger.info "✅ DNSMASQ process found with PID #{pid}"
        return true
      end

      # No dnsmasq process was found - perform more detailed checks
      more_detailed_process = execute_command_with_output('ps aux | grep dnsmasq | grep -v grep')

      # Double-check with the more detailed process search
      detailed_process_running = more_detailed_process[:success] && !more_detailed_process[:stdout].empty?
      if detailed_process_running && more_detailed_process[:stdout].include?('dnsmasq')
        logger.info "✅ DNSMASQ process found with detailed search"
        return true
      end

      # Step 2: Check if any process is listening on DHCP port 67
      port_check = execute_command_with_output('sudo lsof -i :67')
      dhcp_listener = port_check[:success] && !port_check[:stdout].empty?

      # Check if it's our dnsmasq using port 67
      if dhcp_listener && port_check[:stdout].include?('dnsmasq')
        logger.info "✅ DNSMASQ is using port 67 (DHCP port)"
        return true
      elsif dhcp_listener
        # Some other process is using port 67
        process_name = "unknown"
        if port_check[:stdout].match(/\n(\S+)\s+\d+/)
          process_name = $1
        end
        logger.warn "⚠️ Port 67 is in use by another process: #{process_name}"
        logger.warn "This conflicts with DNSMASQ's DHCP functionality"
      end

      # Step 3: Check various service registrations
      homebrew_service_check = execute_command_with_output('sudo brew services list | grep dnsmasq')
      custom_service_check = execute_command_with_output('sudo launchctl list | grep custom.dnsmasq')
      launchdaemon_check = execute_command_with_output('ls -la /Library/LaunchDaemons/*dnsmasq*')

      # Check if any service shows as active
      homebrew_service_active = homebrew_service_check[:success] && homebrew_service_check[:stdout].include?('started')
      custom_service_active = custom_service_check[:success]

      # Final determination: dnsmasq is not running
      logger.warn "❌ DNSMASQ process is not running"

      # Return false - DNSMASQ is not running
      false
    end
    
    # Detailed diagnostics method
    def detailed_diagnostics(process_running, process_check, more_detailed_process, dhcp_listener, port_check,
                           homebrew_service_active, homebrew_service_check, custom_service_active,
                           custom_service_check, launchdaemon_check, is_running)
      logger.warn "Process check: #{process_running ? 'Passed' : 'Failed'} - #{process_check[:stdout]}"
      if more_detailed_process[:success] && !more_detailed_process[:stdout].empty?
        logger.warn "Process details: #{more_detailed_process[:stdout]}"
      end

      logger.warn "Port 67 usage: #{dhcp_listener ? 'Something is using DHCP port' : 'No DHCP service detected'}"
      if dhcp_listener
        logger.warn "Port 67 details: #{port_check[:stdout]}"
      end

      logger.warn "Homebrew service check: #{homebrew_service_active ? 'Passed' : 'Failed'} - #{homebrew_service_check[:stdout]}"
      logger.warn "Custom service check: #{custom_service_active ? 'Passed' : 'Failed'} - #{custom_service_check[:stdout]}"
      logger.warn "LaunchDaemon files: #{launchdaemon_check[:stdout]}"

      # Step 5: Check configuration
      if File.exist?(DNSMASQ_CONF)
        config_check = execute_command_with_output("cat #{DNSMASQ_CONF} | grep -v '^#' | grep -v '^$'")
        logger.warn "Config file exists: Yes"
        logger.warn "Config content (excluding comments):"
        logger.warn config_check[:stdout]

        # Check permissions
        perm_check = execute_command_with_output("ls -la #{DNSMASQ_CONF}")
        logger.warn "Config permissions: #{perm_check[:stdout]}"
      else
        logger.warn "Config file exists: No - Config file is missing!"
      end

      # Step 6: Check executable
      bin_check = execute_command_with_output("ls -la /opt/homebrew/sbin/dnsmasq")
      logger.warn "DNSMASQ binary: #{bin_check[:success] ? bin_check[:stdout] : 'Not found!'}"

      # Step 7: Check logs
      if File.exist?('/tmp/dnsmasq.stderr')
        stderr = File.read('/tmp/dnsmasq.stderr').strip
        logger.warn "Custom DNSMASQ stderr: #{stderr.empty? ? 'Empty file' : stderr}"
      else
        logger.warn "Custom DNSMASQ stderr: File doesn't exist"
      end

      if File.exist?('/tmp/dnsmasq.stdout')
        stdout = File.read('/tmp/dnsmasq.stdout').strip
        logger.warn "Custom DNSMASQ stdout: #{stdout.empty? ? 'Empty file' : stdout}"
      else
        logger.warn "Custom DNSMASQ stdout: File doesn't exist"
      end

      # Step 8: Check system log for dnsmasq messages
      syslog_check = execute_command_with_output('grep -i dnsmasq /var/log/system.log | tail -10')
      if syslog_check[:success] && !syslog_check[:stdout].empty?
        logger.warn "Recent system log entries:"
        logger.warn syslog_check[:stdout]
      end

      # Step 9: If everything else has failed, try direct launch one last time
      if @force && !is_running
        logger.warn "Force mode enabled - Attempting to start DNSMASQ directly as a last resort..."
        # Attempt to run dnsmasq directly to see any immediate error messages
        direct_start = execute_command_with_output("sudo /opt/homebrew/sbin/dnsmasq --no-daemon --conf-file=#{DNSMASQ_CONF} --user=root")
        logger.warn "Direct start result: #{direct_start[:stdout]}"
        logger.warn "Direct start error: #{direct_start[:stderr]}"

        # Check if it's running now
        sleep(1)
        new_check = execute_command_with_output('pgrep -l dnsmasq')
        if new_check[:success] && !new_check[:stdout].empty?
          logger.info "✅ DNSMASQ service started via direct launch"
          return true
        end
      end

      return is_running
    end

    def flush_dns_cache
      begin
        # First, check if dnsmasq is running
        is_running = verify_running
        unless is_running
          logger.error "Cannot flush DNS cache: DNSMASQ is not running"
          return false
        end

        # Get PID of dnsmasq
        pid_check = execute_command_with_output('pgrep dnsmasq')
        unless pid_check[:success] && !pid_check[:stdout].empty?
          logger.error "Cannot flush DNS cache: Unable to find DNSMASQ process"
          return false
        end

        # Send SIGUSR1 signal to flush the cache
        # SIGUSR1 is the signal that tells dnsmasq to clear its cache
        pid = pid_check[:stdout].strip
        flush_result = execute_command_with_output("sudo kill -SIGUSR1 #{pid}")

        if flush_result[:success]
          logger.info "DNS cache flushed successfully"
          return true
        else
          logger.error "Failed to flush DNS cache: #{flush_result[:stderr]}"
          return false
        end
      rescue StandardError => e
        logger.error "Failed to flush DNS cache: #{e.message}", exception: e
        return false
      end
    end

    def check_status
      status = { installed: false, running: false, configured: false }

      # Check if dnsmasq is installed
      result = execute_command_with_output('brew list --formula | grep dnsmasq')
      status[:installed] = result[:success] && result[:stdout].include?('dnsmasq')

      if status[:installed]
        # First check if dnsmasq process is running (most reliable method)
        process_check = execute_command_with_output('pgrep -f dnsmasq')
        process_running = process_check[:success] && !process_check[:stdout].empty?

        # Then check if any of the services are running
        homebrew_check = execute_command_with_output('sudo brew services list | grep dnsmasq')
        homebrew_running = homebrew_check[:success] && homebrew_check[:stdout].include?('started')

        custom_check = execute_command_with_output('sudo launchctl list | grep custom.dnsmasq')
        custom_running = custom_check[:success] && !custom_check[:stdout].empty?

        # Consider it running if either the process is detected or any service shows as running
        status[:running] = process_running || homebrew_running || custom_running

        # Check if dnsmasq is configured
        if File.exist?(DNSMASQ_CONF)
          status[:configured] = true
          content = File.read(DNSMASQ_CONF)

          # Extract configuration details
          interface_match = content.match(/interface=([^\s]+)/)
          status[:interface] = interface_match[1] if interface_match

          dhcp_range_match = content.match(/dhcp-range=([^\s]+)/)
          status[:dhcp_range] = dhcp_range_match[1] if dhcp_range_match

          ip_match = content.match(/listen-address=([0-9.]+)/)
          status[:ip] = ip_match[1] if ip_match && ip_match[1] != '127.0.0.1'

          # Count static mappings
          mappings = read_existing_mappings
          status[:mappings_count] = mappings.size

          # Extract DNS caching configuration
          cache_size_match = content.match(/cache-size=([0-9]+)/)
          status[:cache_size] = cache_size_match[1].to_i if cache_size_match

          min_ttl_match = content.match(/min-cache-ttl=([0-9]+)/)
          status[:min_ttl] = min_ttl_match[1].to_i if min_ttl_match

          max_ttl_match = content.match(/max-ttl=([0-9]+)/)
          status[:max_ttl] = max_ttl_match[1].to_i if max_ttl_match

          # Check for DNS servers in resolv file
          if File.exist?(RESOLV_CONF)
            resolv_content = File.read(RESOLV_CONF)
            dns_servers = resolv_content.scan(/^nameserver\s+([0-9.]+)/).flatten
            status[:dns_servers] = dns_servers if dns_servers && !dns_servers.empty?
          end
        end
      end

      status
    end

    private

    def ensure_dnsmasq_installed
      # Check if dnsmasq is installed
      stdout, _, status = Open3.capture3('brew list --formula | grep dnsmasq')

      unless status.success? && stdout.include?('dnsmasq')
        logger.info 'DNSMASQ not found, installing...'
        execute_command('brew install dnsmasq', 'Failed to install dnsmasq')
        logger.info 'DNSMASQ installed successfully'
      else
        logger.info 'DNSMASQ is already installed'
      end
    end

    def process_static_mappings
      # Get existing mappings
      existing_mappings = read_existing_mappings

      # Extract MAC, name, and IP from existing mappings for duplicate checking
      existing_macs = []
      existing_names = []
      existing_ips = []

      existing_mappings.each do |mapping|
        parts = mapping.split(',')
        existing_macs << parts[0].upcase if parts[0]
        existing_names << parts[1].sub(/^set:/, '') if parts[1]
        existing_ips << parts[2] if parts[2]
      end

      # Process mappings to add
      @add_mappings.each do |mapping|
        mac, name, ip = parse_mapping(mapping)

        # Check for duplicates
        if existing_macs.include?(mac)
          logger.error "Cannot add mapping: MAC address #{mac} already exists"
          exit(1)
        end

        if existing_names.include?("set:#{name}")
          logger.error "Cannot add mapping: Name #{name} already exists"
          exit(1)
        end

        if existing_ips.include?(ip)
          logger.error "Cannot add mapping: IP address #{ip} already exists"
          exit(1)
        end

        # Format for dnsmasq: MAC,set:name,IP
        formatted_mapping = "#{mac},set:#{name},#{ip}"

        # Add to existing mappings
        existing_mappings << formatted_mapping
        existing_macs << mac
        existing_names << "set:#{name}"
        existing_ips << ip

        logger.info "Added static mapping: #{mac} → #{ip} (#{name})"
      end

      # Process mappings to remove
      @remove_mappings.each do |mapping_spec|
        removed = false

        # Check if it's a full mapping or just a MAC, name, or IP
        if mapping_spec.include?(',')
          # Full mapping specification
          mac, name, ip = parse_mapping(mapping_spec)
          formatted_mapping = "#{mac},set:#{name},#{ip}"

          if existing_mappings.delete(formatted_mapping)
            logger.info "Removed static mapping: #{mac} → #{ip} (#{name})"
            removed = true
          end
        else
          # Single value specification (MAC, name, or IP)
          mapping_spec = mapping_spec.strip

          # Try to interpret as MAC address
          if valid_mac?(mapping_spec)
            mac = mapping_spec.upcase
            to_remove = existing_mappings.select { |m| m.split(',')[0].upcase == mac }

            to_remove.each do |m|
              parts = m.split(',')
              existing_mappings.delete(m)
              logger.info "Removed static mapping with MAC #{parts[0]}: #{parts[0]} → #{parts[2]} (#{parts[1].sub(/^set:/, '')})"
              removed = true
            end
          # Try to interpret as IP address
          elsif valid_ip?(mapping_spec)
            ip = mapping_spec
            to_remove = existing_mappings.select { |m| m.split(',')[2] == ip }

            to_remove.each do |m|
              parts = m.split(',')
              existing_mappings.delete(m)
              logger.info "Removed static mapping with IP #{parts[2]}: #{parts[0]} → #{parts[2]} (#{parts[1].sub(/^set:/, '')})"
              removed = true
            end
          # Try to interpret as hostname
          elsif valid_hostname?(mapping_spec)
            name = mapping_spec
            to_remove = existing_mappings.select { |m| m.split(',')[1] == "set:#{name}" }

            to_remove.each do |m|
              parts = m.split(',')
              existing_mappings.delete(m)
              logger.info "Removed static mapping with name #{name}: #{parts[0]} → #{parts[2]} (#{parts[1].sub(/^set:/, '')})"
              removed = true
            end
          else
            logger.warn "Invalid mapping specification: #{mapping_spec}. Must be a valid MAC, IP, hostname, or full mapping."
          end
        end

        logger.warn "No matching mapping found for: #{mapping_spec}" unless removed
      end

      # Store updated mappings
      @static_mappings = existing_mappings
    end

    def read_existing_mappings
      mappings = []

      if File.exist?(DNSMASQ_CONF)
        File.readlines(DNSMASQ_CONF).each do |line|
          next unless line.start_with?('dhcp-host=')

          # Extract just the mapping part (without the dhcp-host= prefix)
          mapping = line.strip.sub(/^dhcp-host=/, '')
          mappings << mapping unless mapping.empty?
        end
      end

      mappings
    end

    def parse_mapping(mapping)
      mac, name, ip = mapping.split(',').map(&:strip)

      # Validate MAC address
      raise ArgumentError, "Invalid MAC address format: #{mac}. Expected format: AA:BB:CC:DD:EE:FF" unless valid_mac?(mac)

      # Validate hostname
      unless valid_hostname?(name)
        raise ArgumentError, "Invalid hostname: #{name}. Hostname should contain only letters, numbers, and hyphens"
      end

      # Validate IP address
      raise ArgumentError, "Invalid IP address: #{ip}. Expected format: xxx.xxx.xxx.xxx" unless valid_ip?(ip)

      [mac.upcase, name, ip]
    end

    def valid_mac?(mac)
      !!(mac =~ /^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$/i)
    end

    def valid_hostname?(name)
      !!(name =~ /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/)
    end

    def valid_ip?(ip)
      IPAddr.new(ip)
      true
    rescue IPAddr::InvalidAddressError, ArgumentError
      false
    end

    def internet_sharing_enabled?
      # We need at least two positive indicators to confirm Internet Sharing is running
      # Just checking settings is not enough as it can be misleading

      # 1. Check Internet Sharing setting in system preferences - this is not reliable by itself
      # Add error redirection to avoid issues when the file doesn't exist
      internet_sharing_setting = execute_command_with_output('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>/dev/null | grep -i enabled')
      is_enabled_in_settings = internet_sharing_setting[:success] && internet_sharing_setting[:stdout].include?('Enabled = 1')

      # Early return if the setting explicitly shows disabled - most reliable negative indicator
      if internet_sharing_setting[:success] && internet_sharing_setting[:stdout].include?('Enabled = 0')
        logger.info "Internet Sharing is explicitly disabled in system settings"
        return false
      end

      # 2. Check for bootpd process - most reliable indicator for Internet Sharing
      bootpd_check = execute_command_with_output('ps aux | grep bootpd | grep -v grep')
      bootpd_running = bootpd_check[:success] && !bootpd_check[:stdout].empty?

      # 3. Check if bootpd is specifically using DHCP port
      bootpd_port_check = execute_command_with_output('sudo lsof -i :67 | grep bootpd')
      bootpd_using_port = bootpd_port_check[:success] && !bootpd_port_check[:stdout].empty?

      # 4. Check for natd process which is part of Internet Sharing
      natd_check = execute_command_with_output('ps aux | grep natd | grep -v grep')
      natd_running = natd_check[:success] && !natd_check[:stdout].empty?

      # 5. Check for active bridge interface (often used by Internet Sharing)
      bridge_check = execute_command_with_output('ifconfig | grep bridge')
      active_bridge = bridge_check[:success] && !bridge_check[:stdout].empty?

      # Some indicators are more reliable than others
      # bootpd running and using DHCP port are the strongest indicators
      has_primary_indicator = bootpd_running || bootpd_using_port || natd_running

      # Settings and bridge interface by themselves are not reliable
      secondary_count = 0
      secondary_count += 1 if is_enabled_in_settings
      secondary_count += 1 if active_bridge

      # Log detailed information about what was detected
      logger.info "Internet Sharing detection results:"
      logger.info "- Settings indicate enabled: #{is_enabled_in_settings}"
      logger.info "- bootpd process running: #{bootpd_running} (PRIMARY)"
      logger.info "- bootpd using DHCP port: #{bootpd_using_port} (PRIMARY)"
      logger.info "- natd process running: #{natd_running} (PRIMARY)"
      logger.info "- Active bridge interface: #{active_bridge}"
      logger.info "- Has primary indicator: #{has_primary_indicator}"
      logger.info "- Secondary indicators count: #{secondary_count}/2"

      # Only consider Internet Sharing enabled if we have at least one PRIMARY indicator
      # Settings and bridge interface alone are not enough
      is_internet_sharing_enabled = has_primary_indicator

      if is_internet_sharing_enabled
        logger.warn "Internet Sharing appears to be ACTIVE (detected PRIMARY indicator: bootpd/natd)"

        # Check if we're in force mode
        if @force
          logger.warn "Force mode enabled - proceeding despite Internet Sharing being active"
          return false
        end

        # Show detailed evidence
        if bootpd_running
          logger.warn "Evidence: bootpd process - #{bootpd_check[:stdout]}"
        end
        if bootpd_using_port
          logger.warn "Evidence: bootpd on port 67 - #{bootpd_port_check[:stdout]}"
        end

        return true
      else
        # Now check if any other service is using port 67 (could be conflict even without Internet Sharing)
        # First check if ANY process is using port 67
        any_dhcp_check = execute_command_with_output('sudo lsof -i :67')

        # Then extract all process names to identify them
        if any_dhcp_check[:success] && !any_dhcp_check[:stdout].empty?
          # Check if it's OUR dnsmasq process that's already running
          if any_dhcp_check[:stdout].include?('dnsmasq')
            # Our dnsmasq is already running - check if config changed
            if config_changed?
              logger.info "Our dnsmasq is already running on port 67, but configuration has changed"
              logger.info "Will restart dnsmasq with new configuration"

              # Stop existing dnsmasq service and wait for port to be freed
              logger.info "Stopping existing dnsmasq service..."
              execute_command_with_output('sudo brew services stop dnsmasq')
              execute_command_with_output('sudo launchctl unload -w /Library/LaunchDaemons/custom.dnsmasq.plist 2>/dev/null || true')
              execute_command_with_output('sudo pkill -f dnsmasq || true')

              # Give it a moment to fully stop
              sleep(2)

              # Check if port is freed
              port_check = execute_command_with_output('sudo lsof -i :67')
              if port_check[:success] && !port_check[:stdout].empty?
                logger.warn "Failed to stop existing dnsmasq service cleanly"
                logger.warn "Port 67 is still in use by:"
                logger.warn port_check[:stdout]

                if @force
                  logger.warn "Force mode enabled - proceeding anyway"
                  return false
                else
                  logger.error "Cannot restart dnsmasq - port 67 is still in use"
                  logger.error "Use --force to attempt to continue anyway"
                  return true
                end
              else
                logger.info "Successfully stopped existing dnsmasq service"
              end
            else
              logger.info "Our dnsmasq is already running on port 67 with correct configuration"
              return false # Not a conflict
            end
          else
            # Some other process (not our dnsmasq) is using port 67
            # Extract the process name for better error reporting
            process_name = "unknown"
            if any_dhcp_check[:stdout].match(/\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)/)
              process_name = $1
            else
              # Try alternate regex for different lsof output formats
              process_match = any_dhcp_check[:stdout].split("\n").grep(/\b67\b/).first
              if process_match && process_match.split.length > 0
                process_name = process_match.split.first
              end
            end

            if process_name.include?("dnsmasq")
              # It's probably our dnsmasq from a previous run
              logger.info "Process dnsmasq is using port 67 - likely from a previous run"
              logger.info "Will attempt to reconfigure existing dnsmasq service"
              return false
            elsif @force
              logger.warn "Another service (#{process_name}) is using DHCP port 67, but proceeding due to force mode"
              logger.warn "Port 67 usage details:"
              logger.warn any_dhcp_check[:stdout]
              return false
            else
              logger.error "Another service (#{process_name}) is using DHCP port 67:"
              logger.error any_dhcp_check[:stdout]
              logger.error "This will conflict with our DNSMASQ DHCP server"
              if process_name == "bootpd"
                logger.error "bootpd is Apple's DHCP server used by Internet Sharing"
                logger.error "Please disable Internet Sharing or use --only-nat mode"
              end
              return true
            end
          end
        end

        logger.info "Internet Sharing appears to be INACTIVE"
        return false
      end
    end

    # Checks if the configuration has changed compared to current config
    def config_changed?
      # If configuration file doesn't exist yet, it's definitely changed
      return true unless File.exist?(DNSMASQ_CONF)

      # Generate new config based on current parameters
      new_config = generate_config
      # Read existing config
      current_config = File.read(DNSMASQ_CONF)

      # Compare configs, ignoring whitespace and comments
      clean_new = new_config.lines.reject { |l| l.strip.empty? || l.strip.start_with?('#') }.map(&:strip).join("\n")
      clean_current = current_config.lines.reject { |l| l.strip.empty? || l.strip.start_with?('#') }.map(&:strip).join("\n")

      # Return true if configs differ, false if they're the same
      clean_new != clean_current
    end

    def generate_config
      renderer = MacRouterUtils::TemplateRenderer.new

      variables = {
        lan: @lan,
        dhcp_range: @dhcp_range,
        domain: @domain,
        ip: @ip,
        static_mappings: @static_mappings,
        # DNS caching options
        cache_size: @cache_size,
        min_ttl: @min_ttl,
        max_ttl: @max_ttl,
        resolv_file: @resolv_file
      }

      renderer.render('dnsmasq_config', variables)
    end

    def repair_dnsmasq_service
      logger.info "Repairing DNSMASQ service (comprehensive repair)..."

      # Step 1: Stop all services
      logger.info "Step 1: Stopping existing services"
      execute_command_with_output('sudo brew services stop dnsmasq || true')
      execute_command_with_output('sudo launchctl unload -w /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist 2>/dev/null || true')
      execute_command_with_output('sudo launchctl unload -w /Library/LaunchDaemons/custom.dnsmasq.plist 2>/dev/null || true')

      # Step 2: Remove any existing service plists
      logger.info "Step 2: Removing existing service plists"
      execute_command_with_output('sudo rm -f /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist')
      execute_command_with_output('sudo rm -f ~/Library/LaunchAgents/homebrew.mxcl.dnsmasq.plist')
      execute_command_with_output('sudo rm -f /Library/LaunchDaemons/custom.dnsmasq.plist')

      # Step 3: Kill all dnsmasq processes
      logger.info "Step 3: Killing all dnsmasq processes"
      execute_command_with_output('sudo pkill -f dnsmasq || true')
      # Wait to ensure processes are terminated
      sleep(1)

      # Step 4: Check for port 67 usage (DHCP port)
      logger.info "Step 4: Checking for DHCP port usage"
      port_check = execute_command_with_output('sudo lsof -i :67')
      if port_check[:success] && !port_check[:stdout].empty?
        logger.warn "Found processes using DHCP port 67:"
        logger.warn port_check[:stdout]
        logger.warn "Attempting to terminate these processes..."

        # Extract PIDs
        pids = port_check[:stdout].lines.drop(1).map do |line|
          line.strip.split[1]
        end.uniq.compact

        # Kill each PID individually
        pids.each do |pid|
          execute_command_with_output("sudo kill -9 #{pid} 2>/dev/null || true")
        end

        # Wait to ensure processes are terminated
        sleep(2)
      end

      # Step 5: Reset Homebrew services
      logger.info "Step 5: Cleaning up Homebrew services"
      execute_command_with_output('brew services cleanup || true')

      # Step 6: Ensure proper permissions for directories
      logger.info "Step 6: Setting up directories and permissions"
      # Create required directories
      execute_command_with_output('sudo mkdir -p /opt/homebrew/var/lib/misc')
      execute_command_with_output('sudo mkdir -p /opt/homebrew/var/log')
      execute_command_with_output('sudo mkdir -p /opt/homebrew/etc')

      # Set proper permissions
      execute_command_with_output('sudo chown -R $(whoami):admin /opt/homebrew/var/lib/misc')
      execute_command_with_output('sudo chown -R $(whoami):admin /opt/homebrew/var/log')
      execute_command_with_output('sudo chown -R $(whoami):admin /opt/homebrew/etc')

      # Ensure log file exists and has correct permissions
      execute_command_with_output('sudo touch /opt/homebrew/var/log/dnsmasq.log')
      execute_command_with_output('sudo chmod 644 /opt/homebrew/var/log/dnsmasq.log')
      execute_command_with_output('sudo chown nobody /opt/homebrew/var/log/dnsmasq.log')

      # Step 7: Repair Homebrew dnsmasq installation
      logger.info "Step 7: Repairing dnsmasq installation"
      execute_command_with_output('sudo brew uninstall dnsmasq --force || true')
      execute_command_with_output('brew install dnsmasq')

      # Fix permissions on Homebrew paths
      execute_command_with_output('sudo chown -R $(whoami):admin /opt/homebrew/Cellar/dnsmasq 2>/dev/null || true')
      execute_command_with_output('sudo chown -R $(whoami):admin /opt/homebrew/opt/dnsmasq 2>/dev/null || true')
      execute_command_with_output('sudo chown -R $(whoami):admin /opt/homebrew/var/homebrew/linked/dnsmasq 2>/dev/null || true')

      # Step 8: Create a custom LaunchDaemon with broader permissions
      logger.info "Step 8: Creating custom LaunchDaemon"
      custom_plist = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
        <dict>
          <key>Label</key>
          <string>custom.dnsmasq</string>
          <key>ProgramArguments</key>
          <array>
            <string>/opt/homebrew/sbin/dnsmasq</string>
            <string>--keep-in-foreground</string>
            <string>--conf-file=#{DNSMASQ_CONF}</string>
            <string>--user=root</string>
          </array>
          <key>RunAtLoad</key>
          <true/>
          <key>KeepAlive</key>
          <true/>
          <key>StandardErrorPath</key>
          <string>/tmp/dnsmasq.stderr</string>
          <key>StandardOutPath</key>
          <string>/tmp/dnsmasq.stdout</string>
          <key>UserName</key>
          <string>root</string>
          <key>GroupName</key>
          <string>wheel</string>
        </dict>
      </plist>
      XML

      custom_plist_path = '/Library/LaunchDaemons/custom.dnsmasq.plist'
      temp_plist_path = '/tmp/custom.dnsmasq.plist'

      # Write and install custom plist
      File.write(temp_plist_path, custom_plist)
      execute_command_with_output("sudo mv #{temp_plist_path} #{custom_plist_path}")
      execute_command_with_output("sudo chown root:wheel #{custom_plist_path}")
      execute_command_with_output("sudo chmod 644 #{custom_plist_path}")

      # Step 9: Try again with our config file (make sure it exists and has correct permissions)
      logger.info "Step 9: Ensuring config file has proper permissions"
      if File.exist?(DNSMASQ_CONF)
        execute_command_with_output("sudo chmod 644 #{DNSMASQ_CONF}")
        execute_command_with_output("sudo chown root:wheel #{DNSMASQ_CONF}")
      else
        # Generate minimal config to get started
        min_config = "# Minimal dnsmasq configuration\ndomain-needed\nbogus-priv\nlisten-address=127.0.0.1\n"
        File.write('/tmp/min_dnsmasq.conf', min_config)
        execute_command_with_output("sudo mv /tmp/min_dnsmasq.conf #{DNSMASQ_CONF}")
        execute_command_with_output("sudo chmod 644 #{DNSMASQ_CONF}")
        execute_command_with_output("sudo chown root:wheel #{DNSMASQ_CONF}")
      end

      # Step 10: Load the custom service
      logger.info "Step 10: Loading custom DNSMASQ service"
      execute_command_with_output("sudo launchctl load -w #{custom_plist_path}")

      # Wait for service to start
      sleep(3)

      # Step 11: Verify service is running
      logger.info "Step 11: Verifying if repair was successful"
      process_check = execute_command_with_output('pgrep -l dnsmasq')
      if process_check[:success] && !process_check[:stdout].empty?
        logger.info "✅ DNSMASQ service repair successful - process is running:"
        logger.info process_check[:stdout]
      else
        # Try one last direct launch to see any errors
        logger.warn "❌ DNSMASQ service not running after repair, trying direct launch..."
        direct_launch = execute_command_with_output('sudo /opt/homebrew/sbin/dnsmasq --keep-in-foreground --conf-file=/opt/homebrew/etc/dnsmasq.conf --user=root --no-daemon')
        logger.warn "Direct launch output: #{direct_launch[:stdout]}"
        logger.warn "Direct launch error: #{direct_launch[:stderr]}"
      end

      logger.info "DNSMASQ service repair complete"
    end

    def flush_dns_cache
      begin
        # First, check if dnsmasq is running
        is_running = verify_running
        unless is_running
          logger.error "Cannot flush DNS cache: DNSMASQ is not running"
          return false
        end

        # Get PID of dnsmasq
        pid_check = execute_command_with_output('pgrep dnsmasq')
        unless pid_check[:success] && !pid_check[:stdout].empty?
          logger.error "Cannot flush DNS cache: Unable to find DNSMASQ process"
          return false
        end

        # Send SIGUSR1 signal to flush the cache
        # SIGUSR1 is the signal that tells dnsmasq to clear its cache
        pid = pid_check[:stdout].strip
        flush_result = execute_command_with_output("sudo kill -SIGUSR1 #{pid}")

        if flush_result[:success]
          logger.info "DNS cache flushed successfully"
          return true
        else
          logger.error "Failed to flush DNS cache: #{flush_result[:stderr]}"
          return false
        end
      rescue StandardError => e
        logger.error "Failed to flush DNS cache: #{e.message}", exception: e
        return false
      end
    end

    def show_dns_stats
      begin
        # First, check if dnsmasq is running
        is_running = verify_running
        unless is_running
          puts "Cannot show DNS statistics: DNSMASQ is not running"
          return
        end

        # Read configuration
        if File.exist?(DNSMASQ_CONF)
          content = File.read(DNSMASQ_CONF)

          # Extract cache size
          cache_size_match = content.match(/cache-size=([0-9]+)/)
          cache_size = cache_size_match ? cache_size_match[1].to_i : "Default"

          # Extract TTL settings
          min_ttl_match = content.match(/min-cache-ttl=([0-9]+)/)
          min_ttl = min_ttl_match ? min_ttl_match[1].to_i : "Default"

          max_ttl_match = content.match(/max-ttl=([0-9]+)/)
          max_ttl = max_ttl_match ? max_ttl_match[1].to_i : "Default"

          puts "\nDNS Cache Configuration:"
          puts "======================="
          puts "Cache Size: #{cache_size} entries"
          puts "Min TTL: #{min_ttl} seconds"
          puts "Max TTL: #{max_ttl} seconds"
        end

        # Get upstream DNS servers
        if File.exist?(RESOLV_CONF)
          resolv_content = File.read(RESOLV_CONF)
          dns_servers = resolv_content.scan(/^nameserver\s+([0-9.]+)/).flatten

          if dns_servers && !dns_servers.empty?
            puts "\nUpstream DNS Servers:"
            dns_servers.each_with_index do |server, index|
              puts "#{index + 1}. #{server}"
            end
          end
        end

        # Check log file for query stats
        log_file = '/opt/homebrew/var/log/dnsmasq.log'
        if File.exist?(log_file)
          # Get total DNS queries
          query_count = execute_command_with_output("grep -c 'query\\[A\\]' #{log_file}")
          queries = query_count[:success] ? query_count[:stdout].to_i : 0

          # Get cache hits (queries that were returned from cache)
          cache_hits = execute_command_with_output("grep -c 'cached' #{log_file}")
          hits = cache_hits[:success] ? cache_hits[:stdout].to_i : 0

          # Most queried domains (top 5)
          popular_domains = execute_command_with_output("grep 'query\\[A\\]' #{log_file} | awk '{print $6}' | sort | uniq -c | sort -rn | head -5")

          puts "\nDNS Query Statistics (since log started):"
          puts "Total DNS Queries: #{queries}"

          if queries > 0
            hit_rate = (hits.to_f / queries * 100).round(2)
            puts "Cache Hits: #{hits} (#{hit_rate}% cache hit rate)"
          else
            puts "Cache Hits: 0 (0% cache hit rate)"
          end

          if popular_domains[:success] && !popular_domains[:stdout].empty?
            puts "\nMost Popular Domains:"
            puts popular_domains[:stdout]
          end

          # Recent queries (last 5)
          recent_queries = execute_command_with_output("grep 'query\\[A\\]' #{log_file} | tail -5")
          if recent_queries[:success] && !recent_queries[:stdout].empty?
            puts "\nRecent DNS Queries:"
            puts recent_queries[:stdout]
          end
        else
          puts "No DNS log file found at #{log_file}"
        end
      rescue StandardError => e
        puts "Error retrieving DNS statistics: #{e.message}"
      end
    end
    # Make show_dns_stats and flush_dns_cache public methods
    public :show_dns_stats, :flush_dns_cache
  end
end