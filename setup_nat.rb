#!/usr/bin/env ruby
# frozen_string_literal: true

#
# NAT Setup Script for macOS
# ==========================
#
# This script sets up Network Address Translation (NAT) on macOS, allowing you to share
# your internet connection with devices connected to a secondary network interface.
#
# During setup, the script:
# - Enables IP forwarding via sysctl
# - Configures packet filtering (PF) for NAT
# - Sets up DNSMASQ for DHCP and DNS services
# - Configures a network interface with a static IP
# - Optionally adds static MAC to IP mappings
#
# During uninstall, the script:
# - Disables IP forwarding
# - Restores the original PF configuration
# - Stops and unloads DNSMASQ service
# - Removes DNSMASQ configuration files
# - Optionally resets the LAN interface configuration
#
# Usage examples:
#   ./setup_nat.rb --list-interfaces                        # List available network interfaces
#   ./setup_nat.rb --list-static-mappings                   # List current static MAC to IP mappings
#   ./setup_nat.rb --status                                 # Show current NAT setup status
#   ./setup_nat.rb --wan-interface en0 --lan-interface en5  # Basic setup
#   ./setup_nat.rb --only-dhcp --lan-interface en5          # Setup only DHCP server without NAT
#   ./setup_nat.rb --uninstall                              # Remove NAT configuration

require_relative 'utils'
require 'ipaddr'
require 'open3'
require 'fileutils'

# Use the shared NetworkUtils module
NetworkUtils = MacRouterUtils::NetworkUtils

# Main class for setting up NAT
class NatSetup < MacRouterUtils::SetupBase
  def initialize(options)
    @options = options

    # Skip validation for utility commands that don't need the interfaces
    skip_validation = @options[:uninstall] ||
                      @options[:list_static_mappings] ||
                      @options[:list_dhcp_leases] ||
                      @options[:status] ||
                      @options[:dns_stats] ||
                      @options[:flush_dns_cache]

    # Check for mutually exclusive options
    if @options[:only_dhcp] && @options[:only_nat]
      raise ArgumentError, "Cannot use both --only-dhcp and --only-nat options together"
    end

    validate_required_options! unless skip_validation

    # Set default values for optional parameters
    @options[:static_ip] ||= '192.168.100.1'
    @options[:dhcp_range] ||= '192.168.100.10,192.168.100.100,12h'
    @options[:domain] ||= 'local'
    @options[:dns] ||= '1.1.1.1'
    @options[:add_static_mappings] ||= []
    @options[:remove_static_mappings] ||= []
    @options[:dns_cache_size] ||= 10000
    @options[:dns_min_ttl] ||= 60
    @options[:dns_max_ttl] ||= 3600
    @options[:dns_servers] ||= []
  end

  def setup
    if @options[:only_dhcp]
      logger.info 'Starting DHCP-only configuration...'

      begin
        dnsmasq_manager.configure(false) # false = not in nat_only_mode
        interface_manager.configure

        # Verify DHCP service is running
        verify_dhcp_service

        logger.info 'DHCP-only configuration complete.'
      rescue StandardError => e
        logger.error "DHCP configuration failed: #{e.message}", exception: e
        exit(1)
      end
    elsif @options[:only_nat]
      logger.info 'Starting NAT-only configuration (compatible with Internet Sharing)...'

      # For NAT-only mode, we don't need DNSMASQ at all, so we'll skip it entirely
      # This is the most reliable approach and prevents conflicts with Internet Sharing

      begin
        logger.info 'In NAT-only mode - skipping DNSMASQ setup completely'
        sysctl_manager.ensure_ip_forwarding
        pf_manager.configure
        interface_manager.configure

        # Verify NAT service is running, but don't fail if DNSMASQ isn't running
        # since we're in NAT-only mode and don't need DHCP
        begin
          verify_nat_service
        rescue StandardError => e
          # For NAT-only mode, just log the error but continue
          logger.warn "NAT verification warning: #{e.message}"
          logger.info "Continuing anyway since we're in NAT-only mode and DHCP isn't required"
        end

        logger.info 'NAT-only configuration complete.'
      rescue StandardError => e
        logger.error "NAT configuration failed: #{e.message}", exception: e
        exit(1)
      end
    else
      logger.info 'Starting full NAT configuration...'

      begin
        sysctl_manager.ensure_ip_forwarding
        pf_manager.configure

        # Update blacklists before configuring dnsmasq
        logger.info 'Updating DNS blacklists...'
        blacklist_dir = File.join(File.dirname(__FILE__), 'blacklists')
        whitelist_path = File.join(blacklist_dir, 'whitelist.txt')
        FileUtils.mkdir_p(blacklist_dir) unless Dir.exist?(blacklist_dir)
        blacklist_update_cmd = File.join(File.dirname(__FILE__), 'utils/update_blacklists.rb')
        blacklist_update_cmd += " --verbose --whitelist #{whitelist_path} --output /opt/homebrew/etc/dnsmasq.blacklist"
        # Use sudo to ensure we can write to the destination directory
        update_result = execute_command_with_output("sudo #{blacklist_update_cmd}")
        if update_result[:success]
          logger.info 'DNS blacklists updated successfully'
        else
          logger.warn "Failed to update DNS blacklists: #{update_result[:stderr]}"
          logger.warn "Will continue setup with existing or default blacklists"
        end

        dnsmasq_manager.configure(false) # false = not in nat_only_mode
        interface_manager.configure

        # Verify all services are running
        verify_services

        logger.info 'Full NAT configuration complete.'
      rescue StandardError => e
        logger.error "Configuration failed: #{e.message}", exception: e
        exit(1)
      end
    end
  end

  def uninstall
    if @options[:only_dhcp]
      logger.info 'Starting DHCP-only uninstallation...'

      begin
        # Uninstall in reverse order
        interface_manager.uninstall if @options[:lan_interface]
        dnsmasq_manager.uninstall

        logger.info 'DHCP-only uninstallation complete.'
      rescue StandardError => e
        logger.error "DHCP-only uninstallation failed: #{e.message}", exception: e
        exit(1)
      end
    elsif @options[:only_nat]
      logger.info 'Starting NAT-only uninstallation...'

      begin
        # Uninstall in reverse order
        interface_manager.uninstall if @options[:wan_interface] && @options[:lan_interface]
        pf_manager.uninstall
        sysctl_manager.uninstall

        logger.info 'NAT-only uninstallation complete.'
      rescue StandardError => e
        logger.error "NAT-only uninstallation failed: #{e.message}", exception: e
        exit(1)
      end
    else
      logger.info 'Starting full NAT uninstallation...'

      begin
        # Uninstall in reverse order
        interface_manager.uninstall if @options[:wan_interface] && @options[:lan_interface]
        dnsmasq_manager.uninstall
        pf_manager.uninstall
        sysctl_manager.uninstall

        logger.info 'Full NAT uninstallation complete.'
      rescue StandardError => e
        logger.error "Uninstallation failed: #{e.message}", exception: e
        exit(1)
      end
    end
  end

  def list_static_mappings
    dnsmasq_manager.list_static_mappings
  rescue StandardError => e
    logger.error "Failed to list static mappings: #{e.message}", exception: e
    exit(1)
  end

  def list_dhcp_leases
    puts "\nCurrent DHCP Leases:"
    puts "==================="

    # Check for dnsmasq leases file in various possible locations
    possible_lease_locations = [
      '/var/lib/misc/dnsmasq.leases',
      '/opt/homebrew/var/lib/misc/dnsmasq.leases',
      '/usr/local/var/lib/misc/dnsmasq.leases',
      '/tmp/dnsmasq.leases'
    ]

    leases_file = possible_lease_locations.find { |path| File.exist?(path) }

    unless leases_file
      puts "No DHCP leases file found in standard locations."

      # Try to detect where dnsmasq might be storing leases
      dnsmasq_cmd = execute_command_with_output('ps aux | grep dnsmasq | grep -v grep')
      if dnsmasq_cmd[:success] && !dnsmasq_cmd[:stdout].empty?
        puts "\nDNSMASQ is running with the following command:"
        puts dnsmasq_cmd[:stdout]

        # Search for lease file in the command arguments
        lease_arg = dnsmasq_cmd[:stdout].match(/--dhcp-leasefile=([^\s]+)/)
        if lease_arg && lease_arg[1]
          custom_lease_file = lease_arg[1]
          puts "\nChecking custom lease file location: #{custom_lease_file}"
          if File.exist?(custom_lease_file)
            leases_file = custom_lease_file
          else
            puts "Custom lease file not found or empty."
          end
        end
      else
        puts "No dnsmasq process found running."
      end

      return unless leases_file
    end

    # Read and display leases
    leases = File.readlines(leases_file)
    if leases.empty?
      puts "No active DHCP leases found."
    else
      # Display header
      puts "Expiry Time          MAC Address        IP Address      Hostname"
      puts "--------------------------------------------------------------------"

      # Process each lease
      leases.each do |lease|
        fields = lease.strip.split(' ')
        next if fields.size < 4

        # Parse fields - format varies slightly between versions
        expiry_time = Time.at(fields[0].to_i).strftime('%Y-%m-%d %H:%M:%S')
        mac = fields[1]
        ip = fields[2]
        hostname = fields[3] == '*' ? '(Unknown)' : fields[3]

        puts "#{expiry_time}  #{mac}  #{ip.ljust(15)}  #{hostname}"
      end
    end

    # Show the source of leases
    puts "\nLeases file: #{leases_file}"

    # Show the dnsmasq process to confirm it's running
    dnsmasq_process = execute_command_with_output('ps aux | grep -v grep | grep dnsmasq')
    if dnsmasq_process[:success] && !dnsmasq_process[:stdout].empty?
      puts "\nDNSMASQ Process:"
      puts dnsmasq_process[:stdout]
    else
      puts "\nWarning: No dnsmasq process found running!"
    end

    # Check for log file and show recent DHCP activity
    log_file = '/opt/homebrew/var/log/dnsmasq.log'
    if File.exist?(log_file)
      puts "\nRecent DHCP activity from log (last 20 lines):"
      puts "-" * 60
      recent_logs = execute_command_with_output("grep -i dhcp #{log_file} | tail -n 20")
      if recent_logs[:success] && !recent_logs[:stdout].empty?
        puts recent_logs[:stdout]
      else
        puts "No recent DHCP activity found in logs."
      end
      puts "\nLog file location: #{log_file}"
    else
      # Try to find logs in syslog if dedicated log file doesn't exist
      puts "\nDNSMASQ log file not found. Checking system logs for DHCP activity:"
      syslog_check = execute_command_with_output('grep -i dnsmasq /var/log/system.log 2>/dev/null | grep -i dhcp | tail -n 10')
      if syslog_check[:success] && !syslog_check[:stdout].empty?
        puts syslog_check[:stdout]
      else
        puts "No DNSMASQ DHCP activity found in system logs."
      end
    end
  rescue StandardError => e
    logger.error "Failed to list DHCP leases: #{e.message}", exception: e
    exit(1)
  end

  def show_status
    if @options[:only_dhcp]
      puts "\nDHCP-only Setup Status:"
      puts '======================'
    elsif @options[:only_nat]
      puts "\nNAT-only Setup Status (works with Internet Sharing):"
      puts '================================================'
    else
      puts "\nFull NAT Setup Status:"
      puts '===================='

      # Check IP forwarding status
      ip_forwarding_status = sysctl_manager.check_status
      if ip_forwarding_status.is_a?(Hash)
        # Use effective status when showing the indicator
        status_indicator = ip_forwarding_status[:effective_enabled] ? '✅' : '❌'

        if ip_forwarding_status[:enabled]
          puts "#{status_indicator} IP Forwarding: Enabled (via sysctl)"
        elsif ip_forwarding_status[:internet_sharing_active]
          # Only show as enabled if internet_sharing_active is true AND we've verified it with additional checks
          verified_internet_sharing = false

          # Check if Internet Sharing is actually active by checking for bootpd process
          bootpd_check = execute_command_with_output('ps aux | grep bootpd | grep -v grep')
          if bootpd_check[:success] && !bootpd_check[:stdout].empty?
            verified_internet_sharing = true
          end

          if verified_internet_sharing
            puts "#{status_indicator} IP Forwarding: Effectively enabled via Internet Sharing"
            puts "   Note: sysctl setting shows disabled, but Internet Sharing is active"
          else
            # This fixes the false positive after uninstallation
            puts "❌ IP Forwarding: Disabled"
            puts "   Note: Internet Sharing setting appears enabled but service is not running"
          end
        elsif ip_forwarding_status[:nat_traffic_detected]
          puts "#{status_indicator} IP Forwarding: Effectively enabled (NAT traffic detected)"
          puts "   Note: sysctl setting shows disabled, but NAT traffic is flowing"
        else
          puts "❌ IP Forwarding: Disabled"
        end

        # Show information about persistent configuration
        if ip_forwarding_status[:persistent]
          persistent_status = ip_forwarding_status[:persistent_active] ? '✅' : '⚠️'
          puts "#{persistent_status} IP Forwarding Persistence: Configured#{ip_forwarding_status[:persistent_active] ? ' and active' : ' but not active'}"
        elsif ip_forwarding_status[:internet_sharing_active] && verified_internet_sharing
          puts "✅ IP Forwarding Persistence: Managed by Internet Sharing"
        else
          puts "❌ IP Forwarding Persistence: Not configured"
        end
      else
        # For backward compatibility (if status is a boolean)
        status_indicator = ip_forwarding_status ? '✅' : '❌'
        puts "#{status_indicator} IP Forwarding: #{ip_forwarding_status ? 'Enabled' : 'Disabled'}"
      end

      # Check PF status
      pf_status = pf_manager.check_status
      status_indicator = pf_status[:enabled] ? '✅' : '❌'
      puts "#{status_indicator} Packet Filter (PF): #{pf_status[:enabled] ? 'Enabled' : 'Disabled'}"

      if pf_status[:nat_configured]
        # Verify NAT is actually configured by checking for active rules
        nat_rules_check = execute_command_with_output('sudo pfctl -s nat')
        nat_all_check = execute_command_with_output('sudo pfctl -s all | grep nat')

        nat_rules_active = (nat_rules_check[:success] && !nat_rules_check[:stdout].empty?) ||
                          (nat_all_check[:success] && !nat_all_check[:stdout].empty?)

        # For Internet Sharing, also check if bootpd is running
        internet_sharing_active = false
        if pf_status[:internet_sharing_enabled]
          bootpd_check = execute_command_with_output('ps aux | grep bootpd | grep -v grep')
          internet_sharing_active = bootpd_check[:success] && !bootpd_check[:stdout].empty?
        end

        if nat_rules_active || (pf_status[:internet_sharing_enabled] && internet_sharing_active)
          nat_indicator = '✅'
          puts "#{nat_indicator} NAT Configuration: Present"

          # Show who is managing NAT
          if pf_status[:managed_by_us]
            puts "   - Managed by: This application (MacRouterNas)"
            puts "   - Anchor file: #{pf_status[:anchor]}" if pf_status[:anchor]
          elsif pf_status[:internet_sharing_enabled] && internet_sharing_active
            puts "   - Managed by: macOS Internet Sharing"
          elsif pf_status[:managed_by_system]
            puts "   - Managed by: System or other application"
          else
            puts "   - Managed by: Unknown"
          end

          # Show interface information
          if pf_status[:interfaces]
            puts "   - WAN Interface: #{pf_status[:interfaces][:wan]}"
            puts "   - LAN Interface: #{pf_status[:interfaces][:lan]}" if pf_status[:interfaces][:lan]
          end
        else
          puts '❌ NAT Configuration: Not present'
        end
      else
        puts '❌ NAT Configuration: Not present'
      end
    end

    # Check DNSMASQ status
    dnsmasq_status = dnsmasq_manager.check_status
    status_indicator = dnsmasq_status[:installed] ? '✅' : '❌'
    puts "#{status_indicator} DNSMASQ: #{dnsmasq_status[:installed] ? 'Installed' : 'Not installed'}"
    if dnsmasq_status[:installed]
      running_indicator = dnsmasq_status[:running] ? '✅' : '❌'
      puts "#{running_indicator} - Service: #{dnsmasq_status[:running] ? 'Running' : 'Not running'}"
      if dnsmasq_status[:configured]
        puts '   - Configuration: Present'
        puts "   - Interface: #{dnsmasq_status[:interface]}" if dnsmasq_status[:interface]
        puts "   - Static IP: #{dnsmasq_status[:ip]}" if dnsmasq_status[:ip]
        puts "   - DHCP Range: #{dnsmasq_status[:dhcp_range]}" if dnsmasq_status[:dhcp_range]
        puts "   - Static Mappings: #{dnsmasq_status[:mappings_count]} configured" if dnsmasq_status[:mappings_count]

        # Display DNS caching configuration
        if dnsmasq_status[:cache_size]
          puts "\n   DNS Caching Information:"
          puts "   - Cache Size: #{dnsmasq_status[:cache_size]} entries"
          puts "   - Min TTL: #{dnsmasq_status[:min_ttl] || 'Default'} seconds"
          puts "   - Max TTL: #{dnsmasq_status[:max_ttl] || 'Default'} seconds"

          if dnsmasq_status[:dns_servers] && !dnsmasq_status[:dns_servers].empty?
            puts "   - DNS Servers:"
            dnsmasq_status[:dns_servers].each do |server|
              puts "     * #{server}"
            end
          else
            puts "   - DNS Server: #{@options[:dns]}"
          end
        end
      else
        puts '❌ - Configuration: Not present'
      end
    end

    # Check interface status if WAN and LAN are specified
    if @options[:wan_interface] && @options[:lan_interface]
      wan_status = interface_manager.check_wan_status(@options[:wan_interface])
      lan_status = interface_manager.check_lan_status

      status_indicator = wan_status[:active] ? '✅' : '❌'
      puts "#{status_indicator} WAN Interface (#{@options[:wan_interface]}): #{wan_status[:active] ? 'Active' : 'Inactive'}"
      puts "   - IP: #{wan_status[:ip]}" if wan_status[:active] && wan_status[:ip]

      status_indicator = lan_status[:active] ? '✅' : '❌'
      puts "#{status_indicator} LAN Interface (#{@options[:lan_interface]}): #{lan_status[:active] ? 'Active' : 'Inactive'}"
      if lan_status[:active]
        puts "   - IP: #{lan_status[:ip]}" if lan_status[:ip]
        lan_status[:has_static_ip] ? '✅' : '❌'
        puts "   - Static IP (#{@options[:static_ip]}): #{lan_status[:has_static_ip] ? 'Configured' : 'Not configured'}"
      end
    end

    puts "\n✅ = enabled/active, ❌ = disabled/inactive"
  end

  # Alias for show_status to match SetupBase interface
  def check_status
    show_status
  end

  # Alias for setup to match SetupBase interface
  def install
    setup
  end

  # Public method for accessing the dnsmasq manager
  def dnsmasq_manager
    # Prepare DNS options hash
    dns_options = {
      cache_size: @options[:dns_cache_size],
      min_ttl: @options[:dns_min_ttl],
      max_ttl: @options[:dns_max_ttl]
    }

    # Add DNS servers if specified, otherwise use the primary DNS
    dns_servers = @options[:dns_servers].empty? ? [@options[:dns]] : @options[:dns_servers]
    dns_options[:dns_servers] = dns_servers

    @dnsmasq_manager ||= MacRouterUtils::DNSMasqManager.new(
      @options[:lan_interface],
      @options[:static_ip],
      @options[:dhcp_range],
      @options[:domain],
      @options[:dns],
      @options[:add_static_mappings],
      @options[:remove_static_mappings],
      @options[:force],
      dns_options
    )
  end

  private

  def validate_required_options!
    if @options[:only_dhcp]
      return if @options[:lan_interface]

      logger.fatal 'LAN interface is required even with --only-dhcp option'
      exit(1)
    elsif @options[:only_nat]
      return if @options[:wan_interface] && @options[:lan_interface]

      logger.fatal 'Both WAN and LAN interfaces are required for NAT-only setup'
      exit(1)
    else
      return if @options[:wan_interface] && @options[:lan_interface]

      logger.fatal 'Both WAN and LAN interfaces are required for NAT setup'
      exit(1)
    end
  end

  def verify_services
    logger.info 'Verifying services...'

    # Verify PF is enabled
    raise 'Packet filter (PF) service is not running' unless pf_manager.verify_running

    # Verify DNSMASQ is running
    raise 'DNSMASQ service is not running' unless dnsmasq_manager.verify_running

    # Verify interface configuration
    raise 'Interface configuration failed' unless interface_manager.verify_configured

    logger.info 'All services verified and running'
  end

  def verify_dhcp_service
    logger.info 'Verifying DHCP service...'

    # Verify DNSMASQ is running
    unless dnsmasq_manager.verify_running
      # Check config file existence and permissions
      if File.exist?(MacRouterUtils::DNSMasqManager::DNSMASQ_CONF)
        config_content = File.read(MacRouterUtils::DNSMasqManager::DNSMASQ_CONF)
        logger.error "DNSMASQ config exists at #{MacRouterUtils::DNSMasqManager::DNSMASQ_CONF}:"
        logger.error "---CONFIG START---"
        logger.error config_content
        logger.error "---CONFIG END---"

        # Check file permissions
        permissions = execute_command_with_output("ls -la #{MacRouterUtils::DNSMasqManager::DNSMASQ_CONF}")
        logger.error "File permissions: #{permissions[:stdout]}"
      else
        logger.error "DNSMASQ config file not found!"
      end

      # Check if we can manually start the service
      logger.error "Attempting to manually start DNSMASQ..."
      manual_start = execute_command_with_output('sudo brew services start dnsmasq')
      logger.error "Manual start result: #{manual_start[:stdout]} #{manual_start[:stderr]}"

      # Check logs
      logs = execute_command_with_output('brew services log dnsmasq')
      logger.error "DNSMASQ logs: #{logs[:stdout]}"

      raise 'DNSMASQ service is not running'
    end

    # Verify interface configuration
    unless interface_manager.verify_configured
      # Get interface details
      interface_info = execute_command_with_output("ifconfig #{@options[:lan_interface]}")
      logger.error "Interface status: #{interface_info[:stdout]}"
      raise 'Interface configuration failed'
    end

    logger.info 'DHCP service verified and running'
  end

  def verify_nat_service
    logger.info 'Verifying NAT service (with enhanced diagnostics)...'

    # Step 1: Check IP forwarding status
    ip_forwarding_status = sysctl_manager.check_status
    logger.info "IP Forwarding status: #{ip_forwarding_status.is_a?(Hash) ? (ip_forwarding_status[:effective_enabled] ? 'Enabled' : 'Disabled') : ip_forwarding_status.to_s}"

    # Step 2: Check for Internet Sharing
    internet_sharing = execute_command_with_output('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>/dev/null | grep -i enabled')
    internet_sharing_enabled = internet_sharing[:success] && internet_sharing[:stdout].include?('Enabled = 1')
    if internet_sharing_enabled
      logger.info "Internet Sharing: Enabled in system preferences"

      # Check if Internet Sharing is actually active (bootpd running)
      bootpd_check = execute_command_with_output('ps aux | grep bootpd | grep -v grep')
      internet_sharing_active = bootpd_check[:success] && !bootpd_check[:stdout].empty?

      if internet_sharing_active
        logger.info "Internet Sharing: Active (bootpd is running)"
      else
        logger.warn "Internet Sharing: Enabled in preferences but not fully active (bootpd not running)"
      end
    else
      logger.info "Internet Sharing: Not enabled"
    end

    # Step 3: Check for PF NAT rules
    nat_rule_check = execute_command_with_output('sudo pfctl -s nat')
    has_nat_rules = nat_rule_check[:success] && !nat_rule_check[:stdout].strip.empty?

    if has_nat_rules
      logger.info "PF NAT rules: Found"
      logger.info "NAT rules detected: #{nat_rule_check[:stdout].strip}"
    else
      logger.warn "PF NAT rules: None found"
    end

    # Step 4: Check PF status
    pf_status = execute_command_with_output('sudo pfctl -s info | grep Status')
    pf_enabled = pf_status[:success] && pf_status[:stdout].include?('Enabled')

    if pf_enabled
      logger.info "PF status: Enabled"
    else
      logger.error "PF status: Disabled - PF must be enabled for NAT to work!"

      # Try to enable PF if it's disabled
      if @force
        logger.warn "Force mode enabled - Attempting to enable PF..."
        enable_result = execute_command_with_output('sudo pfctl -e')
        if enable_result[:success]
          logger.info "Successfully enabled PF"
          pf_enabled = true
        end
      end
    end

    # Step 5: Determine overall NAT functionality
    nat_working = false

    if (ip_forwarding_status.is_a?(Hash) && ip_forwarding_status[:effective_enabled]) || internet_sharing_active
      # IP forwarding enabled via sysctl or Internet Sharing
      if pf_enabled && has_nat_rules
        # Ideal scenario: IP forwarding + PF enabled + NAT rules
        nat_working = true
        logger.info "NAT status: ✅ Fully configured and active"
      elsif internet_sharing_active
        # Internet Sharing handles both IP forwarding and NAT
        nat_working = true
        logger.info "NAT status: ✅ Active via Internet Sharing"
      else
        # IP forwarding enabled but NAT might not be working
        logger.warn "NAT status: ⚠️ IP forwarding enabled but NAT configuration is incomplete"
      end
    else
      # IP forwarding not enabled explicitly
      if pf_enabled && has_nat_rules && @force
        # In force mode, trust that NAT is working even without explicit IP forwarding
        nat_working = true
        logger.warn "NAT status: ⚠️ PF and NAT rules found, but IP forwarding not explicitly enabled"
        logger.warn "Proceeding anyway due to force mode..."
      else
        # NAT can't work without IP forwarding
        logger.error "NAT status: ❌ Not working - IP forwarding is disabled"
      end
    end

    # Step 6: Check interface configuration
    interface_status = interface_manager.verify_configured
    if interface_status
      logger.info "LAN interface configuration: ✅ Properly configured with static IP"
    else
      # Get detailed interface info for troubleshooting
      interface_info = execute_command_with_output("ifconfig #{@options[:lan_interface]}")
      logger.error "LAN interface configuration: ❌ Not properly configured"
      logger.error "Interface details: #{interface_info[:stdout]}"

      if @force
        logger.warn "Force mode enabled - Continuing despite interface configuration failure"
      else
        raise 'Interface configuration failed'
      end
    end

    # Step 7: Final assessment
    if @options[:only_nat]
      # For NAT-only mode, be more lenient
      if nat_working || internet_sharing_active || (pf_enabled && has_nat_rules)
        logger.info "NAT-only mode: NAT appears to be working"
      else
        logger.warn "NAT-only mode: NAT configuration may be incomplete, but continuing anyway"
        # In NAT-only mode, don't fail even if NAT is not detected
      end
    else
      # For full setup, be stricter
      unless nat_working || (pf_enabled && has_nat_rules) || internet_sharing_active
        error_msg = "NAT not functioning properly. Ensure IP forwarding is enabled and PF is configured."
        if @force
          logger.warn "#{error_msg} Continuing anyway due to force mode..."
        else
          raise error_msg
        end
      end
    end

    logger.info 'NAT service verification complete'
  end

  def sysctl_manager
    @sysctl_manager ||= MacRouterUtils::SysctlManager.new
  end

  def pf_manager
    # Extract subnet from static IP if needed
    lan_subnet = if @options[:lan_subnet]
                   @options[:lan_subnet]
                 elsif @options[:static_ip]
                   # Convert the static IP to a subnet using the first 3 octets + .0/24
                   ip_parts = @options[:static_ip].split('.')
                   "#{ip_parts[0]}.#{ip_parts[1]}.#{ip_parts[2]}.0/24"
                 else
                   '192.168.1.0/24'
                 end

    @pf_manager ||= MacRouterUtils::PFManager.new(
      @options[:wan_interface],
      @options[:lan_interface],
      @options[:force],
      lan_subnet
    )
  end

  def dnsmasq_manager
    # Prepare DNS options hash
    dns_options = {
      cache_size: @options[:dns_cache_size],
      min_ttl: @options[:dns_min_ttl],
      max_ttl: @options[:dns_max_ttl]
    }

    # Add DNS servers if specified, otherwise use the primary DNS
    dns_servers = @options[:dns_servers].empty? ? [@options[:dns]] : @options[:dns_servers]
    dns_options[:dns_servers] = dns_servers

    @dnsmasq_manager ||= MacRouterUtils::DNSMasqManager.new(
      @options[:lan_interface],
      @options[:static_ip],
      @options[:dhcp_range],
      @options[:domain],
      @options[:dns],
      @options[:add_static_mappings],
      @options[:remove_static_mappings],
      @options[:force],
      dns_options
    )
  end

  def interface_manager
    @interface_manager ||= MacRouterUtils::InterfaceManager.new(@options[:lan_interface], @options[:static_ip])
  end

  def execute_command_with_output(command)
    stdout, stderr, status = Open3.capture3(command)
    { stdout: stdout.strip, stderr: stderr.strip, success: status.success? }
  end
end

# Use the shared utility classes

# CLI class for NAT setup
class NatCLI < MacRouterUtils::CLIBase
  def initialize
    super({
      status: false,
      uninstall: false,
      verbose: false,
      list_interfaces: false,
      list_static_mappings: false,
      list_dhcp_leases: false,
      only_dhcp: false,
      only_nat: false,
      force: false,
      add_static_mappings: [],
      remove_static_mappings: [],
      lan_subnet: nil,
      flush_dns_cache: false,
      dns_stats: false
    })
  end

  def parse
    OptionParser.new do |opts|
      opts.banner = 'Usage: setup_nat.rb [options]'

      opts.on('--wan-interface NAME', 'WAN interface (e.g., en0)') { |v| @options[:wan_interface] = v }
      opts.on('--lan-interface NAME', 'LAN interface (e.g., en5)') { |v| @options[:lan_interface] = v }
      opts.on('--static-ip IP', 'Static IP for LAN interface') { |v| @options[:static_ip] = v }
      opts.on('--lan-subnet SUBNET', 'LAN subnet in CIDR notation (e.g., 192.168.1.0/24)') { |v| @options[:lan_subnet] = v }
      opts.on('--dhcp-range RANGE', 'DHCP range in format "start,end,lease_time"',
              'Example: 192.168.1.11,192.168.1.249,4h',
              'Lease time can be in seconds or with a suffix: m (minutes), h (hours), d (days)') do |v|
        @options[:dhcp_range] = v
      end
      opts.on('--domain DOMAIN', 'DNS domain') { |v| @options[:domain] = v }
      opts.on('--dns DNS', 'Primary upstream DNS server') { |v| @options[:dns] = v }
      opts.on('--dns-server DNS_SERVER', 'Add additional DNS server (can be used multiple times)') do |v|
        @options[:dns_servers] ||= []
        @options[:dns_servers] << v
      end
      opts.on('--dns-cache-size SIZE', Integer, 'Size of the DNS cache (default: 10000)') { |v| @options[:dns_cache_size] = v }
      opts.on('--dns-min-ttl SECONDS', Integer, 'Minimum TTL for cached DNS entries in seconds (default: 60)') { |v| @options[:dns_min_ttl] = v }
      opts.on('--dns-max-ttl SECONDS', Integer, 'Maximum TTL for cached DNS entries in seconds (default: 3600)') { |v| @options[:dns_max_ttl] = v }
      opts.on('--only-dhcp', 'Set up only the DHCP server (no NAT)') { @options[:only_dhcp] = true }
      opts.on('--only-nat', 'Set up only NAT (no DHCP server, works with Internet Sharing)') { @options[:only_nat] = true }
      opts.on('--force', 'Force restart of services even if already running') { @options[:force] = true }

      # Static mapping options
      opts.on('--add-static-mapping MAPPING', 'Add static MAC to IP mapping (can be used multiple times)',
              'Format: AA:BB:CC:DD:EE:FF,name,192.168.100.50') do |v|
        @options[:add_static_mappings] ||= []
        @options[:add_static_mappings] << v
      end

      opts.on('--remove-static-mapping MAPPING', 'Remove static mapping by full mapping, MAC, name, or IP',
              'Format: AA:BB:CC:DD:EE:FF,name,192.168.100.50 or just MAC, name, or IP') do |v|
        @options[:remove_static_mappings] ||= []
        @options[:remove_static_mappings] << v
      end

      # Utility options
      opts.on('--list-interfaces', 'List usable network interfaces') do
        @options[:list_interfaces] = true
      end

      opts.on('--list-static-mappings', 'List current static MAC to IP mappings') do
        @options[:list_static_mappings] = true
      end

      opts.on('--list-dhcp-leases', 'List current DHCP leases from dnsmasq') do
        @options[:list_dhcp_leases] = true
      end

      # DNS cache management options
      opts.on('--flush-dns-cache', 'Flush the DNS cache') do
        @options[:flush_dns_cache] = true
      end

      opts.on('--dns-stats', 'Show DNS caching statistics and query information') do
        @options[:dns_stats] = true
      end

      # Add common options (status, uninstall, verbose, help)
      add_common_options(opts)
    end.parse!

    @options
  end
end

begin
  logger = MacRouterUtils.logger('NatSetup')
  cli = NatCLI.new
  options = cli.parse

  # Handle list interfaces option separately
  if options[:list_interfaces]
    NetworkUtils.display_usable_interfaces
    exit(0)
  end

  # Create NAT setup instance
  nat_setup = NatSetup.new(options)

  # Run appropriate action based on options
  if options[:list_static_mappings]
    nat_setup.list_static_mappings
  elsif options[:list_dhcp_leases]
    nat_setup.list_dhcp_leases
  elsif options[:flush_dns_cache]
    # Create a DNSMasqManager directly without going through NatSetup
    dns_manager = MacRouterUtils::DNSMasqManager.new(
      'en8',  # Default LAN interface
      '192.168.1.1',  # Default IP
      '192.168.1.10,192.168.1.100,12h',  # Default range
      'local',  # Default domain
      '1.1.1.1',  # Default DNS
      [],  # No static mappings
      [],  # No removals
      false  # Don't force
    )
    if dns_manager.flush_dns_cache
      puts "DNS cache flushed successfully"
    else
      puts "Failed to flush DNS cache"
      exit(1)
    end
  elsif options[:dns_stats]
    # Create a DNSMasqManager directly without going through NatSetup
    dns_manager = MacRouterUtils::DNSMasqManager.new(
      'en8',  # Default LAN interface
      '192.168.1.1',  # Default IP
      '192.168.1.10,192.168.1.100,12h',  # Default range
      'local',  # Default domain
      '1.1.1.1',  # Default DNS
      [],  # No static mappings
      [],  # No removals
      false  # Don't force
    )
    dns_manager.show_dns_stats
  else
    nat_setup.run
  end
rescue OptionParser::InvalidOption, OptionParser::MissingArgument => e
  logger.error("Error: #{e.message}")
  exit(1)
rescue ArgumentError => e
  logger.error("Error: #{e.message}")
  exit(1)
rescue StandardError => e
  logger.error("Error: #{e.message}")
  logger.debug(e.backtrace.join("\n"))
  exit(1)
end
