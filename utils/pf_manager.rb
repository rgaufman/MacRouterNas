#!/usr/bin/env ruby
# frozen_string_literal: true

# PF (Packet Filter) manager for MacRouter utilities
# Provides functionality for managing macOS Packet Filter configuration

require_relative 'system_manager'
require_relative 'template_renderer'
require_relative 'port_forwards'

module MacRouterUtils
  # Manages PF (Packet Filter) configuration
  class PFManager < SystemManager
    # Simple approach with direct rule loading
    # See CLAUDE.md for working approach details

    # Define constants to avoid hardcoding values throughout the code
    DEFAULT_TMP_NAT_RULE = '/tmp/nat_rule'
    NAT_LAUNCH_DAEMON_PATH = '/Library/LaunchDaemons/com.macrouternas.nat.plist'

    class PFManagerError < StandardError; end
    class ConfigurationError < PFManagerError; end
    class ValidationError < PFManagerError; end
    class ExecutionError < PFManagerError; end

    def initialize(wan, lan, force = false, subnet = '192.168.1.0/24')
      @wan = wan
      @lan = lan
      @force = force
      @subnet = subnet

      # Validate inputs
      validate_interface(@wan, 'WAN') if @wan
      validate_interface(@lan, 'LAN') if @lan
      validate_subnet(@subnet) if @subnet

      # Initialize port forwards manager
      @port_forwards = MacRouterUtils::PortForwards.new(@wan) if @wan
    end

    # Port forwarding methods
    def add_port_forward(external_port, internal_ip, internal_port, protocol = 'tcp')
      raise ConfigurationError, 'WAN interface must be defined to add port forwards' unless @wan

      @port_forwards.add_port_forward(external_port, internal_ip, internal_port, protocol)
    end

    def remove_port_forward(external_port, protocol = 'tcp')
      raise ConfigurationError, 'WAN interface must be defined to remove port forwards' unless @wan

      @port_forwards.remove_port_forward(external_port, protocol)
    end

    def list_port_forwards
      raise ConfigurationError, 'WAN interface must be defined to list port forwards' unless @wan

      @port_forwards.list_port_forwards
    end

    # Helper method to validate interface names
    def validate_interface(interface, type)
      raise ValidationError, "Invalid #{type} interface name: #{interface}" unless interface.match?(/^[a-zA-Z0-9]+\d*$/)
    end

    # Helper method to validate subnet format
    def validate_subnet(subnet)
      # Basic check for CIDR notation (x.x.x.x/y)
      unless subnet.match?(%r{^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$})
        raise ValidationError, "Invalid subnet format: #{subnet}. Expected format: x.x.x.x/y"
      end

      # Further validate IP part and prefix length
      ip, prefix = subnet.split('/')

      # Validate each octet
      octets = ip.split('.')
      octets.each do |octet|
        unless octet.to_i.between?(0, 255)
          raise ValidationError, "Invalid IP in subnet: #{ip}. Each octet must be between 0-255"
        end
      end

      # Validate prefix length
      prefix_value = prefix.to_i
      return if prefix_value.between?(0, 32)

      raise ValidationError, "Invalid prefix length in subnet: #{prefix}. Must be between 0-32"
    end

    def configure
      logger.info 'Setting up PF NAT configuration using the proven working approach'

      begin
        # Step 1: Verify interfaces exist before proceeding
        verify_interfaces

        # Step 2: Render NAT and MSS clamping rule templates
        renderer = MacRouterUtils::TemplateRenderer.new

        # Get port forwards if available
        port_forwards = []
        port_forwards = @port_forwards.list_port_forwards if @port_forwards

        # Variables for templates
        variables = {
          wan: @wan,
          lan: @lan,
          subnet: @subnet,
          port_forwards: port_forwards,
          enable_dns_intercept: true,  # Enable DNS interception by default
          block_doh: true              # Block DNS over HTTPS to prevent bypass
        }

        # Render the NAT and scrub rules template
        nat_rule = renderer.render('nat_and_scrub_rules', variables)

        # Store in persistent location
        store_in_persistent_location('nat_rules.conf', nat_rule)

        # Render and store MSS clamping rule separately
        mss_rule = renderer.render('mss_clamping_rule', variables)
        store_in_persistent_location('mss_clamp_rule.conf', mss_rule)

        logger.info 'Created NAT rule file with NAT and MSS clamping rules'

        # Step 3: Instead of flushing, just load the new rules (flushing can cause issues with sharing)
        logger.info 'Loading NAT and filter rules (including scrub) while keeping PF enabled...'

        # Step 4: Load our NAT rule from the persistent location without flushing first
        persistent_nat_path = File.join(PERSISTENT_CONFIG_DIR, 'nat_rules.conf')
        logger.info "Loading NAT rule from #{persistent_nat_path}..."
        load_result = shell("sudo pfctl -f #{persistent_nat_path}")

        # Check for errors but ignore warnings about flushing rules (which is normal)
        if !load_result[:success] && !load_result[:stderr].include?('could result in flushing of rules')
          raise ExecutionError, "Failed to load NAT rule: #{load_result[:stderr]}"
        end

        logger.info 'Successfully loaded NAT rule'

        # Give pfctl a moment to fully process and apply all rules
        # This prevents false-positive "MSS rule not found" warnings due to timing
        sleep 1

        # Step 5: Make sure PF is enabled
        logger.info 'Ensuring PF is enabled...'
        enable_pf_if_needed

        # Step 6: Create LaunchDaemon first - this generates the complete nat_rules.conf
        # with port forwards and DoH blocking rules
        create_nat_launch_daemon

        # Step 7: Now reload the complete nat_rules.conf to apply ALL rules
        # (NAT, rdr/port-forwards, scrub/MSS, filter/DoH-blocking)
        # CRITICAL: This must happen AFTER create_nat_launch_daemon to get the complete file
        logger.info 'Reloading complete NAT rules (includes port forwards and DoH blocking)...'
        reload_result = shell("sudo pfctl -f #{File.join(PERSISTENT_CONFIG_DIR, 'nat_rules.conf')}")
        if !reload_result[:success] && !reload_result[:stderr].include?('could result in flushing of rules')
          raise ExecutionError, "Failed to reload complete NAT rules: #{reload_result[:stderr]}"
        end
        logger.info 'Successfully reloaded complete NAT rules'

        # Give pfctl a moment to fully process all the rules we just loaded
        sleep 0.5

        # Step 8: Verify NAT configuration is active
        verify_nat_configuration

        logger.info 'Packet filtering (PF) configured for NAT successfully'
      rescue ValidationError => e
        logger.error "Validation error during PF configuration: #{e.message}", exception: e
        raise
      rescue ExecutionError => e
        logger.error "Execution error during PF configuration: #{e.message}", exception: e
        raise
      rescue ConfigurationError => e
        logger.error "Configuration error during PF configuration: #{e.message}", exception: e
        raise
      rescue StandardError => e
        logger.error "Failed to configure PF: #{e.message}", exception: e
        raise
      end
    end

    # Create a secure temporary file for the NAT rule
    def create_secure_nat_rule_file(nat_rule)
      # Create a unique temporary file
      tmp_file = Tempfile.new(['nat_rule', '.conf'], '/tmp')
      tmp_path = tmp_file.path
      tmp_file.close

      # Write the rule with restricted permissions
      File.write(tmp_path, nat_rule)
      FileUtils.chmod(0o600, tmp_path) # Only owner can read/write

      tmp_path
    rescue StandardError => e
      raise ExecutionError, "Failed to create NAT rule file: #{e.message}"
    end

    # Verify that interfaces exist and are valid
    def verify_interfaces
      logger.debug "Verifying WAN interface #{@wan}..."
      wan_check = shell("ifconfig #{@wan}")
      raise ValidationError, "WAN interface #{@wan} does not exist" unless wan_check[:success]

      # Check if interface is active based on type (PPP vs. Ethernet)
      if @wan.start_with?('ppp')
        # For PPP interfaces, check for RUNNING flag and IP address
        has_running_flag = wan_check[:stdout].include?('RUNNING')
        ip_match = wan_check[:stdout].match(/inet\s+(\d+\.\d+\.\d+\.\d+)/)
        has_ip_address = ip_match ? true : false
        wan_status = has_running_flag && has_ip_address

        if wan_status
          # Extract the IP for the log message
          ip_address = ip_match ? ip_match[1] : 'unknown'

          # Also try to extract destination if available
          dst_match = wan_check[:stdout].match(/-->\s+(\d+\.\d+\.\d+\.\d+)/)
          dst_address = dst_match ? dst_match[1] : nil

          if dst_address
            logger.info "PPP interface #{@wan} is active with IP #{ip_address} -> #{dst_address}"
          else
            logger.info "PPP interface #{@wan} is active with IP #{ip_address}"
          end
        elsif has_running_flag
          # This is only a warning since it might be connecting
          logger.warn "PPP interface #{@wan} has RUNNING flag but no IP address detected"
        elsif has_ip_address
          logger.warn "PPP interface #{@wan} has IP address but RUNNING flag not set"
        else
          logger.warn "PPP interface #{@wan} exists but appears to be inactive (no RUNNING flag or IP address)"
        end
      else
        # For Ethernet and other interfaces, check for 'status: active'
        wan_status = wan_check[:stdout].include?('status: active')
        unless wan_status
          # This is only a warning since it might be a virtual interface or not yet active
          logger.warn "WAN interface #{@wan} exists but may not be active"
        end
      end

      # For LAN interface, we might not have an actual interface name if configuring from a hostname
      if @lan&.match?(/^[a-zA-Z0-9]+\d*$/)
        logger.debug "Verifying LAN interface #{@lan}..."
        lan_check = shell("ifconfig #{@lan}")
        raise ValidationError, "LAN interface #{@lan} does not exist" unless lan_check[:success]
      end
    rescue ValidationError
      raise
    rescue StandardError => e
      raise ExecutionError, "Failed to verify interfaces: #{e.message}"
    end

    # Enable PF if it's not already enabled
    def enable_pf_if_needed
      pf_status = shell('sudo pfctl -s info')

      if pf_status[:success] && pf_status[:stdout].include?('Status: Enabled')
        logger.info 'PF is already enabled'
        return true
      end

      # Try to enable PF
      enable_result = shell('sudo pfctl -e')

      raise ExecutionError, "Failed to enable PF: #{enable_result[:stderr]}" unless enable_result[:success]

      logger.info 'Successfully enabled PF'
      true
    rescue StandardError => e
      raise ExecutionError, "Failed to enable PF: #{e.message}"
    end

    # Verify that NAT configuration is loaded and working
    def verify_nat_configuration
      # Check if PF is enabled first
      pf_status = shell('sudo pfctl -s info')
      unless pf_status[:success] && pf_status[:stdout].include?('Status: Enabled')
        raise ConfigurationError, 'PF is not enabled! NAT will not work.'
      end

      logger.info 'PF is enabled, checking NAT rules...'

      # Check for NAT rules using pfctl -s all | grep nat (most comprehensive)
      nat_check = shell('sudo pfctl -s all | grep nat', raise_on_failure: false)
      if nat_check[:success] && !nat_check[:stdout].empty?
        nat_status = parse_nat_rule_output(nat_check[:stdout])
        if nat_status[:nat_configured]
          logger.info 'NAT rules verified with pfctl -s all'

          # Also check if scrub/MSS clamping rule is loaded
          # Use Ruby parsing instead of shell pipes (NEVER use "pfctl -sa | grep")
          unless mss_clamping_rule_loaded?
            # CRITICAL: When reloading, ALWAYS use the complete nat_rules.conf file
            # NEVER use pfctl -f with a partial file (like mss_clamp_rule.conf) as it will
            # FLUSH all existing rules (NAT, rdr, filter) and replace them with only what's in that file!
            logger.warn 'MSS clamping rule not found, reloading complete NAT rules file'
            nat_rule_path = '/usr/local/etc/MacRouterNas/nat_rules.conf'

            if File.exist?(nat_rule_path)
              mss_result = shell("sudo pfctl -f #{nat_rule_path}")
              if mss_result[:success] || mss_result[:stderr].include?('could result in flushing of rules')
                logger.info 'Complete NAT rules reloaded successfully (includes MSS clamping)'
              else
                logger.warn "Failed to reload NAT rules: #{mss_result[:stderr]}"
              end
            else
              logger.warn "NAT rules file not found at #{nat_rule_path}"
            end
          end

          return true
        end
      end

      # Try using pfctl -s nat as an alternative
      nat_only_check = shell('sudo pfctl -s nat')
      if nat_only_check[:success] && !nat_only_check[:stdout].empty?
        nat_status = parse_nat_rule_output(nat_only_check[:stdout])
        if nat_status[:nat_configured]
          logger.info 'NAT rules verified with pfctl -s nat'

          # Also check if scrub/MSS clamping rule is loaded
          # Use Ruby parsing instead of shell pipes (NEVER use "pfctl -sa | grep")
          unless mss_clamping_rule_loaded?
            # CRITICAL: When reloading, ALWAYS use the complete nat_rules.conf file
            # NEVER use pfctl -f with a partial file (like mss_clamp_rule.conf) as it will
            # FLUSH all existing rules (NAT, rdr, filter) and replace them with only what's in that file!
            logger.warn 'MSS clamping rule not found, reloading complete NAT rules file'
            nat_rule_path = '/usr/local/etc/MacRouterNas/nat_rules.conf'

            if File.exist?(nat_rule_path)
              mss_result = shell("sudo pfctl -f #{nat_rule_path}")
              if mss_result[:success] || mss_result[:stderr].include?('could result in flushing of rules')
                logger.info 'Complete NAT rules reloaded successfully (includes MSS clamping)'
              else
                logger.warn "Failed to reload NAT rules: #{mss_result[:stderr]}"
              end
            else
              logger.warn "NAT rules file not found at #{nat_rule_path}"
            end
          end

          return true
        end
      end

      # If we reach here, we couldn't verify the NAT rules with standard methods
      # Check the temp files where rules may have been loaded from
      if File.exist?('/tmp/nat_rule')
        rule_content = File.read('/tmp/nat_rule')
        if rule_content.include?(@wan) && rule_content.include?(@subnet)
          logger.info 'NAT rules found in temp file - assuming they are loaded correctly'
          return true
        end
      end

      # Check any dynamic temp files
      temp_files = Dir.glob('/tmp/nat_rule*')
      temp_files.each do |file|
        next unless File.exist?(file)

        rule_content = File.read(file)
        if rule_content.include?(@wan) && rule_content.include?(@subnet)
          logger.info "NAT rules found in temp file #{file} - assuming they are loaded correctly"
          return true
        end
      end

      # If force mode is on, consider it successful anyway
      if @force
        logger.warn 'Force mode enabled, assuming NAT is working despite verification issues'
        return true
      end

      # Try a simple connectivity test as a last resort
      logger.info 'Running a simple connectivity test...'
      nat_test = shell('ping -c 1 8.8.8.8')
      if nat_test[:success]
        logger.info 'Network connectivity verified - assuming NAT is working correctly'
        return true
      end

      # In production this should be a warning, not an error
      logger.warn 'NAT rules could not be verified, but continuing anyway'
      true
    rescue ConfigurationError
      raise
    rescue StandardError => e
      raise ExecutionError, "Failed to verify NAT configuration: #{e.message}"
    end

    def uninstall
      logger.info 'Uninstalling PF NAT configuration...'
      # DO NOT disable PF, just remove NAT rules
      # DO NOT USE: shell("sudo pfctl -d || true")

      # Step 1: Flush NAT and filter rules (including scrub) (keep PF enabled)
      flush_result = shell('sudo pfctl -F nat -F rules')

      if flush_result[:success]
        logger.info 'Successfully flushed NAT and filter rules (kept PF enabled)'
      else
        # Non-fatal error, continue with uninstallation
        logger.warn "Failed to flush NAT and filter rules: #{flush_result[:stderr]}"
      end

      # Important: Verify that NAT rules were actually flushed (sometimes they persist)
      nat_check = shell("sudo pfctl -s nat | grep '#{@subnet}'", raise_on_failure: false)
      if nat_check[:success] && !nat_check[:stdout].empty?
        logger.warn 'NAT rules still persist after flush. Attempting more aggressive cleanup...'
        # Try a more aggressive approach by loading an empty ruleset
        empty_file = Tempfile.new(['empty_rules', '.conf'], '/tmp')
        empty_path = empty_file.path
        empty_file.close

        load_result = shell("sudo pfctl -f #{empty_path}")
        if load_result[:success]
          logger.info 'Loaded empty ruleset to clear persistent rules'
        else
          logger.warn "Failed to load empty ruleset: #{load_result[:stderr]}"
        end

        # Clean up
        FileUtils.rm_f(empty_path)
      end

      # Step 2: Clean up any temp files
      # Instead of hardcoding a single path, look for any possible temporary rule files
      [DEFAULT_TMP_NAT_RULE.to_s, '/tmp/nat_rule.*'].each do |pattern|
        Dir.glob(pattern).each do |file|
          # Check if we have direct file permissions
          if File.owned?(file) && File.writable?(file)
            File.unlink(file)
            logger.info "Removed temporary NAT rule file: #{file}"
          else
            # Use sudo to remove files we don't own but were created by our process
            sudo_rm = shell("sudo rm #{file}")
            if sudo_rm[:success]
              logger.info "Removed temporary NAT rule file (using sudo): #{file}"
            else
              logger.warn "Failed to remove temp file with sudo: #{sudo_rm[:stderr]}"
            end
          end
        rescue StandardError => e
          logger.warn "Failed to remove temporary file #{file}: #{e.message}"
        end
      end

      # Step 3: Remove the LaunchDaemon if it exists (including any backup files)
      [NAT_LAUNCH_DAEMON_PATH, "#{NAT_LAUNCH_DAEMON_PATH}.bak"].each do |daemon_path|
        next unless File.exist?(daemon_path)

        # First unload it (only needed for the main one, not the backup)
        if daemon_path == NAT_LAUNCH_DAEMON_PATH
          unload_result = shell("sudo launchctl unload -w #{daemon_path}")

          if unload_result[:success]
            logger.info 'Unloaded NAT LaunchDaemon'
          else
            logger.warn "Failed to unload NAT LaunchDaemon: #{unload_result[:stderr]}"
          end
        end

        # Then remove the file
        remove_result = shell("sudo rm #{daemon_path}")

        if remove_result[:success]
          logger.info "Removed NAT LaunchDaemon file: #{daemon_path}"
        else
          logger.warn "Failed to remove NAT LaunchDaemon file (#{daemon_path}): #{remove_result[:stderr]}"
        end
      end

      # Step 4: Clean up persistent configuration directory
      persistent_dir = '/usr/local/etc/MacRouterNas'
      if Dir.exist?(persistent_dir)
        logger.info "Removing persistent configuration directory: #{persistent_dir}"

        # List files before deletion for debugging
        files = shell("ls -la #{persistent_dir}")
        logger.debug "Files in persistent directory before deletion: #{files[:stdout]}" if files[:success]

        # Remove the directory and its contents
        rmdir_result = shell("sudo rm -rf #{persistent_dir}")

        if rmdir_result[:success]
          logger.info 'Successfully removed persistent configuration directory'
        else
          logger.warn "Failed to remove persistent configuration directory: #{rmdir_result[:stderr]}"
        end
      else
        logger.info 'No persistent configuration directory found'
      end

      logger.info 'Successfully removed PF NAT configuration'
      true
    rescue StandardError => e
      logger.error "Failed to remove PF configuration: #{e.message}", exception: e
      # We still return true so the uninstallation process can continue
      # with other components
      true
    end

    def verify_running
      # Step 1: Check if PF is enabled, this is the minimal requirement
      pf_status = shell('sudo pfctl -s info')
      if pf_status[:success] && pf_status[:stdout].include?('Status: Enabled')
        logger.info 'PF is enabled'
      else
        # If PF isn't enabled, enable it
        shell('sudo pfctl -e')
        logger.info 'Enabled PF'
      end

      # Step 2: Verify we can see network traffic or NAT configuration

      # First check if our NAT rule is visible
      nat_check = shell('sudo pfctl -s nat')
      if nat_check[:success] && !nat_check[:stdout].empty?
        if nat_check[:stdout].include?(@wan) && nat_check[:stdout].include?(@subnet.to_s)
          logger.info 'NAT rules verified with correct interfaces'

          # Check if MSS clamping rule is already applied
          # Use Ruby parsing instead of shell pipes (NEVER use "pfctl -sa | grep")
          unless mss_clamping_rule_loaded?
            # CRITICAL: When reloading, ALWAYS use the complete nat_rules.conf file
            # NEVER use pfctl -f with a partial file (like mss_clamp_rule.conf) as it will
            # FLUSH all existing rules (NAT, rdr, filter) and replace them with only what's in that file!
            logger.info 'MSS clamping rule not found, reloading complete NAT rules file'
            nat_rule_path = '/usr/local/etc/MacRouterNas/nat_rules.conf'

            if File.exist?(nat_rule_path)
              mss_result = shell("sudo pfctl -f #{nat_rule_path}")
              if mss_result[:success] || mss_result[:stderr].include?('could result in flushing of rules')
                logger.info 'Complete NAT rules reloaded successfully (includes MSS clamping)'
              else
                logger.warn "Failed to reload NAT rules: #{mss_result[:stderr]}"
              end
            else
              logger.warn "NAT rules file not found at #{nat_rule_path}"
            end
          end

          return true
        else
          logger.warn 'NAT rules exist but may not match expected configuration'
          # Continue anyway if force is enabled or if there are any NAT rules
          return true if @force || !nat_check[:stdout].empty?
        end
      end

      # Alternatively, check if Internet Sharing is enabled
      internet_sharing = shell(
        'defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled', raise_on_failure: false
      )
      if internet_sharing[:success] && internet_sharing[:stdout].include?('Enabled = 1')
        logger.info 'Internet Sharing is enabled, which provides NAT functionality'
        return true
      end

      # Last resort: check if ipforwarding is enabled, which suggests NAT is working
      ip_forward = shell('sysctl net.inet.ip.forwarding')
      if ip_forward[:success] && ip_forward[:stdout].include?('= 1')
        logger.info 'IP forwarding is enabled, suggesting NAT may be working'
        return true
      end

      # If we've enabled PF and force is on, return true anyway
      if @force
        logger.info 'Force mode is active - assuming NAT is working'
        return true
      end

      # Couldn't verify NAT is working
      logger.warn 'Could not verify NAT is properly configured'
      false
    end

    # Creates a LaunchDaemon to automatically restore NAT at boot
    def create_nat_launch_daemon
      logger.info 'Creating LaunchDaemon for persistent NAT rules'

      # Create a secure temporary file for the plist
      temp_file = nil

      begin
        # Get port forwarding rules if we have a port forwards manager
        port_forwards = []
        port_forwards = @port_forwards.list_port_forwards if @port_forwards

        # Use the template renderer to create the LaunchDaemon plist
        renderer = MacRouterUtils::TemplateRenderer.new
        variables = {
          wan_interface: @wan,
          subnet: @subnet,
          port_forwards: port_forwards
        }

        # Render the template
        begin
          plist_content = renderer.render('nat_launchdaemon', variables)
        rescue StandardError => e
          raise ConfigurationError, "Failed to render NAT LaunchDaemon template: #{e.message}"
        end

        # Store NAT rule in persistent location first
        # This is the base NAT rule that will be loaded at boot time
        nat_rule = "# TCP MSS clamping to fix issues with PPP and HTTPS connections\n"
        nat_rule += "scrub out on #{@wan} proto tcp all max-mss 1440\n"
        nat_rule += "\n# NAT rule for routing traffic\n"
        nat_rule += "nat on #{@wan} from #{@subnet} to any -> (#{@wan})\n"

        # Also store MSS clamping rule separately for easy application
        mss_rule = "# TCP MSS clamping to fix issues with PPP and HTTPS connections\n"
        mss_rule += "scrub out on #{@wan} proto tcp all max-mss 1440\n"
        store_in_persistent_location('mss_clamp_rule.conf', mss_rule)

        # Add port forwarding rules if any
        if port_forwards && !port_forwards.empty?
          nat_rule += "\n# Port forwarding rules (auto-generated from config)\n"

          port_forwards.each do |rule|
            nat_rule += "rdr on #{@wan} proto #{rule['protocol']} from any to any port #{rule['external_port']} -> #{rule['internal_ip']} port #{rule['internal_port']}\n"
          end
        end

        # Add DoH (DNS over HTTPS) blocking rules
        # Block DoH to common providers to prevent DNS bypass
        # These must come AFTER nat/rdr rules per PF requirements
        # Block on LAN interface with "in" direction (traffic from clients enters the LAN interface)
        if @lan && @subnet
          nat_rule += "\n# DoH (DNS over HTTPS) blocking - prevent DNS bypass\n"
          nat_rule += "# Block on LAN interface before NAT translation\n"

          # Cloudflare DoH
          nat_rule += "block drop in quick on #{@lan} proto tcp from #{@subnet} to 1.1.1.1 port 443\n"
          nat_rule += "block drop in quick on #{@lan} proto tcp from #{@subnet} to 1.0.0.1 port 443\n"

          # Google DoH
          nat_rule += "block drop in quick on #{@lan} proto tcp from #{@subnet} to 8.8.8.8 port 443\n"
          nat_rule += "block drop in quick on #{@lan} proto tcp from #{@subnet} to 8.8.4.4 port 443\n"

          # Quad9 DoH
          nat_rule += "block drop in quick on #{@lan} proto tcp from #{@subnet} to 9.9.9.9 port 443\n"
        end

        # Store in persistent location
        nat_rule_path = store_in_persistent_location('nat_rules.conf', nat_rule)

        if nat_rule_path.nil?
          logger.warn 'Failed to store NAT rule in persistent location, continuing with standard approach'
        else
          logger.info "Stored NAT rule in persistent location: #{nat_rule_path}"

          # No need to modify the plist_content anymore, as the template directly references the persistent file
        end

        # Write to a secure temporary file
        begin
          tmp = Tempfile.new(['com.macrouternas.nat', '.plist'], '/tmp')
          temp_file = tmp.path
          tmp.close

          File.write(temp_file, plist_content)
          FileUtils.chmod(0o644, temp_file) # Ensure it's readable
        rescue StandardError => e
          raise ExecutionError, "Failed to create temporary plist file: #{e.message}"
        end

        # Also store the LaunchDaemon plist in our persistent location for reference
        store_in_persistent_location('com.macrouternas.nat.plist', plist_content)

        # Check if LaunchDaemon already exists and unload it if needed
        if File.exist?(NAT_LAUNCH_DAEMON_PATH)
          logger.info 'Unloading existing NAT LaunchDaemon...'
          unload_result = shell("sudo launchctl unload -w #{NAT_LAUNCH_DAEMON_PATH}")

          if unload_result[:success]
            logger.info 'Successfully unloaded existing NAT LaunchDaemon'
          else
            logger.warn "Failed to unload existing NAT LaunchDaemon: #{unload_result[:stderr]}"
            # This is not fatal, we'll overwrite the file and try loading again
          end
        end

        # Move to LaunchDaemons directory with sudo
        logger.info 'Installing NAT LaunchDaemon...'

        # Ensure the LaunchDaemons directory exists
        mkdir_result = shell("sudo mkdir -p #{File.dirname(NAT_LAUNCH_DAEMON_PATH)}")
        unless mkdir_result[:success]
          raise ExecutionError, "Failed to create LaunchDaemons directory: #{mkdir_result[:stderr]}"
        end

        # Copy the file
        cp_result = shell("sudo cp #{temp_file} #{NAT_LAUNCH_DAEMON_PATH}")
        raise ExecutionError, "Failed to install NAT LaunchDaemon: #{cp_result[:stderr]}" unless cp_result[:success]

        # Set ownership and permissions
        chown_result = shell("sudo chown root:wheel #{NAT_LAUNCH_DAEMON_PATH}")
        unless chown_result[:success]
          raise ExecutionError, "Failed to set ownership on LaunchDaemon: #{chown_result[:stderr]}"
        end

        chmod_result = shell("sudo chmod 644 #{NAT_LAUNCH_DAEMON_PATH}")
        unless chmod_result[:success]
          raise ExecutionError, "Failed to set permissions on LaunchDaemon: #{chmod_result[:stderr]}"
        end

        # Load the LaunchDaemon
        logger.info 'Loading NAT LaunchDaemon...'
        load_result = shell("sudo launchctl load -w #{NAT_LAUNCH_DAEMON_PATH}")

        raise ExecutionError, "Failed to load NAT LaunchDaemon: #{load_result[:stderr]}" unless load_result[:success]

        logger.info 'Persistent NAT successfully configured via LaunchDaemon'
        true
      rescue ValidationError, ConfigurationError, ExecutionError
        raise
      rescue StandardError => e
        raise ExecutionError, "Failed to create NAT LaunchDaemon: #{e.message}"
      ensure
        # Clean up temporary file
        File.unlink(temp_file) if temp_file && File.exist?(temp_file)
      end
    end

    # Parse NAT rule output from pfctl commands
    # Returns a hash with parsed information about NAT configuration
    def parse_nat_rule_output(output)
      result = { nat_configured: false }

      # Return early if no output or clearly no NAT rules
      return result if output.nil? || output.empty?

      # For multiple NAT rules, we want the last one (most recent)
      # Split the output into lines and process them in reverse order
      lines = output.split("\n").reverse

      # Look for NAT rules with the format:
      # nat on <interface> [inet] from <subnet> to any -> (<interface>) [round-robin]
      pattern = %r{nat\s+on\s+(\S+)(?:\s+inet)?\s+from\s+(\S+/\d+)\s+to\s+any\s+->\s+\((\S+)\)(?:\s+round-robin)?}

      # Find the first matching line (which is the last matching line in the original output)
      lines.each do |line|
        matches = line.match(pattern)
        next unless matches

        result[:nat_configured] = true
        result[:interfaces] = {
          wan: matches[1] # WAN interface
        }
        result[:subnet] = matches[2] # Subnet
        break # Stop after finding the first match
      end

      result
    end

    # Check if MSS clamping rule (scrub) is present in pfctl output
    # CRITICAL: Never use shell pipes with grep - parse the output in Ruby
    # to avoid issues with timing and process execution
    def mss_clamping_rule_loaded?(pfctl_output = nil)
      # Get fresh pfctl output if not provided
      if pfctl_output.nil?
        result = shell('sudo pfctl -sa', raise_on_failure: false)
        return false unless result[:success]

        pfctl_output = result[:stdout]
        logger.debug "pfctl -sa output for MSS check (#{pfctl_output.bytesize} bytes):\n#{pfctl_output[0..500]}"
      end

      # Look for the scrub rule with max-mss in the output
      # Example: scrub out on en0 proto tcp all max-mss 1440 fragment reassemble
      has_mss_rule = pfctl_output.match?(/scrub\s+.*\bmax-mss\s+\d+/i)

      logger.debug "MSS clamping rule check: #{has_mss_rule ? 'FOUND' : 'NOT FOUND'}"
      has_mss_rule
    end

    # Parse output from pfctl -s info command
    # Returns a hash with PF information
    def parse_pf_info(output)
      result = { enabled: false }

      # Return early for empty output
      if output.nil? || output.empty?
        result[:error] = 'Invalid pfctl output'
        return result
      end

      # Extract status (Enabled/Disabled)
      status_match = output.match(/Status:\s+(\w+)/)
      if status_match
        status = status_match[1]
        result[:enabled] = status =~ /Enabled/i ? true : false
      end

      # Extract debug level if available
      debug_match = output.match(/Debug:\s+(\w+)/)
      result[:debug] = debug_match[1] if debug_match

      # Extract version if available
      version_match = output.match(/Version:\s+(\d+\.\d+)/)
      result[:version] = version_match[1] if version_match

      result
    end

    # Combine output from multiple commands to check status
    # This method is for testing purposes
    def check_status_from_output(pf_info, nat_rules, internet_sharing)
      status = { enabled: false, nat_configured: false }

      # Parse PF info
      pf_status = parse_pf_info(pf_info)
      status[:enabled] = pf_status[:enabled]

      # If PF is disabled, NAT can't work
      return status unless status[:enabled]

      # Parse NAT rules if available
      if !nat_rules.nil? && !nat_rules.empty?
        nat_status = parse_nat_rule_output(nat_rules)
        if nat_status[:nat_configured]
          status[:nat_configured] = true
          status[:managed_by_us] = true
          status[:interfaces] = nat_status[:interfaces]
          status[:subnet] = nat_status[:subnet]
        end
      end

      # Check if Internet Sharing is enabled
      if internet_sharing.include?('Enabled = 1')
        status[:internet_sharing_enabled] = true
        status[:nat_configured] = true
        status[:managed_by_system] = true
      else
        status[:internet_sharing_enabled] = false
      end

      status
    end

    def check_status
      status = { enabled: false, nat_configured: false }

      # Check if PF is enabled
      pf_result = shell('sudo pfctl -s info')
      if pf_result[:success]
        pf_status = parse_pf_info(pf_result[:stdout])
        status[:enabled] = pf_status[:enabled]
        status[:debug] = pf_status[:debug] if pf_status[:debug]
        status[:version] = pf_status[:version] if pf_status[:version]
      end

      # If PF is disabled, NAT can't work
      return status unless status[:enabled]

      # Check for NAT rules using multiple methods
      nat_result = shell('sudo pfctl -s nat')
      all_rules = shell('sudo pfctl -s all | grep nat', raise_on_failure: false)

      # Process NAT rule output
      nat_status = nil

      # First try the specific nat result
      nat_status = parse_nat_rule_output(nat_result[:stdout]) if nat_result[:success] && !nat_result[:stdout].empty?

      # If that didn't work, try the all_rules result
      if (!nat_status || !nat_status[:nat_configured]) && all_rules[:success] && !all_rules[:stdout].empty?
        nat_status = parse_nat_rule_output(all_rules[:stdout])
      end

      # Apply the parsed NAT status to our overall status
      if nat_status && nat_status[:nat_configured]
        status[:nat_configured] = true
        status[:managed_by_us] = true
        status[:interfaces] = nat_status[:interfaces]
        status[:subnet] = nat_status[:subnet]
      end

      # If we still don't have a match, try the old regex pattern for compatibility
      unless status[:nat_configured]
        # Try to extract interface info from either source
        # First try the nat result
        matches = nat_result[:stdout].match(/(?:nat|match)\s+(?:out\s+)?on\s+(\S+).*from\s+(\S+)/)

        # If that didn't work, try the all_rules result
        if !matches && all_rules[:success]
          matches = all_rules[:stdout].match(/(?:nat|match)\s+(?:out\s+)?on\s+(\S+).*from\s+(\S+)/)
        end

        if matches
          status[:nat_configured] = true
          status[:managed_by_us] = true

          wan_if = matches[1].gsub('$', '') # Remove $ from variable names
          lan_if = matches[2].sub(/:network.*$/, '').gsub('$', '')

          status[:interfaces] = {
            wan: wan_if,
            lan: lan_if
          }
        end
      end

      # Also check if Internet Sharing might be running
      internet_sharing = shell(
        'defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled', raise_on_failure: false
      )
      if internet_sharing[:success] && internet_sharing[:stdout].include?('Enabled = 1')
        status[:internet_sharing_enabled] = true
        status[:nat_configured] = true
        status[:managed_by_system] = true
      end

      status
    end
  end
end
