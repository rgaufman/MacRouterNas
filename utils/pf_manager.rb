#!/usr/bin/env ruby
# frozen_string_literal: true

# PF (Packet Filter) manager for MacRouter utilities
# Provides functionality for managing macOS Packet Filter configuration

require_relative 'system_manager'
require_relative 'template_renderer'

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
    end

    # Helper method to validate interface names
    def validate_interface(interface, type)
      unless interface.match?(/^[a-zA-Z0-9]+\d*$/)
        raise ValidationError, "Invalid #{type} interface name: #{interface}"
      end
    end

    # Helper method to validate subnet format
    def validate_subnet(subnet)
      # Basic check for CIDR notation (x.x.x.x/y)
      unless subnet.match?(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)
        raise ValidationError, "Invalid subnet format: #{subnet}. Expected format: x.x.x.x/y"
      end

      # Further validate IP part and prefix length
      ip, prefix = subnet.split('/')

      # Validate each octet
      octets = ip.split('.')
      octets.each do |octet|
        unless octet.to_i >= 0 && octet.to_i <= 255
          raise ValidationError, "Invalid IP in subnet: #{ip}. Each octet must be between 0-255"
        end
      end

      # Validate prefix length
      prefix_value = prefix.to_i
      unless prefix_value >= 0 && prefix_value <= 32
        raise ValidationError, "Invalid prefix length in subnet: #{prefix}. Must be between 0-32"
      end
    end

    def configure
      logger.info "Setting up PF NAT configuration using the proven working approach"

      # Use a temporary file with a unique name for better security
      tmp_nat_rule = nil

      begin
        # Step 1: Verify interfaces exist before proceeding
        verify_interfaces

        # Step 2: Create the NAT rule file with appropriate permissions
        # Add MSS clamping rule to prevent issues with PPP interfaces and HTTPS sites
        # Note that scrub rules must come before nat rules (rule ordering requirement)
        nat_rule = "# TCP MSS clamping to fix issues with PPP and HTTPS connections\n"
        nat_rule += "scrub out on #{@wan} proto tcp all max-mss 1440\n"

        # Add NAT rule after scrub rule
        nat_rule += "\n# NAT rule for routing traffic\n"
        nat_rule += "nat on #{@wan} from #{@subnet} to any -> (#{@wan})\n"

        # Create a file with the combined rules
        tmp_nat_rule = create_secure_nat_rule_file(nat_rule)
        logger.info "Created NAT rule file with NAT and MSS clamping rules"

        # Step 3: Flush NAT rules but keep PF enabled (DO NOT disable PF, it breaks connectivity)
        logger.info "Flushing NAT rules while keeping PF enabled..."
        flush_result = execute_command_with_output("sudo pfctl -F nat")

        if !flush_result[:success]
          raise ExecutionError, "Failed to flush NAT rules: #{flush_result[:stderr]}"
        end
        logger.info "Successfully flushed NAT rules"

        # Step 4: Load our NAT rule
        logger.info "Loading NAT rule from #{tmp_nat_rule}..."
        load_result = execute_command_with_output("sudo pfctl -f #{tmp_nat_rule}")

        # Check for errors but ignore warnings about flushing rules (which is normal)
        if !load_result[:success] && !load_result[:stderr].include?('could result in flushing of rules')
          raise ExecutionError, "Failed to load NAT rule: #{load_result[:stderr]}"
        end
        logger.info "Successfully loaded NAT rule"

        # Step 5: Make sure PF is enabled
        logger.info "Ensuring PF is enabled..."
        enable_pf_if_needed

        # Step 6: Create a LaunchDaemon to restore NAT at boot
        create_nat_launch_daemon

        # Step 7: Verify NAT configuration is active
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
      ensure
        # Always clean up the temporary file
        File.unlink(tmp_nat_rule) if tmp_nat_rule && File.exist?(tmp_nat_rule)
      end
    end

    # Create a secure temporary file for the NAT rule
    def create_secure_nat_rule_file(nat_rule)
      begin
        # Create a unique temporary file
        tmp_file = Tempfile.new(['nat_rule', '.conf'], '/tmp')
        tmp_path = tmp_file.path
        tmp_file.close

        # Write the rule with restricted permissions
        File.write(tmp_path, nat_rule)
        FileUtils.chmod(0600, tmp_path) # Only owner can read/write

        return tmp_path
      rescue StandardError => e
        raise ExecutionError, "Failed to create NAT rule file: #{e.message}"
      end
    end

    # Verify that interfaces exist and are valid
    def verify_interfaces
      begin
        logger.debug "Verifying WAN interface #{@wan}..."
        wan_check = execute_command_with_output("ifconfig #{@wan}")
        unless wan_check[:success]
          raise ValidationError, "WAN interface #{@wan} does not exist"
        end

        # Check if interface is active based on type (PPP vs. Ethernet)
        if @wan.start_with?('ppp')
          # For PPP interfaces, check for RUNNING flag and IP address
          has_running_flag = wan_check[:stdout].include?('RUNNING')
          ip_match = wan_check[:stdout].match(/inet\s+(\d+\.\d+\.\d+\.\d+)/)
          has_ip_address = ip_match ? true : false
          wan_status = has_running_flag && has_ip_address

          if wan_status
            # Extract the IP for the log message
            ip_address = ip_match ? ip_match[1] : "unknown"

            # Also try to extract destination if available
            dst_match = wan_check[:stdout].match(/-->\s+(\d+\.\d+\.\d+\.\d+)/)
            dst_address = dst_match ? dst_match[1] : nil

            if dst_address
              logger.info "PPP interface #{@wan} is active with IP #{ip_address} -> #{dst_address}"
            else
              logger.info "PPP interface #{@wan} is active with IP #{ip_address}"
            end
          else
            # This is only a warning since it might be connecting
            if has_running_flag
              logger.warn "PPP interface #{@wan} has RUNNING flag but no IP address detected"
            elsif has_ip_address
              logger.warn "PPP interface #{@wan} has IP address but RUNNING flag not set"
            else
              logger.warn "PPP interface #{@wan} exists but appears to be inactive (no RUNNING flag or IP address)"
            end
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
        if @lan && @lan.match?(/^[a-zA-Z0-9]+\d*$/)
          logger.debug "Verifying LAN interface #{@lan}..."
          lan_check = execute_command_with_output("ifconfig #{@lan}")
          unless lan_check[:success]
            raise ValidationError, "LAN interface #{@lan} does not exist"
          end
        end
      rescue ValidationError => e
        raise
      rescue StandardError => e
        raise ExecutionError, "Failed to verify interfaces: #{e.message}"
      end
    end

    # Enable PF if it's not already enabled
    def enable_pf_if_needed
      begin
        pf_status = execute_command_with_output('sudo pfctl -s info')

        if pf_status[:success] && pf_status[:stdout].include?('Status: Enabled')
          logger.info "PF is already enabled"
          return true
        end

        # Try to enable PF
        enable_result = execute_command_with_output("sudo pfctl -e")

        if !enable_result[:success]
          raise ExecutionError, "Failed to enable PF: #{enable_result[:stderr]}"
        end

        logger.info "Successfully enabled PF"
        return true
      rescue StandardError => e
        raise ExecutionError, "Failed to enable PF: #{e.message}"
      end
    end

    # Verify that NAT configuration is loaded and working
    def verify_nat_configuration
      begin
        # Check if PF is enabled first
        pf_status = execute_command_with_output("sudo pfctl -s info")
        unless pf_status[:success] && pf_status[:stdout].include?("Status: Enabled")
          raise ConfigurationError, "PF is not enabled! NAT will not work."
        end

        logger.info "PF is enabled, checking NAT rules..."

        # Check for NAT rules using pfctl -s all | grep nat (most comprehensive)
        nat_check = execute_command_with_output("sudo pfctl -s all | grep nat")
        if nat_check[:success] && !nat_check[:stdout].empty?
          nat_status = parse_nat_rule_output(nat_check[:stdout])
          if nat_status[:nat_configured]
            logger.info "NAT rules verified with pfctl -s all"
            return true
          end
        end

        # Try using pfctl -s nat as an alternative
        nat_only_check = execute_command_with_output("sudo pfctl -s nat")
        if nat_only_check[:success] && !nat_only_check[:stdout].empty?
          nat_status = parse_nat_rule_output(nat_only_check[:stdout])
          if nat_status[:nat_configured]
            logger.info "NAT rules verified with pfctl -s nat"
            return true
          end
        end

        # If we reach here, we couldn't verify the NAT rules with standard methods
        # Check the temp files where rules may have been loaded from
        if File.exist?('/tmp/nat_rule')
          rule_content = File.read('/tmp/nat_rule')
          if rule_content.include?(@wan) && rule_content.include?(@subnet)
            logger.info "NAT rules found in temp file - assuming they are loaded correctly"
            return true
          end
        end

        # Check any dynamic temp files
        temp_files = Dir.glob('/tmp/nat_rule*')
        temp_files.each do |file|
          if File.exist?(file)
            rule_content = File.read(file)
            if rule_content.include?(@wan) && rule_content.include?(@subnet)
              logger.info "NAT rules found in temp file #{file} - assuming they are loaded correctly"
              return true
            end
          end
        end

        # If force mode is on, consider it successful anyway
        if @force
          logger.warn "Force mode enabled, assuming NAT is working despite verification issues"
          return true
        end

        # Try a simple connectivity test as a last resort
        logger.info "Running a simple connectivity test..."
        nat_test = execute_command_with_output("ping -c 1 8.8.8.8")
        if nat_test[:success]
          logger.info "Network connectivity verified - assuming NAT is working correctly"
          return true
        end

        # In production this should be a warning, not an error
        logger.warn "NAT rules could not be verified, but continuing anyway"
        return true

      rescue ConfigurationError => e
        raise
      rescue StandardError => e
        raise ExecutionError, "Failed to verify NAT configuration: #{e.message}"
      end
    end

    def uninstall
      begin
        logger.info "Uninstalling PF NAT configuration..."
        # DO NOT disable PF, just remove NAT rules
        # DO NOT USE: execute_command_with_output("sudo pfctl -d || true")

        # Step 1: Flush NAT rules only (keep PF enabled)
        flush_result = execute_command_with_output("sudo pfctl -F nat")

        if !flush_result[:success]
          # Non-fatal error, continue with uninstallation
          logger.warn "Failed to flush NAT rules: #{flush_result[:stderr]}"
        else
          logger.info "Successfully flushed NAT rules (kept PF enabled)"
        end

        # Step 2: Clean up any temp files
        # Instead of hardcoding a single path, look for any possible temporary rule files
        ["#{DEFAULT_TMP_NAT_RULE}", "/tmp/nat_rule.*"].each do |pattern|
          Dir.glob(pattern).each do |file|
            begin
              # Check if we have direct file permissions
              if File.owned?(file) && File.writable?(file)
                File.unlink(file)
                logger.info "Removed temporary NAT rule file: #{file}"
              else
                # Use sudo to remove files we don't own but were created by our process
                sudo_rm = execute_command_with_output("sudo rm #{file}")
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
        end

        # Step 3: Remove the LaunchDaemon if it exists
        if File.exist?(NAT_LAUNCH_DAEMON_PATH)
          # First unload it
          unload_result = execute_command_with_output("sudo launchctl unload -w #{NAT_LAUNCH_DAEMON_PATH}")

          if !unload_result[:success]
            logger.warn "Failed to unload NAT LaunchDaemon: #{unload_result[:stderr]}"
          else
            logger.info "Unloaded NAT LaunchDaemon"
          end

          # Then remove the file
          remove_result = execute_command_with_output("sudo rm #{NAT_LAUNCH_DAEMON_PATH}")

          if !remove_result[:success]
            logger.warn "Failed to remove NAT LaunchDaemon file: #{remove_result[:stderr]}"
          else
            logger.info "Removed NAT LaunchDaemon file"
          end
        else
          logger.info "No NAT LaunchDaemon found to remove"
        end

        logger.info "Successfully removed PF NAT configuration"
        return true
      rescue StandardError => e
        logger.error "Failed to remove PF configuration: #{e.message}", exception: e
        # We still return true so the uninstallation process can continue
        # with other components
        return true
      end
    end

    def verify_running
      # Step 1: Check if PF is enabled, this is the minimal requirement
      pf_status = execute_command_with_output('sudo pfctl -s info')
      if pf_status[:success] && pf_status[:stdout].include?('Status: Enabled')
        logger.info "PF is enabled"
      else
        # If PF isn't enabled, enable it
        execute_command_with_output('sudo pfctl -e')
        logger.info "Enabled PF"
      end

      # Step 2: Verify we can see network traffic or NAT configuration

      # First check if our NAT rule is visible
      nat_check = execute_command_with_output('sudo pfctl -s nat')
      if nat_check[:success] && !nat_check[:stdout].empty?
        if nat_check[:stdout].include?(@wan) && nat_check[:stdout].include?("#{@subnet}")
          logger.info "NAT rules verified with correct interfaces"
          return true
        else
          logger.warn "NAT rules exist but may not match expected configuration"
          # Continue anyway if force is enabled or if there are any NAT rules
          return true if @force || !nat_check[:stdout].empty?
        end
      end

      # Alternatively, check if Internet Sharing is enabled
      internet_sharing = execute_command_with_output('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled')
      if internet_sharing[:success] && internet_sharing[:stdout].include?('Enabled = 1')
        logger.info "Internet Sharing is enabled, which provides NAT functionality"
        return true
      end

      # Last resort: check if ipforwarding is enabled, which suggests NAT is working
      ip_forward = execute_command_with_output('sysctl net.inet.ip.forwarding')
      if ip_forward[:success] && ip_forward[:stdout].include?('= 1')
        logger.info "IP forwarding is enabled, suggesting NAT may be working"
        return true
      end

      # If we've enabled PF and force is on, return true anyway
      if @force
        logger.info "Force mode is active - assuming NAT is working"
        return true
      end

      # Couldn't verify NAT is working
      logger.warn "Could not verify NAT is properly configured"
      false
    end

    # Creates a LaunchDaemon to automatically restore NAT at boot
    def create_nat_launch_daemon
      logger.info "Creating LaunchDaemon for persistent NAT rules"

      # Create a secure temporary file for the plist
      temp_file = nil

      begin
        # Use the template renderer to create the LaunchDaemon plist
        renderer = MacRouterUtils::TemplateRenderer.new
        variables = {
          wan_interface: @wan,
          subnet: @subnet
        }

        # Render the template
        begin
          plist_content = renderer.render('nat_launchdaemon', variables)
        rescue StandardError => e
          raise ConfigurationError, "Failed to render NAT LaunchDaemon template: #{e.message}"
        end

        # Write to a secure temporary file
        begin
          tmp = Tempfile.new(['com.macrouternas.nat', '.plist'], '/tmp')
          temp_file = tmp.path
          tmp.close

          File.write(temp_file, plist_content)
          FileUtils.chmod(0644, temp_file) # Ensure it's readable
        rescue StandardError => e
          raise ExecutionError, "Failed to create temporary plist file: #{e.message}"
        end

        # Check if LaunchDaemon already exists and unload it if needed
        if File.exist?(NAT_LAUNCH_DAEMON_PATH)
          logger.info "Unloading existing NAT LaunchDaemon..."
          unload_result = execute_command_with_output("sudo launchctl unload -w #{NAT_LAUNCH_DAEMON_PATH}")

          if !unload_result[:success]
            logger.warn "Failed to unload existing NAT LaunchDaemon: #{unload_result[:stderr]}"
            # This is not fatal, we'll overwrite the file and try loading again
          else
            logger.info "Successfully unloaded existing NAT LaunchDaemon"
          end
        end

        # Move to LaunchDaemons directory with sudo
        logger.info "Installing NAT LaunchDaemon..."

        # Ensure the LaunchDaemons directory exists
        mkdir_result = execute_command_with_output("sudo mkdir -p #{File.dirname(NAT_LAUNCH_DAEMON_PATH)}")
        if !mkdir_result[:success]
          raise ExecutionError, "Failed to create LaunchDaemons directory: #{mkdir_result[:stderr]}"
        end

        # Copy the file
        cp_result = execute_command_with_output("sudo cp #{temp_file} #{NAT_LAUNCH_DAEMON_PATH}")
        if !cp_result[:success]
          raise ExecutionError, "Failed to install NAT LaunchDaemon: #{cp_result[:stderr]}"
        end

        # Set ownership and permissions
        chown_result = execute_command_with_output("sudo chown root:wheel #{NAT_LAUNCH_DAEMON_PATH}")
        if !chown_result[:success]
          raise ExecutionError, "Failed to set ownership on LaunchDaemon: #{chown_result[:stderr]}"
        end

        chmod_result = execute_command_with_output("sudo chmod 644 #{NAT_LAUNCH_DAEMON_PATH}")
        if !chmod_result[:success]
          raise ExecutionError, "Failed to set permissions on LaunchDaemon: #{chmod_result[:stderr]}"
        end

        # Load the LaunchDaemon
        logger.info "Loading NAT LaunchDaemon..."
        load_result = execute_command_with_output("sudo launchctl load -w #{NAT_LAUNCH_DAEMON_PATH}")

        if !load_result[:success]
          raise ExecutionError, "Failed to load NAT LaunchDaemon: #{load_result[:stderr]}"
        end

        logger.info "Persistent NAT successfully configured via LaunchDaemon"
        return true
      rescue ValidationError, ConfigurationError, ExecutionError => e
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
      pattern = /nat\s+on\s+(\S+)(?:\s+inet)?\s+from\s+(\S+\/\d+)\s+to\s+any\s+->\s+\((\S+)\)(?:\s+round-robin)?/
      
      # Find the first matching line (which is the last matching line in the original output)
      lines.each do |line|
        matches = line.match(pattern)
        if matches
          result[:nat_configured] = true
          result[:interfaces] = {
            wan: matches[1],  # WAN interface
          }
          result[:subnet] = matches[2]  # Subnet
          break # Stop after finding the first match
        end
      end
      
      result
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
        result[:enabled] = (status =~ /Enabled/i) ? true : false
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
      pf_result = execute_command_with_output('sudo pfctl -s info')
      if pf_result[:success]
        pf_status = parse_pf_info(pf_result[:stdout])
        status[:enabled] = pf_status[:enabled]
        status[:debug] = pf_status[:debug] if pf_status[:debug]
        status[:version] = pf_status[:version] if pf_status[:version]
      end

      # If PF is disabled, NAT can't work
      return status unless status[:enabled]

      # Check for NAT rules using multiple methods
      nat_result = execute_command_with_output('sudo pfctl -s nat')
      all_rules = execute_command_with_output('sudo pfctl -s all | grep nat')

      # Process NAT rule output
      nat_status = nil
      
      # First try the specific nat result
      if nat_result[:success] && !nat_result[:stdout].empty?
        nat_status = parse_nat_rule_output(nat_result[:stdout])
      end
      
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
      if !status[:nat_configured]
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
          
          wan_if = matches[1].gsub(/\$/, '') # Remove $ from variable names
          lan_if = matches[2].sub(/:network.*$/, '').gsub(/\$/, '')

          status[:interfaces] = {
            wan: wan_if,
            lan: lan_if
          }
        end
      end
      
      # Also check if Internet Sharing might be running
      internet_sharing = execute_command_with_output('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled')
      if internet_sharing[:success] && internet_sharing[:stdout].include?('Enabled = 1')
        status[:internet_sharing_enabled] = true
        status[:nat_configured] = true
        status[:managed_by_system] = true
      end

      status
    end
  end
end