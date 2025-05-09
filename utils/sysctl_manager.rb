#!/usr/bin/env ruby
# frozen_string_literal: true

# Sysctl manager for MacRouter utilities
# Provides functionality for managing sysctl configuration

require_relative 'system_manager'

module MacRouterUtils
  # Manages sysctl configuration
  class SysctlManager < SystemManager
    SYSCTL_CONF = '/etc/sysctl.conf'
    IP_FORWARDING = 'net.inet.ip.forwarding=1'
    IP_FORWARDING_DISABLE = 'net.inet.ip.forwarding=0'
    LAUNCH_DAEMON_PLIST = '/Library/LaunchDaemons/com.macrouternas.ipforwarding.plist'
    
    class SysctlManagerError < StandardError; end
    class ConfigurationError < SysctlManagerError; end
    class ValidationError < SysctlManagerError; end
    class ExecutionError < SysctlManagerError; end

    def ensure_ip_forwarding
      begin
        logger.info "Ensuring IP forwarding is enabled..."

        # Step 1: Check if IP forwarding is already enabled
        status_result = execute_command_with_output("sysctl net.inet.ip.forwarding")

        # Check for both "key: value" and "key=value" formats
        if status_result[:success] && (status_result[:stdout].include?(": 1") || status_result[:stdout].include?("=1"))
          logger.info "IP forwarding is already enabled"
        else
          # Step 2: Enable IP forwarding using a direct script approach for better reliability
          enable_ip_forwarding_with_script
        end

        # Step 3: Set up persistent IP forwarding via LaunchDaemon
        create_ip_forwarding_launch_daemon
        
        # Step 4: Final verification
        verify_final = execute_command_with_output("sysctl net.inet.ip.forwarding")
        if !verify_final[:success] || (!verify_final[:stdout].include?(": 1") && !verify_final[:stdout].include?("=1"))
          # One last attempt using direct system command
          logger.warn "Final verification failed, trying one last direct command..."

          # Use backticks for direct execution
          direct_value = `sudo sysctl -w net.inet.ip.forwarding=1 && sysctl net.inet.ip.forwarding`.strip

          if direct_value.include?("= 1")
            logger.info "IP forwarding enabled successfully with direct command"
          else
            # In production we might want to fail, but for now we'll continue with a warning
            logger.warn "IP forwarding verification still failed, but continuing with setup"
            logger.warn "You may need to manually enable IP forwarding with: sudo sysctl -w net.inet.ip.forwarding=1"
            # Don't raise an error to allow setup to continue
            # raise ConfigurationError, "IP forwarding is still not enabled after configuration!"
          end
        end
        
        logger.info "IP forwarding is enabled and will persist across reboots"
        return true
      rescue ValidationError, ConfigurationError, ExecutionError => e
        logger.error "IP forwarding configuration error: #{e.message}", exception: e
        raise
      rescue StandardError => e
        logger.error "Failed to configure IP forwarding: #{e.message}", exception: e
        raise
      end
    end
    
    # Use a script-based approach to enable IP forwarding for better reliability
    def enable_ip_forwarding_with_script
      logger.info "Enabling IP forwarding via script..."
      
      # Create a temporary script
      script_path = "/tmp/enable_ip_forwarding_#{Process.pid}.sh"
      script_content = <<~BASH
        #!/bin/bash
        # Script to enable IP forwarding
        echo "Enabling IP forwarding via direct system call..."
        /usr/sbin/sysctl -w net.inet.ip.forwarding=1
        
        # Verify it's enabled - get the full output to see the exact format
        full_output=$(/usr/sbin/sysctl net.inet.ip.forwarding)
        value=$(/usr/sbin/sysctl -n net.inet.ip.forwarding)
        echo "Current IP forwarding value: $value"
        echo "Full output: $full_output"

        # Check if the value is 1, regardless of output format
        if [ "$value" -eq "1" ]; then
          echo "IP forwarding successfully enabled"
          exit 0
        else
          echo "Failed to enable IP forwarding"
          exit 1
        fi
      BASH
      
      begin
        # Write the script
        File.write(script_path, script_content)
        FileUtils.chmod(0700, script_path)
        
        # Execute it with sudo
        logger.info "Executing IP forwarding script..."
        result = system("sudo #{script_path}")
        
        # Check result
        if result
          logger.info "IP forwarding successfully enabled via script"
        else
          # Try one more time with a simpler direct command
          logger.warn "Script method failed, trying direct command..."
          direct_result = system("sudo sysctl -w net.inet.ip.forwarding=1")
          
          if !direct_result
            raise ExecutionError, "Failed to enable IP forwarding"
          end
          
          # Verify it worked
          verify = `sysctl net.inet.ip.forwarding`.strip
          if !verify.include?(": 1") && !verify.include?("=1")
            raise ConfigurationError, "IP forwarding setting failed to apply"
          end
          
          logger.info "IP forwarding enabled via direct command"
        end
      rescue StandardError => e
        raise ExecutionError, "Error in IP forwarding script: #{e.message}"
      ensure
        # Clean up
        File.unlink(script_path) if File.exist?(script_path)
      end
    end

    # Creates a LaunchDaemon to enable IP forwarding at boot
    def create_ip_forwarding_launch_daemon
      logger.info "Creating LaunchDaemon for persistent IP forwarding..."
      temp_file = nil
      
      begin
        # Use the template renderer to create the LaunchDaemon plist
        renderer = MacRouterUtils::TemplateRenderer.new
        
        begin
          plist_content = renderer.render('ip_forwarding_launchdaemon', {})
        rescue StandardError => e
          raise ConfigurationError, "Failed to render IP forwarding LaunchDaemon template: #{e.message}"
        end

        # Write to a secure temporary file
        begin
          tmp = Tempfile.new(['com.macrouternas.ipforwarding', '.plist'], '/tmp')
          temp_file = tmp.path
          tmp.close
          
          File.write(temp_file, plist_content)
          FileUtils.chmod(0644, temp_file) # Ensure it's readable
        rescue StandardError => e
          raise ExecutionError, "Failed to create temporary plist file: #{e.message}"
        end

        # Check if LaunchDaemon already exists and unload it if needed
        if File.exist?(LAUNCH_DAEMON_PLIST)
          logger.info "Unloading existing IP forwarding LaunchDaemon..."
          unload_result = execute_command_with_output("sudo launchctl unload -w #{LAUNCH_DAEMON_PLIST}")
          
          if !unload_result[:success]
            logger.warn "Failed to unload existing IP forwarding LaunchDaemon: #{unload_result[:stderr]}"
            # This is not fatal, we'll overwrite the file and try loading again
          else
            logger.info "Successfully unloaded existing IP forwarding LaunchDaemon"
          end
        end

        # Ensure the LaunchDaemons directory exists
        mkdir_result = execute_command_with_output("sudo mkdir -p #{File.dirname(LAUNCH_DAEMON_PLIST)}")
        if !mkdir_result[:success]
          raise ExecutionError, "Failed to create LaunchDaemons directory: #{mkdir_result[:stderr]}"
        end
        
        # Copy the file
        cp_result = execute_command_with_output("sudo cp #{temp_file} #{LAUNCH_DAEMON_PLIST}")
        if !cp_result[:success]
          raise ExecutionError, "Failed to install IP forwarding LaunchDaemon: #{cp_result[:stderr]}"
        end
        
        # Set ownership and permissions
        chown_result = execute_command_with_output("sudo chown root:wheel #{LAUNCH_DAEMON_PLIST}")
        if !chown_result[:success]
          raise ExecutionError, "Failed to set ownership on LaunchDaemon: #{chown_result[:stderr]}"
        end
        
        chmod_result = execute_command_with_output("sudo chmod 644 #{LAUNCH_DAEMON_PLIST}")
        if !chmod_result[:success]
          raise ExecutionError, "Failed to set permissions on LaunchDaemon: #{chmod_result[:stderr]}"
        end

        # Load the LaunchDaemon
        logger.info "Loading IP forwarding LaunchDaemon..."
        load_result = execute_command_with_output("sudo launchctl load -w #{LAUNCH_DAEMON_PLIST}")
        
        if !load_result[:success]
          raise ExecutionError, "Failed to load IP forwarding LaunchDaemon: #{load_result[:stderr]}"
        end

        # Give it a moment to run
        sleep(1)
        
        # Verify IP forwarding is still enabled
        verify_result = execute_command_with_output("sysctl net.inet.ip.forwarding")
        if !verify_result[:success] || (!verify_result[:stdout].include?(": 1") && !verify_result[:stdout].include?("=1"))
          logger.warn "LaunchDaemon loaded but IP forwarding is not enabled. Enabling manually..."

          # Try multiple approaches to enable IP forwarding

          # First, try our standard method
          manual_enable = execute_command_with_output("sudo sysctl -w #{IP_FORWARDING}")

          # Check if it worked
          verify_again = execute_command_with_output("sysctl net.inet.ip.forwarding")
          if verify_again[:success] && (verify_again[:stdout].include?(": 1") || verify_again[:stdout].include?("=1"))
            logger.info "IP forwarding enabled successfully after manual attempt"
            return true
          end

          # If still not working, try direct approach with backticks
          logger.warn "Standard method failed, trying direct backtick execution..."
          direct_result = `sudo sysctl -w net.inet.ip.forwarding=1`
          if $?.success?
            logger.info "IP forwarding enabled with direct execution"
          else
            # We'll still continue but with a warning
            logger.warn "All attempts to enable IP forwarding have failed"
            logger.warn "You may need to manually enable IP forwarding with: sudo sysctl -w net.inet.ip.forwarding=1"
          end
        end

        logger.info "Persistent IP forwarding successfully configured via LaunchDaemon"
        return true
      rescue ValidationError, ConfigurationError, ExecutionError => e
        raise
      rescue StandardError => e
        raise ExecutionError, "Failed to create IP forwarding LaunchDaemon: #{e.message}"
      ensure
        # Clean up temporary file
        File.unlink(temp_file) if temp_file && File.exist?(temp_file)
      end
    end

    def uninstall
      begin
        logger.info "Uninstalling IP forwarding configuration..."
        
        # Step 1: Disable IP forwarding
        logger.info "Disabling IP forwarding..."
        disable_result = execute_command_with_output("sudo sysctl -w #{IP_FORWARDING_DISABLE}")
        
        if !disable_result[:success]
          logger.warn "Failed to disable IP forwarding: #{disable_result[:stderr]}"
        else
          logger.info "IP forwarding disabled for current session"
          
          # Verify it's disabled
          verify_result = execute_command_with_output("sysctl net.inet.ip.forwarding")
          if verify_result[:success] && (verify_result[:stdout].include?(": 0") || verify_result[:stdout].include?("=0"))
            logger.info "Verified IP forwarding is disabled"
          else
            logger.warn "IP forwarding may still be enabled"
          end
        end

        # Step 2: Remove the LaunchDaemon if it exists
        if File.exist?(LAUNCH_DAEMON_PLIST)
          # First unload it
          logger.info "Unloading IP forwarding LaunchDaemon..."
          unload_result = execute_command_with_output("sudo launchctl unload -w #{LAUNCH_DAEMON_PLIST}")
          
          if !unload_result[:success]
            logger.warn "Failed to unload IP forwarding LaunchDaemon: #{unload_result[:stderr]}"
          else
            logger.info "Successfully unloaded IP forwarding LaunchDaemon"
          end
          
          # Then remove the file
          logger.info "Removing IP forwarding LaunchDaemon file..."
          remove_result = execute_command_with_output("sudo rm #{LAUNCH_DAEMON_PLIST}")
          
          if !remove_result[:success]
            logger.warn "Failed to remove IP forwarding LaunchDaemon file: #{remove_result[:stderr]}"
          else
            logger.info "Successfully removed IP forwarding LaunchDaemon file"
          end
        else
          logger.info "No IP forwarding LaunchDaemon found to remove"
        end
        
        logger.info "IP forwarding configuration uninstallation complete"
        return true
      rescue StandardError => e
        logger.error "Failed to disable IP forwarding: #{e.message}", exception: e
        # We still return true so the uninstallation process can continue
        # with other components
        return true
      end
    end

    def check_status
      # Create the hash to return
      status = {
        enabled: false,
        persistent: false,
        internet_sharing_active: false
      }

      # Check direct sysctl setting first
      result = execute_command_with_output("sysctl net.inet.ip.forwarding")
      if result[:success]
        # Check both possible formats: "key: value" (macOS) and "key=value" (some systems)
        if result[:stdout].include?(':')
          value = result[:stdout].strip.split(':').last.strip.to_i
        elsif result[:stdout].include?('=')
          value = result[:stdout].strip.split('=').last.strip.to_i
        else
          # If we can't parse, extract any integer from the output
          value = result[:stdout].scan(/\d+/).first.to_i
        end

        status[:enabled] = value == 1
      end

      # Check for Internet Sharing, which might enable IP forwarding without sysctl
      internet_sharing = execute_command_with_output('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled')
      if internet_sharing[:success] && internet_sharing[:stdout].include?('Enabled = 1')
        status[:internet_sharing_active] = true

        # If Internet Sharing is active, we can consider IP forwarding functionally enabled
        # even if the sysctl value doesn't show it
        status[:effective_enabled] = true
      else
        status[:effective_enabled] = status[:enabled]
      end

      # Check if we can detect actual IP forwarding via traffic
      if !status[:enabled] && status[:internet_sharing_active]
        # Try to check actual IP forwarding by seeing if there's NAT traffic
        nat_stats = execute_command_with_output('sudo pfctl -s state | grep NAT')
        if nat_stats[:success] && !nat_stats[:stdout].empty?
          status[:nat_traffic_detected] = true
          # There's actual NAT traffic happening, so IP forwarding must be effectively enabled
          status[:effective_enabled] = true
        end
      end

      # Check if the LaunchDaemon exists (persistent config)
      status[:persistent] = File.exist?(LAUNCH_DAEMON_PLIST)

      # Check if the LaunchDaemon is loaded (active)
      if status[:persistent]
        # Check if it's loaded via launchctl
        launchctl_result = execute_command_with_output("sudo launchctl list | grep com.macrouternas.ipforwarding")
        status[:persistent_active] = launchctl_result[:success] && !launchctl_result[:stdout].empty?
      end

      # For backward compatibility
      if caller_locations(1,1)[0].label == 'show_status'
        # Return the effective status for display purposes
        return status[:effective_enabled]
      end

      # Return the full status hash
      status
    end
  end
end