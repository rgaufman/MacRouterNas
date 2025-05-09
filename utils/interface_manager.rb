#!/usr/bin/env ruby
# frozen_string_literal: true

# Interface manager for MacRouter utilities
# Provides functionality for managing network interfaces

require_relative 'system_manager'

module MacRouterUtils
  # Manages network interface configuration
  class InterfaceManager < SystemManager
    def initialize(lan, ip)
      @lan = lan
      @ip = ip
    end

    def configure
      output = `ifconfig #{@lan}`
      if output.include?(@ip)
        logger.info "#{@lan} already has IP #{@ip}"
      else
        execute_command("sudo ifconfig #{@lan} inet #{@ip} netmask 255.255.255.0 up",
                       "Failed to assign IP #{@ip} to interface #{@lan}")
        logger.info "IP #{@ip} assigned to #{@lan}"
      end
    rescue StandardError => e
      logger.error "Failed to configure interface: #{e.message}", exception: e
      raise
    end

    def uninstall
      begin
        # Check if the interface has our static IP
        output = `ifconfig #{@lan}`
        if output.include?(@ip)
          # Remove the static IP by bringing the interface down and up again
          execute_command("sudo ifconfig #{@lan} down", "Failed to bring down interface #{@lan}")
          execute_command("sudo ifconfig #{@lan} up", "Failed to bring up interface #{@lan}")
          logger.info "Reset interface #{@lan} configuration"
        else
          logger.info "Interface #{@lan} does not have our static IP, no reset needed"
        end
      rescue StandardError => e
        logger.error "Failed to reset interface: #{e.message}", exception: e
        raise
      end
    end

    def verify_configured
      output, _, status = Open3.capture3("ifconfig #{@lan}")
      status.success? && output.include?(@ip)
    end

    def check_wan_status(interface)
      status = { active: false }

      # Check if interface exists and is active
      result = execute_command_with_output("ifconfig #{interface}")
      if result[:success]
        # Handle different interface types differently
        if interface.start_with?('ppp')
          # For PPP interfaces, check for RUNNING flag and IP address
          has_running = result[:stdout].include?('RUNNING')
          has_ip = result[:stdout].match(/inet\s+\d+\.\d+\.\d+\.\d+/) ? true : false
          status[:active] = has_running && has_ip

          # Extract IP if available - PPP format may include destination address
          ip_match = result[:stdout].match(/inet\s+(\d+\.\d+\.\d+\.\d+)/)
          status[:ip] = ip_match[1] if ip_match

          # Also extract destination address if present
          dst_match = result[:stdout].match(/-->\s+(\d+\.\d+\.\d+\.\d+)/)
          status[:destination] = dst_match[1] if dst_match
        else
          # For Ethernet and other interfaces, check for 'status: active'
          status[:active] = result[:stdout].include?('status: active')

          # Extract IP if available
          ip_match = result[:stdout].match(/inet (\d+\.\d+\.\d+\.\d+)/)
          status[:ip] = ip_match[1] if ip_match
        end
      end

      status
    end

    def check_lan_status
      status = { active: false, has_static_ip: false }

      # Check if interface exists and is active
      result = execute_command_with_output("ifconfig #{@lan}")
      if result[:success]
        # Handle different interface types differently
        if @lan.start_with?('ppp')
          # For PPP interfaces, check for RUNNING flag and IP address
          has_running = result[:stdout].include?('RUNNING')
          has_ip = result[:stdout].match(/inet\s+\d+\.\d+\.\d+\.\d+/) ? true : false
          status[:active] = has_running && has_ip

          # Extract IP if available
          ip_match = result[:stdout].match(/inet\s+(\d+\.\d+\.\d+\.\d+)/)
          if ip_match
            status[:ip] = ip_match[1]
            status[:has_static_ip] = (ip_match[1] == @ip)
          end
        else
          # For Ethernet and other interfaces, check for 'status: active'
          status[:active] = result[:stdout].include?('status: active')

          # Extract IP if available
          ip_match = result[:stdout].match(/inet (\d+\.\d+\.\d+\.\d+)/)
          if ip_match
            status[:ip] = ip_match[1]
            status[:has_static_ip] = (ip_match[1] == @ip)
          end
        end
      end

      status
    end
  end
end