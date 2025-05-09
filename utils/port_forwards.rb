#!/usr/bin/env ruby
# frozen_string_literal: true

# Port forwarding utility for MacRouter
# Provides functionality for managing port forwarding rules

require 'fileutils'
require 'tempfile'
require 'json'
require_relative 'system_manager'

module MacRouterUtils
  # Manages port forwarding using PF (Packet Filter)
  class PortForwards < SystemManager
    # Define constants
    # Use user's home directory instead of system directories to avoid permission issues
    PORT_FORWARDS_FILE = ENV['HOME'] + '/.config/macrouternas/port_forwards.json'

    # Class for port forwarding errors
    class PortForwardError < StandardError; end

    def initialize(wan_interface)
      @wan_interface = wan_interface
      # Ensure the directory for port forwards file exists
      create_port_forwards_directory
    end

    # Add a new port forwarding rule
    def add_port_forward(external_port, internal_ip, internal_port, protocol = 'tcp')
      port_forwards = load_port_forwards

      # Validate inputs
      validate_port(external_port)
      validate_ip(internal_ip)
      validate_port(internal_port)
      validate_protocol(protocol)

      # Special handling for 'both' protocol
      if protocol.downcase == 'both'
        # Add both TCP and UDP rules
        ['tcp', 'udp'].each do |single_protocol|
          add_single_protocol_forward(port_forwards, external_port, internal_ip, internal_port, single_protocol)
        end
        logger.info "Added port forwarding rule for both TCP and UDP: #{external_port} -> #{internal_ip}:#{internal_port}"
      else
        # Add a single protocol rule
        add_single_protocol_forward(port_forwards, external_port, internal_ip, internal_port, protocol)
      end

      save_port_forwards(port_forwards)
      apply_port_forwards
    end

    # Helper to add a single protocol rule
    def add_single_protocol_forward(port_forwards, external_port, internal_ip, internal_port, protocol)
      # Check if a rule with the same external port and protocol already exists
      existing_rule_index = port_forwards.find_index { |r| r['external_port'] == external_port && r['protocol'] == protocol }

      if existing_rule_index
        # If we're updating an existing rule, replace it
        port_forwards[existing_rule_index] = {
          'external_port' => external_port,
          'internal_ip' => internal_ip,
          'internal_port' => internal_port,
          'protocol' => protocol
        }
        logger.info "Updated port forwarding rule: #{protocol} #{external_port} -> #{internal_ip}:#{internal_port}"
      else
        # Add new rule
        port_forwards << {
          'external_port' => external_port,
          'internal_ip' => internal_ip,
          'internal_port' => internal_port,
          'protocol' => protocol
        }
        logger.info "Added port forwarding rule: #{protocol} #{external_port} -> #{internal_ip}:#{internal_port}"
      end
    end

    # Remove a port forwarding rule
    def remove_port_forward(external_port, protocol = 'tcp')
      port_forwards = load_port_forwards

      # Validate inputs
      validate_port(external_port)
      validate_protocol(protocol)

      # Special handling for 'both' protocol
      if protocol.downcase == 'both'
        # Remove both TCP and UDP rules
        tcp_removed = remove_single_protocol_forward(port_forwards, external_port, 'tcp')
        udp_removed = remove_single_protocol_forward(port_forwards, external_port, 'udp')

        if tcp_removed || udp_removed
          logger.info "Removed port forwarding rule(s) for both TCP and UDP: #{external_port}"
          save_port_forwards(port_forwards)
          apply_port_forwards
          return true
        else
          logger.warn "No port forwarding rules found for TCP or UDP on port #{external_port}"
          return false
        end
      else
        # Remove a single protocol rule
        if remove_single_protocol_forward(port_forwards, external_port, protocol)
          save_port_forwards(port_forwards)
          apply_port_forwards
          return true
        else
          return false
        end
      end
    end

    # Helper to remove a single protocol rule
    def remove_single_protocol_forward(port_forwards, external_port, protocol)
      original_count = port_forwards.length
      port_forwards.reject! { |r| r['external_port'] == external_port && r['protocol'] == protocol }

      if port_forwards.length < original_count
        logger.info "Removed port forwarding rule: #{protocol} #{external_port}"
        return true
      else
        logger.warn "No port forwarding rule found for #{protocol} #{external_port}"
        return false
      end
    end

    # List all port forwarding rules
    def list_port_forwards
      port_forwards = load_port_forwards
      return port_forwards
    end

    # Apply all port forwarding rules to pf
    def apply_port_forwards
      port_forwards = load_port_forwards
      return true if port_forwards.empty?

      # Create a temporary file for port forwarding rules
      begin
        tmp_file = Tempfile.new(['port_forwards', '.conf'], '/tmp')
        tmp_path = tmp_file.path
        tmp_file.close

        # Create the rdr rules
        rules_content = "# Port forwarding rules\n"
        port_forwards.each do |rule|
          rules_content += "rdr on #{@wan_interface} proto #{rule['protocol']} from any to any port #{rule['external_port']} -> #{rule['internal_ip']} port #{rule['internal_port']}\n"
        end

        # Write the rules to the temporary file
        File.write(tmp_path, rules_content)
        FileUtils.chmod(0600, tmp_path) # Only owner can read/write

        # Also save to a persistent location for the LaunchDaemon to find
        rules_dir = File.dirname(PORT_FORWARDS_FILE)
        begin
          FileUtils.mkdir_p(rules_dir) unless Dir.exist?(rules_dir)
          File.write("#{rules_dir}/port_forwards_rules.conf", rules_content)
        rescue StandardError => e
          logger.warn "Failed to save persistent rules file: #{e.message}"
        end

        # Load the rules into PF
        load_result = execute_command_with_output("sudo pfctl -a com.macrouternas/portforwards -f #{tmp_path}")
        unless load_result[:success]
          # Check if anchor doesn't exist and needs to be created
          if load_result[:stderr].include?("Could not open anchor")
            # Create anchor first
            execute_command_with_output("sudo pfctl -N com.macrouternas")
            execute_command_with_output("sudo pfctl -N com.macrouternas/portforwards")
            # Try loading again
            load_result = execute_command_with_output("sudo pfctl -a com.macrouternas/portforwards -f #{tmp_path}")
            unless load_result[:success]
              logger.error "Failed to load port forwarding rules: #{load_result[:stderr]}"
              return false
            end
          else
            logger.error "Failed to load port forwarding rules: #{load_result[:stderr]}"
            return false
          end
        end

        # Add reference to anchor in the main ruleset if not already there
        main_ruleset = execute_command_with_output("sudo pfctl -s all")
        unless main_ruleset[:stdout].include?("com.macrouternas/portforwards")
          # We need to add a reference to our anchor
          anchor_rule = "rdr-anchor \"com.macrouternas/portforwards\""
          tmp_anchor = Tempfile.new(['anchor_ref', '.conf'], '/tmp')
          tmp_anchor_path = tmp_anchor.path
          tmp_anchor.close
          
          File.write(tmp_anchor_path, anchor_rule)
          FileUtils.chmod(0600, tmp_anchor_path)
          
          add_anchor = execute_command_with_output("sudo pfctl -a com.macrouternas -f #{tmp_anchor_path}")
          unless add_anchor[:success]
            logger.warn "Failed to add anchor reference: #{add_anchor[:stderr]}"
            # This isn't fatal - the port forwarding rules may still work
          end
          
          File.unlink(tmp_anchor_path) if File.exist?(tmp_anchor_path)
        end

        logger.info "Applied #{port_forwards.length} port forwarding rules"
        return true
      rescue StandardError => e
        logger.error "Failed to apply port forwarding rules: #{e.message}"
        return false
      ensure
        # Clean up temporary file
        File.unlink(tmp_path) if tmp_path && File.exist?(tmp_path)
      end
    end

    private

    # Create directory for port forwards file
    def create_port_forwards_directory
      directory = File.dirname(PORT_FORWARDS_FILE)
      unless Dir.exist?(directory)
        begin
          # Try creating directory without sudo first
          FileUtils.mkdir_p(directory)
        rescue StandardError
          # If that fails, use sudo
          result = execute_command_with_output("sudo mkdir -p #{directory}")
          result = execute_command_with_output("sudo chmod 755 #{directory}") if result[:success]
          unless result[:success]
            logger.warn "Failed to create port forwards directory: #{result[:stderr]}"
          end
        end
      end
    end

    # Load port forwarding rules from file
    def load_port_forwards
      if File.exist?(PORT_FORWARDS_FILE)
        begin
          JSON.parse(File.read(PORT_FORWARDS_FILE))
        rescue JSON::ParserError => e
          logger.error "Failed to parse port forwards file: #{e.message}"
          []
        end
      else
        []
      end
    end

    # Save port forwarding rules to file
    def save_port_forwards(rules)
      begin
        # Write to a temp file
        tmp_file = Tempfile.new(['port_forwards', '.json'], '/tmp')
        tmp_path = tmp_file.path
        tmp_file.close
        
        File.write(tmp_path, JSON.pretty_generate(rules))
        
        # Use sudo to copy to final location
        result = execute_command_with_output("sudo cp #{tmp_path} #{PORT_FORWARDS_FILE}")
        result = execute_command_with_output("sudo chmod 644 #{PORT_FORWARDS_FILE}") if result[:success]
        
        unless result[:success]
          logger.error "Failed to save port forwards file: #{result[:stderr]}"
          return false
        end
        
        return true
      rescue StandardError => e
        logger.error "Failed to save port forwards file: #{e.message}"
        return false
      ensure
        # Clean up temp file
        File.unlink(tmp_path) if tmp_path && File.exist?(tmp_path)
      end
    end

    # Validation methods
    def validate_port(port)
      port_num = port.to_i
      unless port_num.between?(1, 65535)
        raise PortForwardError, "Invalid port number: #{port}. Must be between 1-65535"
      end
    end

    def validate_ip(ip)
      # Basic IP validation - 4 octets between 0-255
      unless ip.match?(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
        raise PortForwardError, "Invalid IP address format: #{ip}"
      end
      
      # Check each octet is within range
      octets = ip.split('.')
      octets.each do |octet|
        unless octet.to_i.between?(0, 255)
          raise PortForwardError, "Invalid IP address: #{ip}. Each octet must be between 0-255"
        end
      end
    end

    def validate_protocol(protocol)
      unless %w[tcp udp both].include?(protocol.downcase)
        raise PortForwardError, "Invalid protocol: #{protocol}. Must be 'tcp', 'udp', or 'both'"
      end
    end
  end
end