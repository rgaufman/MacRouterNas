#!/usr/bin/env ruby
# frozen_string_literal: true

# Base class for system operations in MacRouter utilities
# Provides common methods for executing commands and checking configurations

require 'semantic_logger'
require 'open3'
require 'fileutils'

module MacRouterUtils
  class SystemManager
    include SemanticLogger::Loggable

    # Persistent system location for configurations - available at boot time
    PERSISTENT_CONFIG_DIR = '/usr/local/etc/MacRouterNas'

    def initialize
      # Ensure the persistent config directory exists
      ensure_persistent_config_dir
    end

    # Create the persistent config directory if it doesn't exist
    def ensure_persistent_config_dir
      return if Dir.exist?(PERSISTENT_CONFIG_DIR)

      # Skip creating the directory during uninstall operations
      return if is_uninstall_operation?

      logger.info "Creating persistent config directory: #{PERSISTENT_CONFIG_DIR}"
      result = execute_command_with_output("sudo mkdir -p #{PERSISTENT_CONFIG_DIR}")

      if result[:success]
        # Set permissions to allow our process to write to it
        execute_command_with_output("sudo chmod 755 #{PERSISTENT_CONFIG_DIR}")
        logger.info "Created persistent config directory successfully"
      else
        logger.warn "Failed to create persistent config directory: #{result[:stderr]}"
      end
    end

    # Helper method to check if we're in an uninstall operation
    def is_uninstall_operation?
      # Try to determine if we're in an uninstall operation by examining the call stack
      caller_locations.any? { |loc| loc.label.include?('uninstall') }
    end

    # Method to remove the persistent config directory during uninstall
    def remove_persistent_config_dir
      return unless Dir.exist?(PERSISTENT_CONFIG_DIR)

      logger.info "Removing persistent config directory: #{PERSISTENT_CONFIG_DIR}"

      # List files before deletion for debugging
      files = execute_command_with_output("ls -la #{PERSISTENT_CONFIG_DIR}")
      if files[:success]
        logger.debug "Files in persistent directory before deletion: #{files[:stdout]}"
      end

      # Remove the directory and its contents
      rmdir_result = execute_command_with_output("sudo rm -rf #{PERSISTENT_CONFIG_DIR}")

      if !rmdir_result[:success]
        logger.warn "Failed to remove persistent configuration directory: #{rmdir_result[:stderr]}"
      else
        logger.info "Successfully removed persistent configuration directory"
      end
    end

    # Store a file in the persistent config directory
    # Returns the path to the stored file
    def store_in_persistent_location(filename, content)
      # Ensure the directory exists
      ensure_persistent_config_dir

      # Path to the configuration file
      config_path = File.join(PERSISTENT_CONFIG_DIR, filename)

      # Create a temporary file with the content
      temp_file = "/tmp/#{filename}.#{Process.pid}"

      begin
        # Write to temp file
        File.write(temp_file, content)

        # Copy to persistent location with sudo
        result = execute_command_with_output("sudo cp #{temp_file} #{config_path}")

        if result[:success]
          # Set appropriate permissions
          execute_command_with_output("sudo chmod 644 #{config_path}")
          logger.info "Stored configuration file in persistent location: #{config_path}"
          return config_path
        else
          logger.error "Failed to store configuration in persistent location: #{result[:stderr]}"
          return nil
        end
      rescue StandardError => e
        logger.error "Error storing configuration in persistent location: #{e.message}"
        return nil
      ensure
        # Clean up the temporary file
        File.unlink(temp_file) if File.exist?(temp_file)
      end
    end

    # Read a file from the persistent config directory
    def read_from_persistent_location(filename)
      config_path = File.join(PERSISTENT_CONFIG_DIR, filename)

      if File.exist?(config_path)
        begin
          content = File.read(config_path)
          return content
        rescue StandardError => e
          logger.error "Error reading from persistent location: #{e.message}"
          return nil
        end
      else
        logger.warn "Configuration file not found in persistent location: #{config_path}"
        return nil
      end
    end

    def already_configured?(file, marker)
      File.exist?(file) && File.read(file).include?(marker)
    end

    def execute_command(command, error_message = nil)
      logger.debug "Executing: #{command}"

      stdout, stderr, status = Open3.capture3(command)

      if status.success?
        logger.debug "Command succeeded: #{stdout.strip}" unless stdout.empty?
        true
      else
        error = error_message || "Command failed: #{command}"
        logger.error "#{error}: #{stderr.strip}"
        raise "#{error}: #{stderr.strip}"
      end
    end

    def execute_command_with_output(command)
      stdout, stderr, status = Open3.capture3(command)
      { success: status.success?, stdout: stdout, stderr: stderr }
    end
  end
end
