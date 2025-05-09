#!/usr/bin/env ruby
# frozen_string_literal: true

# Base class for system operations in MacRouter utilities
# Provides common methods for executing commands and checking configurations

require 'semantic_logger'
require 'open3'

module MacRouterUtils
  class SystemManager
    include SemanticLogger::Loggable

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
