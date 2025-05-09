#!/usr/bin/env ruby
# frozen_string_literal: true

# Service manager for MacRouter utilities
# Provides functionality for managing system services

require_relative 'system_manager'

module MacRouterUtils
  class ServiceManager < SystemManager
    def initialize(service_name, paths = {})
      @service_name = service_name
      @plist_path = paths[:plist_path] || "/Library/LaunchDaemons/#{service_name}.plist"
      @logger = SemanticLogger["#{service_name.capitalize}Service"]
    end

    def running?
      system("pgrep -fl #{@service_name} > /dev/null")
    end

    def start
      if running?
        @logger.info("#{@service_name} is already running.")
        return true
      end

      @logger.info("Bootstrapping #{@service_name} LaunchDaemon...")
      result = system("sudo launchctl bootstrap system #{@plist_path}")

      unless result
        @logger.error('Failed to bootstrap service.')
        @logger.info("HINT: Try: sudo launchctl print system/#{@service_name}")
        exit 1
      end

      result
    end

    def stop
      if running?
        @logger.info("Stopping #{@service_name} service...")
        system("sudo launchctl bootout system #{@plist_path}")
        true
      else
        @logger.info("#{@service_name} is not running.")
        false
      end
    end

    def status
      if running?
        @logger.info("#{@service_name} is running.")
        true
      else
        @logger.info("#{@service_name} is not running.")
        false
      end
    end
  end
end
