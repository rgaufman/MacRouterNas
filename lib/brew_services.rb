#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'shell'

module MacRouterUtils
  # Helper for Homebrew services management
  # Provides clean API for managing brew services without shell pipes
  class BrewServices
    # List all brew services
    # Returns array of hashes with :name, :status, :user keys
    #
    # Example:
    #   BrewServices.list
    #   # => [{ name: 'dnsmasq', status: 'started', user: 'root' }]
    def self.list
      result = Shell.run('brew services list', raise_on_failure: false)
      return [] unless result[:success] && !result[:stdout].empty?

      # Parse brew services output
      # Format: Name   Status  User  File
      lines = result[:stdout].split("\n")
      return [] if lines.length < 2 # No services or only header

      lines[1..].map do |line|
        parts = line.split
        next nil if parts.length < 2

        {
          name: parts[0],
          status: parts[1],
          user: parts[2] # May be nil
        }
      end.compact
    end

    # Get status for a specific service
    # Returns hash with :name, :status, :user keys or nil if not found
    #
    # Example:
    #   BrewServices.status('dnsmasq')
    #   # => { name: 'dnsmasq', status: 'started', user: 'root' }
    def self.status(service_name)
      list.find { |service| service[:name] == service_name }
    end

    # Check if a service is running (started)
    # Returns boolean
    #
    # Example:
    #   BrewServices.running?('dnsmasq')  # => true
    def self.running?(service_name)
      service = status(service_name)
      return false if service.nil?

      service[:status] == 'started'
    end

    # Start a service
    # Returns true on success, raises on failure
    #
    # Example:
    #   BrewServices.start('dnsmasq')
    def self.start(service_name, use_sudo: false)
      cmd = use_sudo ? "sudo brew services start #{service_name}" : "brew services start #{service_name}"
      result = Shell.run(cmd)
      result[:success]
    end

    # Stop a service
    # Returns true on success, raises on failure
    #
    # Example:
    #   BrewServices.stop('dnsmasq')
    def self.stop(service_name, use_sudo: false)
      cmd = use_sudo ? "sudo brew services stop #{service_name}" : "brew services stop #{service_name}"
      result = Shell.run(cmd)
      result[:success]
    end

    # Restart a service
    # Returns true on success, raises on failure
    #
    # Example:
    #   BrewServices.restart('dnsmasq')
    def self.restart(service_name, use_sudo: false)
      cmd = use_sudo ? "sudo brew services restart #{service_name}" : "brew services restart #{service_name}"
      result = Shell.run(cmd)
      result[:success]
    end

    # Get logs for a service
    # Returns string with log output
    #
    # Example:
    #   BrewServices.logs('dnsmasq')
    def self.logs(service_name)
      result = Shell.run("brew services log #{service_name}", raise_on_failure: false)
      result[:success] ? result[:stdout] : ''
    end

    # Cleanup brew services
    # Returns true on success, raises on failure
    #
    # Example:
    #   BrewServices.cleanup
    def self.cleanup
      result = Shell.run('brew services cleanup', raise_on_failure: false)
      result[:success]
    end
  end
end
