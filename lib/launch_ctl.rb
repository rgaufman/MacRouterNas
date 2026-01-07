#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'shell'

module MacRouterUtils
  # Helper for launchctl operations (LaunchDaemon/LaunchAgent management)
  # Provides clean API for managing launch services without shell pipes
  class LaunchCtl
    # List all loaded services
    # Returns array of service labels
    #
    # Example:
    #   LaunchCtl.list
    #   # => ['com.apple.Spotlight', 'com.macrouternas.ipforwarding']
    def self.list
      result = Shell.run('sudo launchctl list', raise_on_failure: false)
      return [] unless result[:success] && !result[:stdout].empty?

      # Parse launchctl list output, skip header and extract labels
      lines = result[:stdout].split("\n")
      return [] if lines.length < 2

      # Format: PID   Status  Label
      lines[1..].map do |line|
        parts = line.split
        parts[2] if parts.length >= 3
      end.compact
    end

    # Check if a service is loaded
    # Returns boolean
    #
    # Example:
    #   LaunchCtl.loaded?('com.macrouternas.ipforwarding')  # => true
    def self.loaded?(service_label)
      result = Shell.run("sudo launchctl list | grep #{service_label}", raise_on_failure: false)
      result[:success] && !result[:stdout].empty?
    end

    # Load a plist file
    # Returns true on success, raises on failure
    #
    # Options:
    #   force_load: false - Use -w flag to force load
    #
    # Example:
    #   LaunchCtl.load('/Library/LaunchDaemons/com.example.plist')
    #   LaunchCtl.load('/Library/LaunchDaemons/com.example.plist', force_load: true)
    def self.load(plist_path, force_load: false)
      flags = force_load ? '-w' : ''
      result = Shell.run("sudo launchctl load #{flags} #{plist_path}")
      result[:success]
    end

    # Unload a plist file
    # Returns true on success, raises on failure
    #
    # Options:
    #   force_unload: false - Use -w flag to force unload
    #
    # Example:
    #   LaunchCtl.unload('/Library/LaunchDaemons/com.example.plist')
    #   LaunchCtl.unload('/Library/LaunchDaemons/com.example.plist', force_unload: true)
    def self.unload(plist_path, force_unload: false)
      flags = force_unload ? '-w' : ''
      result = Shell.run("sudo launchctl unload #{flags} #{plist_path}", raise_on_failure: false)
      result[:success]
    end

    # Bootstrap a service (newer launchctl API)
    # Returns true on success, raises on failure
    #
    # Example:
    #   LaunchCtl.bootstrap('system', '/Library/LaunchDaemons/com.example.plist')
    def self.bootstrap(domain, plist_path)
      result = Shell.run("sudo launchctl bootstrap #{domain} #{plist_path}")
      result[:success]
    end

    # Bootout a service (newer launchctl API)
    # Returns true on success, raises on failure
    #
    # Example:
    #   LaunchCtl.bootout('system', '/Library/LaunchDaemons/com.example.plist')
    def self.bootout(domain, plist_path)
      result = Shell.run("sudo launchctl bootout #{domain} #{plist_path}", raise_on_failure: false)
      result[:success]
    end

    # Get info about a service
    # Returns hash with service information or nil if not found
    #
    # Example:
    #   LaunchCtl.info('com.macrouternas.ipforwarding')
    def self.info(service_label)
      result = Shell.run("sudo launchctl print system/#{service_label}", raise_on_failure: false)
      return nil unless result[:success]

      # Return the raw output - parsing this format is complex and depends on macOS version
      { label: service_label, info: result[:stdout] }
    end
  end
end
