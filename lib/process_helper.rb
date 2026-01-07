#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'shell'

module MacRouterUtils
  # Helper for process management operations
  # Provides clean API for checking processes without shell pipes
  class ProcessHelper
    # Find all PIDs for a process by name
    # Returns array of PIDs (integers) or empty array if not found
    #
    # Options:
    #   full_match: false - match full command line (pgrep -f)
    #
    # Example:
    #   ProcessHelper.pids('dnsmasq')        # => [12345, 12346]
    #   ProcessHelper.pids('not_running')    # => []
    def self.pids(process_name, options = {})
      flags = options[:full_match] ? '-f' : ''
      result = Shell.run("pgrep #{flags} #{process_name}", raise_on_failure: false)
      return [] unless result[:success] && !result[:stdout].empty?

      result[:stdout].split("\n").map(&:strip).reject(&:empty?).map(&:to_i)
    end

    # Get the first/main PID for a process
    # Returns integer PID or nil if not found
    #
    # Example:
    #   ProcessHelper.pid('dnsmasq')  # => 12345
    def self.pid(process_name, options = {})
      pids(process_name, options).first
    end

    # Check if a process is running
    # Returns boolean
    #
    # Example:
    #   ProcessHelper.running?('dnsmasq')  # => true
    def self.running?(process_name, options = {})
      !pids(process_name, options).empty?
    end

    # Find processes with detailed info (PID and command)
    # Returns array of hashes with :pid and :command keys
    #
    # Example:
    #   ProcessHelper.find_detailed('dnsmasq')
    #   # => [{pid: 12345, command: '/opt/homebrew/sbin/dnsmasq'}]
    def self.find_detailed(process_name, options = {})
      flags = options[:full_match] ? '-fl' : '-l'
      result = Shell.run("pgrep #{flags} #{process_name}", raise_on_failure: false)
      return [] unless result[:success] && !result[:stdout].empty?

      result[:stdout].split("\n").map do |line|
        parts = line.strip.split(' ', 2)
        { pid: parts[0].to_i, command: parts[1] || process_name }
      end
    end
  end
end
