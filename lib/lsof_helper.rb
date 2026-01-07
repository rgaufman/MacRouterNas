#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'shell'

module MacRouterUtils
  # Helper for lsof operations (port and file descriptor inspection)
  # Provides clean API for checking port usage without shell pipes
  class LsofHelper
    # Check what process is using a specific port
    # Returns hash with :process, :pid, :user keys or nil if port is not in use
    #
    # Example:
    #   LsofHelper.port_info(67)
    #   # => { process: 'dnsmasq', pid: 12345, user: 'root' }
    def self.port_info(port)
      result = Shell.run("sudo lsof -i :#{port}", raise_on_failure: false)
      return nil unless result[:success] && !result[:stdout].empty?

      # Parse first non-header line
      lines = result[:stdout].split("\n")
      return nil if lines.length < 2

      # lsof output format:
      # COMMAND    PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
      # dnsmasq  12345  root    4u  IPv4 0x123456      0t0  UDP *:bootps
      parts = lines[1].split
      return nil if parts.length < 3

      {
        process: parts[0],
        pid: parts[1].to_i,
        user: parts[2]
      }
    end

    # Check if a specific process is using a specific port
    # Returns boolean
    #
    # Example:
    #   LsofHelper.port_used_by?(67, 'dnsmasq')  # => true
    def self.port_used_by?(port, process_name)
      info = port_info(port)
      return false if info.nil?

      info[:process] == process_name
    end

    # Check if a port is in use (by any process)
    # Returns boolean
    #
    # Example:
    #   LsofHelper.port_in_use?(67)  # => true
    def self.port_in_use?(port)
      !port_info(port).nil?
    end

    # Get all processes using a specific port
    # Returns array of hashes with :process, :pid, :user keys
    #
    # Example:
    #   LsofHelper.port_processes(67)
    #   # => [{ process: 'dnsmasq', pid: 12345, user: 'root' }]
    def self.port_processes(port)
      result = Shell.run("sudo lsof -i :#{port}", raise_on_failure: false)
      return [] unless result[:success] && !result[:stdout].empty?

      # Parse all non-header lines
      lines = result[:stdout].split("\n")
      return [] if lines.length < 2

      lines[1..].map do |line|
        parts = line.split
        next nil if parts.length < 3

        {
          process: parts[0],
          pid: parts[1].to_i,
          user: parts[2]
        }
      end.compact
    end
  end
end
