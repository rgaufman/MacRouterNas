#!/usr/bin/env ruby
# frozen_string_literal: true

# Network utilities for MacRouter
# Provides functionality for network interface operations

require 'semantic_logger'

module MacRouterUtils
  module NetworkUtils
    extend SemanticLogger::Loggable

    # List usable network interfaces, filtering out virtual and unusable ones
    def self.list_usable_interfaces
      interfaces = {}

      # Get the output of ifconfig
      output = `ifconfig`

      # Parse the output to extract interface information
      current_interface = nil
      output.each_line do |line|
        if line =~ /^([a-zA-Z0-9]+):/
          current_interface = ::Regexp.last_match(1)
          interfaces[current_interface] = { status: 'unknown', type: 'unknown', has_ip: false }
        elsif current_interface && line.include?('status:')
          interfaces[current_interface][:status] = begin
            line.match(/status: (\w+)/)[1]
          rescue StandardError
            'unknown'
          end
        elsif current_interface && line.include?('media:')
          interfaces[current_interface][:type] = line.strip
        elsif current_interface && line.include?('inet ')
          interfaces[current_interface][:has_ip] = true
          interfaces[current_interface][:ip] = begin
            line.match(/inet (\d+\.\d+\.\d+\.\d+)/)[1]
          rescue StandardError
            'unknown'
          end
        end
      end

      # Filter out virtual and unusable interfaces
      interfaces.select do |name, _info|
        # Skip loopback, virtual, and special interfaces
        next false if name == 'lo0' # Loopback
        next false if name =~ /^(gif|stf|pktap|vmenet)/ # Virtual interfaces
        next false if name =~ /^utun/                   # Tunnel interfaces
        next false if name =~ /^bridge/                 # Bridge interfaces
        next false if name =~ /^awdl/                   # Apple Wireless Direct Link
        next false if name =~ /^llw/                    # Low Latency WLAN

        # Keep interfaces that are physical (en*, anpi*)
        true
      end
    end

    # Display usable interfaces in a formatted way
    def self.display_usable_interfaces
      interfaces = list_usable_interfaces

      puts "\nUsable Network Interfaces:"
      puts '============================'

      if interfaces.empty?
        puts 'No usable interfaces found.'
        return
      end

      # Find the longest interface name for formatting
      max_name_length = interfaces.keys.map(&:length).max

      # Sort interfaces by name
      interfaces.sort.each do |name, info|
        status_indicator = info[:status] == 'active' ? '✅' : '❌'
        ip_info = info[:has_ip] ? " (#{info[:ip]})" : ''
        puts "#{status_indicator} #{name.ljust(max_name_length)} - #{info[:status]}#{ip_info}"
      end

      puts "\n✅ = active, ❌ = inactive"
    end
  end
end
