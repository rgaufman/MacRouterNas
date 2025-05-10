#!/usr/bin/env ruby
# frozen_string_literal: true

# Diagnostic script to investigate DNSMASQ conflicts

require 'open3'
require 'logger'

def execute_command_with_output(command)
  stdout, stderr, status = Open3.capture3(command)
  { stdout: stdout.strip, stderr: stderr.strip, success: status.success? }
end

logger = Logger.new(STDOUT)
logger.level = Logger::INFO
logger.formatter = proc do |severity, datetime, progname, msg|
  "#{severity}: #{msg}\n"
end

puts "=== DNSMASQ Process Diagnostic ==="
puts "This script will help investigate DNSMASQ conflicts and process detection"
puts "=" * 40

# Part 1: Check if dnsmasq is running
puts "\n1. Checking if dnsmasq process is running:"
process_check = execute_command_with_output('pgrep -l dnsmasq')
puts "Command: pgrep -l dnsmasq"
puts "Exit status: #{process_check[:success] ? 'Success' : 'Failed'}"
puts "stdout: [#{process_check[:stdout]}]"
puts "stderr: [#{process_check[:stderr]}]"

# Format for humans to understand
if process_check[:success] && !process_check[:stdout].empty?
  puts "\n✅ DNSMASQ process IS running."
  puts "PIDs and process names: #{process_check[:stdout]}"
else
  puts "\n❌ DNSMASQ process is NOT running."
end

# Part 2: More detailed process listing
puts "\n\n2. More detailed process listing:"
more_detailed_process = execute_command_with_output('ps aux | grep dnsmasq | grep -v grep')
puts "Command: ps aux | grep dnsmasq | grep -v grep"
puts "Exit status: #{more_detailed_process[:success] ? 'Success' : 'Failed'}"
puts "stdout length: #{more_detailed_process[:stdout].length} characters"
puts "stdout: [#{more_detailed_process[:stdout]}]"
puts "stderr: [#{more_detailed_process[:stderr]}]"

# Part 3: Check port 67 usage
puts "\n\n3. Checking port 67 (DHCP) usage:"
port_check = execute_command_with_output('sudo lsof -i :67')
puts "Command: sudo lsof -i :67"
puts "Exit status: #{port_check[:success] ? 'Success' : 'Failed'}"
puts "stdout: [#{port_check[:stdout]}]"
puts "stderr: [#{port_check[:stderr]}]"

# Extract process information if something's using port 67
if port_check[:success] && !port_check[:stdout].empty?
  puts "\n✅ Something IS using port 67 (DHCP port)."

  # Parse the output to extract information
  lines = port_check[:stdout].split("\n")
  if lines.length > 1
    # Skip header line and print process details
    puts "\nProcess details from lsof -i :67:"
    puts "-" * 40
    lines.each_with_index do |line, index|
      puts "Line #{index}: #{line}"
      if index > 0 # Skip header
        columns = line.split
        if columns.length >= 1
          puts "  - Process name: #{columns[0]}"
        end
        if columns.length >= 2
          puts "  - PID: #{columns[1]}"
        end
        if columns.length >= 8
          puts "  - Protocol: #{columns[7]}"
        end
        if columns.length >= 9
          puts "  - Address:Port: #{columns[8]}"
        end
      end
    end
  end
else
  puts "\n❌ Nothing is using port 67 (DHCP port)."
end

# Part 4: Check service registration via brew
puts "\n\n4. Checking Homebrew services for dnsmasq:"
brew_services = execute_command_with_output('brew services list | grep dnsmasq')
puts "Command: brew services list | grep dnsmasq"
puts "Exit status: #{brew_services[:success] ? 'Success' : 'Failed'}"
puts "stdout: [#{brew_services[:stdout]}]"
puts "stderr: [#{brew_services[:stderr]}]"

if brew_services[:success] && !brew_services[:stdout].empty?
  puts "\nBreakdown of Homebrew service status:"
  service_info = brew_services[:stdout].strip
  if service_info.include?('started')
    puts "✅ Homebrew service shows dnsmasq as STARTED"
  elsif service_info.include?('stopped')
    puts "❌ Homebrew service shows dnsmasq as STOPPED"
  elsif service_info.include?('error')
    puts "⚠️ Homebrew service shows dnsmasq in ERROR state"
  else
    puts "Status unclear: #{service_info}"
  end
else
  puts "\n❌ No dnsmasq service registered with Homebrew."
end

# Part 5: Check for any launchd service for dnsmasq
puts "\n\n5. Checking LaunchDaemons for dnsmasq:"
launchd_check = execute_command_with_output('sudo launchctl list | grep dnsmasq')
puts "Command: sudo launchctl list | grep dnsmasq"
puts "Exit status: #{launchd_check[:success] ? 'Success' : 'Failed'}"
puts "stdout: [#{launchd_check[:stdout]}]"
puts "stderr: [#{launchd_check[:stderr]}]"

# Check the specific custom launchd service
custom_service = execute_command_with_output('sudo launchctl list | grep custom.dnsmasq')
puts "\nCommand: sudo launchctl list | grep custom.dnsmasq"
puts "Exit status: #{custom_service[:success] ? 'Success' : 'Failed'}"
puts "stdout: [#{custom_service[:stdout]}]"
puts "stderr: [#{custom_service[:stderr]}]"

# Part 6: Check LaunchDaemon files
puts "\n\n6. Checking LaunchDaemon files:"
launchdaemon_check = execute_command_with_output('ls -la /Library/LaunchDaemons/*dnsmasq*')
puts "Command: ls -la /Library/LaunchDaemons/*dnsmasq*"
puts "Exit status: #{launchdaemon_check[:success] ? 'Success' : 'Failed'}"
puts "stdout: [#{launchdaemon_check[:stdout]}]"
puts "stderr: [#{launchdaemon_check[:stderr]}]"

# Part 7: Check config file
puts "\n\n7. Checking configuration file:"
config_path = '/opt/homebrew/etc/dnsmasq.conf'
if File.exist?(config_path)
  puts "✅ Configuration file exists at #{config_path}"
  
  # Get file permissions
  file_perms = execute_command_with_output("ls -la #{config_path}")
  puts "File permissions: #{file_perms[:stdout]}"
  
  # Get non-comment lines from config
  config_content = execute_command_with_output("grep -v '^#' #{config_path} | grep -v '^$'")
  puts "\nActive configuration (excluding comments and empty lines):"
  puts config_content[:stdout]
else
  puts "❌ Configuration file does not exist at #{config_path}"
end

# Summary
puts "\n\n=== SUMMARY ==="
dnsmasq_running = process_check[:success] && !process_check[:stdout].empty?
port_in_use = port_check[:success] && !port_check[:stdout].empty?
is_our_dnsmasq = port_in_use && port_check[:stdout].include?('dnsmasq')
other_process = port_in_use && !port_check[:stdout].include?('dnsmasq')

puts "DNSMASQ Process: #{dnsmasq_running ? '✅ Running' : '❌ Not running'}"
puts "DHCP Port (67): #{port_in_use ? '✅ In use' : '❌ Not in use'}" 
if port_in_use
  puts "Port 67 used by: #{is_our_dnsmasq ? 'dnsmasq' : 'another process (conflict)'}"
end

puts "\nRecommendation:"
if dnsmasq_running && is_our_dnsmasq
  puts "✅ DNSMASQ is running correctly and handling DHCP"
elsif dnsmasq_running && !port_in_use
  puts "⚠️ DNSMASQ is running but not listening on DHCP port 67 (configuration issue)"
elsif !dnsmasq_running && other_process
  puts "❌ CONFLICT: DNSMASQ is not running because port 67 is in use by another process"
  process_name = port_check[:stdout].split("\n").length > 1 ? port_check[:stdout].split("\n")[1].split[0] : "unknown"
  puts "   The conflicting process appears to be: #{process_name}"
elsif !dnsmasq_running && !port_in_use
  puts "❌ DNSMASQ is not running and DHCP port 67 is free (service not started)"
else
  puts "⚠️ Unclear state - check the detailed output above"
end