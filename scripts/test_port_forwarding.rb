#!/usr/bin/env ruby
# frozen_string_literal: true

# Test script for port forwarding implementation without anchors
# This script tests the direct approach to port forwarding

require 'tempfile'
require 'fileutils'
require 'open3'

def execute_command_with_output(command)
  stdout, stderr, status = Open3.capture3(command)
  { stdout: stdout.strip, stderr: stderr.strip, success: status.success? }
end

# Configuration
wan_interface = 'ppp0' # Replace with your WAN interface
port_forwards = [
  { 'external_port' => 8080, 'internal_ip' => '192.168.1.10', 'internal_port' => 80, 'protocol' => 'tcp' }
  # Add more test rules as needed
]

puts "Testing port forwarding implementation without anchors"

# Step 1: Get current NAT rules
puts "\nStep 1: Getting current NAT rules..."
nat_output = execute_command_with_output('sudo pfctl -s nat')
if nat_output[:success]
  puts "Current NAT rules:"
  puts nat_output[:stdout].empty? ? "  (No NAT rules found)" : nat_output[:stdout]
else
  puts "Error getting NAT rules: #{nat_output[:stderr]}"
  exit 1
end

# Step 2: Create a combined rule file with NAT and port forwarding
puts "\nStep 2: Creating combined rule file..."

# Create the port forwarding rules
rules_content = "# Port forwarding rules\n"
port_forwards.each do |rule|
  rules_content += "rdr on #{wan_interface} proto #{rule['protocol']} from any to any port #{rule['external_port']} -> #{rule['internal_ip']} port #{rule['internal_port']}\n"
end

# Combine with NAT rules if they exist
if !nat_output[:stdout].empty?
  combined_rules = nat_output[:stdout] + "\n\n" + rules_content
else
  # Create a basic NAT rule if none exists
  combined_rules = "# NAT rule\nnat on #{wan_interface} from 192.168.1.0/24 to any -> (#{wan_interface})\n\n" + rules_content
end

# Write to a temporary file
begin
  tmp_file = Tempfile.new(['combined_rules', '.conf'], '/tmp')
  tmp_path = tmp_file.path
  tmp_file.close
  
  File.write(tmp_path, combined_rules)
  FileUtils.chmod(0600, tmp_path)
  
  puts "Combined rules file created at #{tmp_path}:"
  puts File.read(tmp_path)
  
  # Step 3: Load the combined rules
  puts "\nStep 3: Loading combined rules..."
  load_result = execute_command_with_output("sudo pfctl -f #{tmp_path}")
  
  if load_result[:success]
    puts "Successfully loaded combined rules"
  else
    # Note: pfctl might return warnings about flushing rules but still work
    if load_result[:stderr].include?('could result in flushing of rules')
      puts "Warning: #{load_result[:stderr]}"
      puts "This warning is expected and the rules may still have been applied"
    else
      puts "Error loading rules: #{load_result[:stderr]}"
      exit 1
    end
  end
  
  # Step 4: Verify the rules are loaded
  puts "\nStep 4: Verifying rules are loaded..."
  verify_nat = execute_command_with_output('sudo pfctl -s nat')
  verify_rdr = execute_command_with_output('sudo pfctl -s rdr')
  
  puts "NAT rules loaded:"
  puts verify_nat[:stdout]
  
  puts "\nPort forwarding (rdr) rules loaded:"
  puts verify_rdr[:stdout]
  
  puts "\nTest completed. Check the output above to confirm rules were properly loaded."
  
rescue StandardError => e
  puts "Error: #{e.message}"
  exit 1
ensure
  # Clean up temporary file
  File.unlink(tmp_path) if tmp_path && File.exist?(tmp_path)
end