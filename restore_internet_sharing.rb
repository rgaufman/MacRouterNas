#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Internet Sharing Restoration Script for macOS
# ============================================
#
# This script quickly restores internet sharing configurations when they break.
# It performs key tasks to fix common issues with NAT and internet sharing:
#
# - Checks and enables IP forwarding
# - Verifies and restarts packet filtering (PF) with NAT rules
# - Ensures dnsmasq is running for DHCP services
# - Resets network interfaces with proper IP assignments
#
# Usage:
#   ./restore_internet_sharing.rb --wan-interface en0 --lan-interface en5

require_relative 'utils'
require 'optparse'
require 'open3'

# Main class for restoring internet sharing
class InternetSharingRestorer
  def initialize(options)
    @options = options
    @logger = MacRouterUtils.logger('InternetSharingRestorer')
    
    unless @options[:wan_interface] && @options[:lan_interface]
      @logger.fatal 'Both WAN and LAN interfaces are required'
      exit(1)
    end
    
    # Set default values
    @options[:static_ip] ||= '192.168.1.1'
    @options[:subnet] ||= '192.168.1.0/24'
  end
  
  def run
    @logger.info "Starting internet sharing restoration..."
    
    # Step 1: Check and enable IP forwarding
    restore_ip_forwarding
    
    # Step 2: Restart packet filtering with proper NAT rules
    restore_pf_rules
    
    # Step 3: Reset interface configuration
    restore_interface_configuration
    
    # Step 4: Restart DHCP server if needed
    restart_dhcp_if_needed
    
    @logger.info "Internet sharing restoration complete!"
  end
  
  private
  
  def restore_ip_forwarding
    @logger.info "Checking IP forwarding status..."
    
    # First check if it's already enabled
    result = execute_command_with_output("sysctl net.inet.ip.forwarding")
    if result[:success] && (result[:stdout].include?(": 1") || result[:stdout].include?("=1"))
      @logger.info "IP forwarding is already enabled"
      return
    end
    
    # Enable IP forwarding directly
    @logger.info "Enabling IP forwarding..."
    result = execute_command_with_output("sudo sysctl -w net.inet.ip.forwarding=1")
    
    if !result[:success]
      @logger.error "Failed to enable IP forwarding: #{result[:stderr]}"
      exit(1)
    end
    
    # Verify it was enabled
    result = execute_command_with_output("sysctl net.inet.ip.forwarding")
    if !result[:success] || (!result[:stdout].include?(": 1") && !result[:stdout].include?("=1"))
      @logger.error "IP forwarding could not be verified as enabled!"
      exit(1)
    end
    
    @logger.info "IP forwarding successfully enabled"
  end
  
  def restore_pf_rules
    @logger.info "Restoring PF NAT rules..."
    
    # Create a temporary rule file
    tmp_file = Tempfile.new(['nat_rule', '.conf'], '/tmp')
    tmp_path = tmp_file.path
    tmp_file.close
    
    begin
      # Create simple NAT rule
      nat_rule = "nat on #{@options[:wan_interface]} from #{@options[:subnet]} to any -> (#{@options[:wan_interface]})"
      File.write(tmp_path, nat_rule)
      
      # Make sure it's readable
      FileUtils.chmod(0600, tmp_path)
      
      # First check if PF is enabled, if not enable it
      pf_status = execute_command_with_output('sudo pfctl -s info')
      if !pf_status[:success] || !pf_status[:stdout].include?('Status: Enabled')
        @logger.info "Enabling PF..."
        execute_command_with_output("sudo pfctl -e")
      end
      
      # Flush NAT rules to start fresh
      @logger.info "Flushing existing NAT rules..."
      execute_command_with_output("sudo pfctl -F nat")
      
      # Load our NAT rule
      @logger.info "Loading NAT rule..."
      result = execute_command_with_output("sudo pfctl -f #{tmp_path}")
      
      if !result[:success] && !result[:stderr].include?('could result in flushing of rules')
        @logger.error "Failed to load NAT rule: #{result[:stderr]}"
        exit(1)
      end
      
      # Verify NAT configuration
      nat_check = execute_command_with_output("sudo pfctl -s nat")
      if !nat_check[:success] || !nat_check[:stdout].include?(@options[:wan_interface])
        @logger.error "Failed to verify NAT configuration"
        # Try loading NAT rules directly
        direct_result = execute_command_with_output("sudo pfctl -a 'com.apple/network' -f #{tmp_path}")
        if !direct_result[:success]
          @logger.error "Failed to load NAT rules directly: #{direct_result[:stderr]}"
          exit(1)
        end
      end
      
      @logger.info "PF NAT rules restored successfully"
    ensure
      # Clean up
      File.unlink(tmp_path) if File.exist?(tmp_path)
    end
  end
  
  def restore_interface_configuration
    @logger.info "Checking interface configuration..."
    
    # Check if LAN interface already has the static IP
    output = execute_command_with_output("ifconfig #{@options[:lan_interface]}")
    if output[:success] && output[:stdout].include?(@options[:static_ip])
      @logger.info "LAN interface #{@options[:lan_interface]} already has IP #{@options[:static_ip]}"
    else
      # Reset interface configuration
      @logger.info "Resetting interface #{@options[:lan_interface]} configuration..."
      execute_command_with_output("sudo ifconfig #{@options[:lan_interface]} down")
      execute_command_with_output("sudo ifconfig #{@options[:lan_interface]} up")
      
      # Assign static IP
      @logger.info "Assigning static IP #{@options[:static_ip]} to interface #{@options[:lan_interface]}..."
      result = execute_command_with_output("sudo ifconfig #{@options[:lan_interface]} inet #{@options[:static_ip]} netmask 255.255.255.0 up")
      
      if !result[:success]
        @logger.error "Failed to assign static IP: #{result[:stderr]}"
        exit(1)
      end
      
      # Verify IP was assigned
      verify = execute_command_with_output("ifconfig #{@options[:lan_interface]} | grep #{@options[:static_ip]}")
      if !verify[:success]
        @logger.error "Failed to verify static IP assignment"
        exit(1)
      end
    end
    
    @logger.info "Interface configuration restored successfully"
  end
  
  def restart_dhcp_if_needed
    # Check if DHCP is enabled
    if @options[:dhcp]
      @logger.info "Checking DHCP server status..."
      
      # Check if dnsmasq is running
      process_check = execute_command_with_output('pgrep -l dnsmasq')
      if process_check[:success]
        @logger.info "DNSMASQ is already running"
      else
        # Try to restart dnsmasq
        @logger.info "Restarting DNSMASQ..."
        result = execute_command_with_output('sudo brew services restart dnsmasq')
        
        if !result[:success]
          @logger.warn "Failed to restart DNSMASQ through Homebrew: #{result[:stderr]}"
          
          # Try to kill any existing processes and start manually
          execute_command_with_output('sudo pkill -f dnsmasq || true')
          manual_result = execute_command_with_output('sudo /opt/homebrew/sbin/dnsmasq --conf-file=/opt/homebrew/etc/dnsmasq.conf')
          
          if !manual_result[:success]
            @logger.error "Failed to start DNSMASQ manually: #{manual_result[:stderr]}"
            exit(1)
          end
        end
        
        # Verify it's running now
        sleep(1)
        verify = execute_command_with_output('pgrep -l dnsmasq')
        if !verify[:success]
          @logger.error "DNSMASQ failed to start"
          exit(1)
        end
        
        @logger.info "DNSMASQ restarted successfully"
      end
    else
      @logger.info "DHCP restoration skipped (not enabled)"
    end
  end
  
  def execute_command_with_output(command)
    stdout, stderr, status = Open3.capture3(command)
    { stdout: stdout.strip, stderr: stderr.strip, success: status.success? }
  end
end

# Parse command-line options
options = {
  dhcp: false
}

OptionParser.new do |opts|
  opts.banner = 'Usage: restore_internet_sharing.rb [options]'
  
  opts.on('--wan-interface NAME', 'WAN interface (e.g., en0)') { |v| options[:wan_interface] = v }
  opts.on('--lan-interface NAME', 'LAN interface (e.g., en5)') { |v| options[:lan_interface] = v }
  opts.on('--static-ip IP', 'Static IP for LAN interface (default: 192.168.1.1)') { |v| options[:static_ip] = v }
  opts.on('--subnet SUBNET', 'LAN subnet in CIDR notation (default: 192.168.1.0/24)') { |v| options[:subnet] = v }
  opts.on('--enable-dhcp', 'Restore DHCP server as well (uses dnsmasq)') { options[:dhcp] = true }
  opts.on('--verbose', 'Enable verbose output') { options[:verbose] = true }
  opts.on('-h', '--help', 'Display this help') do
    puts opts
    exit
  end
end.parse!

# Create and run the restorer
begin
  restorer = InternetSharingRestorer.new(options)
  restorer.run
rescue StandardError => e
  puts "Error: #{e.message}"
  puts e.backtrace if options[:verbose]
  exit(1)
end