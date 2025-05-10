#!/usr/bin/env ruby
# frozen_string_literal: true

# RSpec tests for DNSMasqManager focusing on process detection and port conflicts

require_relative '../utils/dnsmasq_manager'
require 'rspec'

describe MacRouterUtils::DNSMasqManager do
  let(:lan_interface) { 'en8' }
  let(:static_ip) { '192.168.1.1' }
  let(:dhcp_range) { '192.168.1.11,192.168.1.249,4h' }
  let(:domain) { 'local' }
  let(:dns) { '1.1.1.1' }
  let(:dnsmasq_manager) { described_class.new(lan_interface, static_ip, dhcp_range, domain, dns) }

  describe '#verify_running' do
    context 'when DNSMASQ is running and using port 67' do
      before do
        # Mock the process check to show DNSMASQ is running
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('pgrep -l dnsmasq').and_return({
          success: true,
          stdout: "3846 dnsmasq",
          stderr: ""
        })
        
        # Mock the port check to show DNSMASQ is using port 67
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('sudo lsof -i :67').and_return({
          success: true,
          stdout: "COMMAND  PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\ndnsmasq 3846 root    4u  IPv4 0x135b74af9c302b51      0t0  UDP *:bootps",
          stderr: ""
        })
      end
      
      it 'returns true indicating DNSMASQ is running' do
        expect(dnsmasq_manager.verify_running).to be true
      end
    end
    
    context 'when DNSMASQ process exists but not using port 67' do
      before do
        # Mock the process check to show DNSMASQ is running
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('pgrep -l dnsmasq').and_return({
          success: true,
          stdout: "3846 dnsmasq",
          stderr: ""
        })
        
        # Mock the port check to show no process is using port 67
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('sudo lsof -i :67').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
      end
      
      it 'returns true because the DNSMASQ process exists' do
        expect(dnsmasq_manager.verify_running).to be true
      end
    end
    
    context 'when another process is using port 67' do
      before do
        # Mock the process check to show DNSMASQ is not running
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('pgrep -l dnsmasq').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
        
        # Mock the port check to show another process (bootpd) is using port 67
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('sudo lsof -i :67').and_return({
          success: true,
          stdout: "COMMAND  PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\nbootpd 3846 root    4u  IPv4 0x135b74af9c302b51      0t0  UDP *:bootps",
          stderr: ""
        })

        # Mock additional service checks
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('ps aux | grep dnsmasq | grep -v grep').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('sudo brew services list | grep dnsmasq').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('sudo launchctl list | grep custom.dnsmasq').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('ls -la /Library/LaunchDaemons/*dnsmasq*').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
      end
      
      it 'returns false because DNSMASQ is not running' do
        expect(dnsmasq_manager.verify_running).to be false
      end
    end
    
    context 'when no process is running on port 67' do
      before do
        # Mock the process check to show DNSMASQ is not running
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('pgrep -l dnsmasq').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
        
        # Mock the port check to show no process is using port 67
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('sudo lsof -i :67').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })

        # Mock additional service checks
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('ps aux | grep dnsmasq | grep -v grep').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('sudo brew services list | grep dnsmasq').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('sudo launchctl list | grep custom.dnsmasq').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
        allow(dnsmasq_manager).to receive(:execute_command_with_output).with('ls -la /Library/LaunchDaemons/*dnsmasq*').and_return({
          success: false,
          stdout: "",
          stderr: ""
        })
      end
      
      it 'returns false because DNSMASQ is not running' do
        expect(dnsmasq_manager.verify_running).to be false
      end
    end
  end

  describe '#configure' do
    context 'when DNSMASQ is already running with current config' do
      before do
        # Mock verify_running to return true
        allow(dnsmasq_manager).to receive(:verify_running).and_return(true)
        
        # Mock config_changed? to return false (config hasn't changed)
        allow(dnsmasq_manager).to receive(:config_changed?).and_return(false)
        
        # Mock other required setup methods
        allow(FileUtils).to receive(:mkdir_p)
        allow(dnsmasq_manager).to receive(:execute_command_with_output).and_return({
          success: true,
          stdout: "",
          stderr: ""
        })
        
        # Mock internet_sharing_enabled? to return false
        allow(dnsmasq_manager).to receive(:internet_sharing_enabled?).and_return(false)
      end
      
      it 'returns early without restarting DNSMASQ' do
        # The test passes if the method doesn't raise an error and doesn't try to restart
        expect(dnsmasq_manager).not_to receive(:execute_command).with('sudo brew services restart dnsmasq', anything)
        dnsmasq_manager.configure
      end
    end
    
    context 'when DNSMASQ is running but config has changed' do
      before do
        # Mock verify_running to return true
        allow(dnsmasq_manager).to receive(:verify_running).and_return(true)
        
        # Mock config_changed? to return true (config has changed)
        allow(dnsmasq_manager).to receive(:config_changed?).and_return(true)
        
        # Mock other required setup methods
        allow(FileUtils).to receive(:mkdir_p)
        allow(dnsmasq_manager).to receive(:execute_command_with_output).and_return({
          success: true,
          stdout: "",
          stderr: ""
        })
        
        # Mock internet_sharing_enabled? to return false
        allow(dnsmasq_manager).to receive(:internet_sharing_enabled?).and_return(false)
        
        # Mock additional required methods for this test
        allow(dnsmasq_manager).to receive(:process_static_mappings)
        allow(dnsmasq_manager).to receive(:generate_config).and_return("mock_config")
        allow(File).to receive(:write)
        allow(dnsmasq_manager).to receive(:execute_command)
      end
      
      it 'restarts DNSMASQ with the new config' do
        expect(dnsmasq_manager).to receive(:execute_command).with('sudo brew services restart dnsmasq', anything)
        dnsmasq_manager.configure
      end
    end
    
    context 'when another process is using port 67' do
      it 'raises an error about the port conflict' do
        # Just directly mock the internet_sharing_enabled? method for the simplest test
        allow(dnsmasq_manager).to receive(:internet_sharing_enabled?).and_return(true)
        
        # Also need to mock ensure_dnsmasq_installed to avoid actual command executions
        allow(dnsmasq_manager).to receive(:ensure_dnsmasq_installed)
        
        # Configure will detect the Internet Sharing active and raise an error
        expect { dnsmasq_manager.configure }.to raise_error(/Internet Sharing is enabled and will conflict/)
      end
    end
  end
end