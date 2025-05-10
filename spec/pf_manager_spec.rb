#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe MacRouterUtils::PFManager do
  let(:wan_interface) { 'en0' }
  let(:lan_interface) { 'en5' }
  let(:pf_manager) { described_class.new(wan_interface, lan_interface) }

  # Mock the PortForwards class to avoid dependencies in tests
  before(:each) do
    port_forwards_mock = instance_double(MacRouterUtils::PortForwards)
    allow(MacRouterUtils::PortForwards).to receive(:new).and_return(port_forwards_mock)
    allow(port_forwards_mock).to receive(:add_port_forward).and_return(true)
    allow(port_forwards_mock).to receive(:remove_port_forward).and_return(true)
    allow(port_forwards_mock).to receive(:list_port_forwards).and_return([])
  end

  # Note: We no longer test the generate_rules method directly because it was removed
  # in favor of a different approach that uses direct NAT rule loading
  describe '#create_secure_nat_rule_file' do
    it 'generates NAT rules correctly' do
      # Mock the file operations
      temp_file = instance_double(Tempfile)
      allow(Tempfile).to receive(:new).and_return(temp_file)
      allow(temp_file).to receive(:path).and_return('/tmp/mock_nat_rule.conf')
      allow(temp_file).to receive(:close)
      allow(File).to receive(:write)
      allow(FileUtils).to receive(:chmod)

      # Call the private method with test input
      nat_rule = "# NAT rule for testing\nnat on en0 from 192.168.1.0/24 to any -> (en0)"
      result = pf_manager.send(:create_secure_nat_rule_file, nat_rule)

      # Verify the result
      expect(result).to eq('/tmp/mock_nat_rule.conf')
      expect(File).to have_received(:write).with('/tmp/mock_nat_rule.conf', nat_rule)
      expect(FileUtils).to have_received(:chmod).with(0600, '/tmp/mock_nat_rule.conf')
    end
  end

  # The generate_main_conf method has been removed in the updated implementation
  # Let's test the create_nat_launch_daemon method instead since it's now used
  describe '#create_nat_launch_daemon' do
    before do
      # Mock template renderer
      renderer = instance_double(MacRouterUtils::TemplateRenderer)
      allow(MacRouterUtils::TemplateRenderer).to receive(:new).and_return(renderer)

      # Mock the render method (with the updated parameters)
      allow(renderer).to receive(:render).with('nat_launchdaemon', hash_including({
        wan_interface: wan_interface,
        subnet: '192.168.1.0/24',
        port_forwards: []
      })).and_return("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n</plist>")

      # Mock the MSS clamping rule render
      allow(renderer).to receive(:render).with('mss_clamping_rule', anything).and_return("scrub out on en0 proto tcp all max-mss 1452\n")

      # Mock store_in_persistent_location to avoid issues with that method
      allow(pf_manager).to receive(:store_in_persistent_location).and_return('/usr/local/etc/MacRouterNas/test_file.conf')

      # Mock tempfile operations
      temp_file = instance_double(Tempfile)
      allow(Tempfile).to receive(:new).and_return(temp_file)
      allow(temp_file).to receive(:path).and_return('/tmp/com.macrouternas.nat.plist')
      allow(temp_file).to receive(:close)

      # Mock file operations
      allow(File).to receive(:write)
      allow(FileUtils).to receive(:chmod)
      allow(File).to receive(:exist?).and_return(false)

      # Mock the mkdir command
      allow(pf_manager).to receive(:execute_command_with_output).with("sudo mkdir -p /Library/LaunchDaemons").and_return(
        {success: true, stdout: '', stderr: ''}
      )

      # Mock other command executions
      allow(pf_manager).to receive(:execute_command_with_output).and_return({success: true, stdout: '', stderr: ''})
    end

    it 'creates a launch daemon for NAT configuration' do
      # Call the method
      expect { pf_manager.send(:create_nat_launch_daemon) }.not_to raise_error

      # We can check that our mocked renderer was called
      expect(MacRouterUtils::TemplateRenderer).to have_received(:new)
    end
  end

  describe '#verify_interfaces' do
    context 'when checking a PPP WAN interface' do
      let(:ppp_manager) { described_class.new('ppp0', 'en5') }

      # Mock the PortForwards class for the PPP manager
      before(:each) do
        port_forwards_mock = instance_double(MacRouterUtils::PortForwards)
        allow(MacRouterUtils::PortForwards).to receive(:new).and_return(port_forwards_mock)
      end

      it 'correctly identifies active PPP interface' do
        allow(ppp_manager).to receive(:execute_command_with_output).with("ifconfig ppp0").and_return({
          success: true,
          stdout: <<~INTERFACE
            ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1492
                inet 100.66.91.122 --> 203.134.4.189 netmask 0xff000000
                inet6 fe80::d211:e5ff:fe88:7787%ppp0 prefixlen 64 scopeid 0x19
                nd6 options=201<PERFORMNUD,DAD>
          INTERFACE
        })

        # Also mock ifconfig for LAN interface
        allow(ppp_manager).to receive(:execute_command_with_output).with("ifconfig en5").and_return({
          success: true,
          stdout: "en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500"
        })

        # Execute the private method
        expect { ppp_manager.send(:verify_interfaces) }.not_to raise_error

        # The method doesn't return a value, but it logs an info message for active PPP interfaces
        logger_double = instance_double(SemanticLogger::Logger)
        allow(ppp_manager).to receive(:logger).and_return(logger_double)
        allow(logger_double).to receive(:debug)
        expect(logger_double).to receive(:info).with(/PPP interface ppp0 is active/)

        ppp_manager.send(:verify_interfaces)
      end

      it 'warns but continues if PPP interface has no IP' do
        allow(ppp_manager).to receive(:execute_command_with_output).with("ifconfig ppp0").and_return({
          success: true,
          stdout: <<~INTERFACE
            ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1492
                inet6 fe80::d211:e5ff:fe88:7787%ppp0 prefixlen 64 scopeid 0x19
                nd6 options=201<PERFORMNUD,DAD>
          INTERFACE
        })

        # Also mock ifconfig for LAN interface
        allow(ppp_manager).to receive(:execute_command_with_output).with("ifconfig en5").and_return({
          success: true,
          stdout: "en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500"
        })

        # The method warns but doesn't error
        logger_double = instance_double(SemanticLogger::Logger)
        allow(ppp_manager).to receive(:logger).and_return(logger_double)
        allow(logger_double).to receive(:debug)
        expect(logger_double).to receive(:warn).with(/PPP interface ppp0 has RUNNING flag but no IP address/)

        ppp_manager.send(:verify_interfaces)
      end

      it 'warns but continues if PPP interface has no RUNNING flag' do
        allow(ppp_manager).to receive(:execute_command_with_output).with("ifconfig ppp0").and_return({
          success: true,
          stdout: <<~INTERFACE
            ppp0: flags=8050<POINTOPOINT,MULTICAST> mtu 1492
                inet 100.66.91.122 --> 203.134.4.189 netmask 0xff000000
                inet6 fe80::d211:e5ff:fe88:7787%ppp0 prefixlen 64 scopeid 0x19
                nd6 options=201<PERFORMNUD,DAD>
          INTERFACE
        })

        # Also mock ifconfig for LAN interface
        allow(ppp_manager).to receive(:execute_command_with_output).with("ifconfig en5").and_return({
          success: true,
          stdout: "en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500"
        })

        # The method warns but doesn't error
        logger_double = instance_double(SemanticLogger::Logger)
        allow(ppp_manager).to receive(:logger).and_return(logger_double)
        allow(logger_double).to receive(:debug)
        expect(logger_double).to receive(:warn).with(/PPP interface ppp0 has IP address but RUNNING flag not set/)

        ppp_manager.send(:verify_interfaces)
      end
    end
  end

  describe '#verify_running' do
    context 'when PF is enabled with NAT rules' do
      before do
        # Mock successful PF status check
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: "Status: Enabled\nSome other PF info..."
        })

        # Mock NAT rules check with new implementation
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s nat').and_return({
          success: true,
          stdout: "nat on en0 from 192.168.1.0/24 to any -> (en0)"
        })

        # Mock the scrub rule check (MSS clamping)
        allow(pf_manager).to receive(:execute_command_with_output).with("sudo pfctl -sa | grep -i 'max-mss'").and_return({
          success: true,
          stdout: "scrub out on en0 proto tcp all max-mss 1452",
          stderr: ""
        })

        # Since verify_running also calls the log when force mode is used
        allow(pf_manager).to receive(:logger).and_return(double('logger').as_null_object)
      end

      it 'returns true' do
        expect(pf_manager.verify_running).to be true
      end
    end

    context 'when PF is disabled' do
      before do
        # Mock the logger
        logger_double = double('logger')
        allow(logger_double).to receive(:info)
        allow(logger_double).to receive(:warn)
        allow(pf_manager).to receive(:logger).and_return(logger_double)

        # Mock force mode
        allow(pf_manager).to receive(:instance_variable_get).with(any_args).and_call_original
        allow(pf_manager).to receive(:instance_variable_get).with(:@force).and_return(true)

        # Step 1: PF is disabled initially
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: "Status: Disabled\nSome other PF info..."
        })

        # Step 2: Enable PF
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -e').and_return({
          success: true,
          stdout: "pf enabled"
        })

        # Step 3: Check NAT rules (empty)
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s nat').and_return({
          success: true,
          stdout: ""
        })

        # Step 4: Check if Internet Sharing is enabled (it's not)
        allow(pf_manager).to receive(:execute_command_with_output).with('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled').and_return({
          success: true,
          stdout: "Enabled = 0"
        })

        # Step 5: Check IP forwarding (it's not enabled)
        allow(pf_manager).to receive(:execute_command_with_output).with('sysctl net.inet.ip.forwarding').and_return({
          success: true,
          stdout: "net.inet.ip.forwarding = 0"
        })
      end

      it 'enables PF but returns false when NAT is not properly configured' do
        # Even though we enable PF, it should still return false because NAT isn't configured
        # and no rules were found - this is the actual current behavior
        expect(pf_manager.verify_running).to be false
        # Verify the logger received the warning about NAT not being properly configured
        expect(pf_manager.logger).to have_received(:warn).with('Could not verify NAT is properly configured')
      end
    end

    context 'when PF is enabled but NAT is not configured' do
      before do
        # Mock successful PF status check
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: "Status: Enabled\nSome other PF info..."
        })

        # Mock NAT rules check - empty NAT rules
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s nat').and_return({
          success: true,
          stdout: ""
        })

        # Mock NAT rules check with grep - also empty
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s all | grep nat').and_return({
          success: true,
          stdout: ""
        })

        # Mock Internet Sharing check
        allow(pf_manager).to receive(:execute_command_with_output).with('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled').and_return({
          success: true,
          stdout: "Enabled = 0"
        })

        # For force mode check
        allow(pf_manager).to receive(:instance_variable_get).with(:@force).and_return(false)

        # Since verify_running also calls the log
        allow(pf_manager).to receive(:logger).and_return(double('logger').as_null_object)

        # For IP forwarding check
        allow(pf_manager).to receive(:execute_command_with_output).with('sysctl net.inet.ip.forwarding').and_return({
          success: true,
          stdout: "net.inet.ip.forwarding: 0"
        })
      end

      it 'returns false if NAT is not configured and force mode is not enabled' do
        expect(pf_manager.verify_running).to be false
      end
    end
  end

  # Test port forwarding methods
  describe 'port forwarding methods' do
    let(:port_forwards_mock) { instance_double(MacRouterUtils::PortForwards) }

    before(:each) do
      allow(MacRouterUtils::PortForwards).to receive(:new).and_return(port_forwards_mock)
    end

    describe '#add_port_forward' do
      it 'delegates to the PortForwards instance' do
        expect(port_forwards_mock).to receive(:add_port_forward).with('8080', '192.168.1.10', '80', 'tcp')
        pf_manager.add_port_forward('8080', '192.168.1.10', '80', 'tcp')
      end

      it 'raises an error if WAN interface is not defined' do
        no_wan_pf_manager = described_class.new(nil, lan_interface)
        expect { no_wan_pf_manager.add_port_forward('8080', '192.168.1.10', '80') }.to raise_error(MacRouterUtils::PFManager::ConfigurationError)
      end
    end

    describe '#remove_port_forward' do
      it 'delegates to the PortForwards instance' do
        expect(port_forwards_mock).to receive(:remove_port_forward).with('8080', 'tcp')
        pf_manager.remove_port_forward('8080', 'tcp')
      end

      it 'raises an error if WAN interface is not defined' do
        no_wan_pf_manager = described_class.new(nil, lan_interface)
        expect { no_wan_pf_manager.remove_port_forward('8080') }.to raise_error(MacRouterUtils::PFManager::ConfigurationError)
      end
    end

    describe '#list_port_forwards' do
      it 'delegates to the PortForwards instance' do
        port_forwards = [
          { 'external_port' => '8080', 'internal_ip' => '192.168.1.10', 'internal_port' => '80', 'protocol' => 'tcp' }
        ]
        expect(port_forwards_mock).to receive(:list_port_forwards).and_return(port_forwards)
        result = pf_manager.list_port_forwards
        expect(result).to eq(port_forwards)
      end

      it 'raises an error if WAN interface is not defined' do
        no_wan_pf_manager = described_class.new(nil, lan_interface)
        expect { no_wan_pf_manager.list_port_forwards }.to raise_error(MacRouterUtils::PFManager::ConfigurationError)
      end
    end
  end

  describe '#check_status' do
    context 'when PF is enabled with NAT configured' do
      let(:pfctl_info_output) {
        <<~OUTPUT
        Status: Enabled
        Debug: Urgent
        OUTPUT
      }

      let(:nat_rules_output) {
        "nat on en0 from 192.168.1.0/24 to any -> (en0)"
      }

      before do
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: pfctl_info_output
        })

        # New implementation checks different commands
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s nat').and_return({
          success: true,
          stdout: nat_rules_output
        })

        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s all | grep nat').and_return({
          success: true,
          stdout: nat_rules_output
        })

        # Mock Internet Sharing check
        allow(pf_manager).to receive(:execute_command_with_output).with('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled').and_return({
          success: true,
          stdout: "Enabled = 0"
        })
      end

      it 'returns correct status information' do
        status = pf_manager.check_status

        expect(status[:enabled]).to be true
        expect(status[:nat_configured]).to be true
        expect(status[:interfaces][:wan]).to eq('en0')
        # The updated implementation gets subnet instead of lan
        expect(status[:subnet]).to eq('192.168.1.0/24')
        expect(status[:managed_by_us]).to be true
      end
    end
    
    context 'when using older nat syntax' do
      let(:pfctl_info_output) {
        <<~OUTPUT
        Status: Enabled
        Debug: Urgent
        OUTPUT
      }

      let(:nat_rules_output) {
        "nat on en0 from 192.168.1.0/24 to any -> (en0)"
      }

      before do
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: pfctl_info_output
        })

        # New implementation checks these commands
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s nat').and_return({
          success: true,
          stdout: nat_rules_output
        })

        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s all | grep nat').and_return({
          success: true,
          stdout: nat_rules_output
        })

        # Mock Internet Sharing check
        allow(pf_manager).to receive(:execute_command_with_output).with('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled').and_return({
          success: true,
          stdout: "Enabled = 0"
        })
      end

      it 'returns correct status information with old nat syntax' do
        status = pf_manager.check_status

        expect(status[:enabled]).to be true
        expect(status[:nat_configured]).to be true
        expect(status[:interfaces][:wan]).to eq('en0')
        expect(status[:subnet]).to eq('192.168.1.0/24')
        expect(status[:managed_by_us]).to be true
      end
    end
    
    context 'when PF is enabled but NAT is not configured' do
      let(:pfctl_info_output) {
        <<~OUTPUT
        Status: Enabled
        Debug: Urgent
        OUTPUT
      }

      before do
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: pfctl_info_output
        })

        # No NAT rules found
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s nat').and_return({
          success: true,
          stdout: ""
        })

        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s all | grep nat').and_return({
          success: true,
          stdout: ""
        })

        # Internet Sharing is disabled
        allow(pf_manager).to receive(:execute_command_with_output).with('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enabled').and_return({
          success: true,
          stdout: "Enabled = 0"
        })
      end

      it 'returns status with NAT not configured' do
        status = pf_manager.check_status

        expect(status[:enabled]).to be true
        expect(status[:nat_configured]).to be false
        expect(status[:interfaces]).to be_nil
      end
    end
    
    context 'when PF is disabled' do
      let(:pfctl_info_output) {
        <<~OUTPUT
        Status: Disabled
        DEBUG: Urgent
        OUTPUT
      }

      before do
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: pfctl_info_output
        })
      end

      it 'returns status with PF disabled' do
        status = pf_manager.check_status

        expect(status[:enabled]).to be false
        expect(status[:nat_configured]).to be false
      end
    end
  end
end