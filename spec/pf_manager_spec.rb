#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe MacRouterUtils::PFManager do
  let(:wan_interface) { 'en0' }
  let(:lan_interface) { 'en5' }
  let(:pf_manager) { described_class.new(wan_interface, lan_interface) }

  describe '#generate_rules' do
    it 'generates NAT rules correctly' do
      # Create a mock of the template engine that returns known output
      renderer = instance_double(MacRouterUtils::TemplateRenderer)
      allow(MacRouterUtils::TemplateRenderer).to receive(:new).and_return(renderer)
      
      # Mock the render method to return a predefined NAT configuration
      expected_rules = <<~RULES
      # MacRouterNas PF NAT Configuration
      # For: en0 (WAN) and en5 (LAN)
      # This file should be loaded into an anchor

      # Define interfaces
      ext_if = "en0"
      int_if = "en5"

      # NAT configuration
      match out on $ext_if from $int_if:network to any nat-to ($ext_if)

      # Pass rules for the NAT
      pass out on $ext_if from $int_if:network to any
      pass in on $int_if all
      RULES
      
      allow(renderer).to receive(:render).with('pf_rules', {wan: wan_interface, lan: lan_interface}).and_return(expected_rules)
      
      # Call the private method
      rules = pf_manager.send(:generate_rules)
      
      # Verify the rules contain the expected content
      expect(rules).to include("ext_if = \"#{wan_interface}\"")
      expect(rules).to include("int_if = \"#{lan_interface}\"")
      expect(rules).to include("match out on $ext_if from $int_if:network to any nat-to ($ext_if)")
      expect(rules).to include("pass out on $ext_if from $int_if:network to any")
      expect(rules).to include("pass in on $int_if all")
    end
  end

  describe '#generate_main_conf' do
    it 'generates main PF configuration correctly' do
      # Create a mock of the template engine that returns known output
      renderer = instance_double(MacRouterUtils::TemplateRenderer)
      allow(MacRouterUtils::TemplateRenderer).to receive(:new).and_return(renderer)
      
      # Mock the render method to return a predefined main PF configuration
      expected_conf = <<~CONF
      # MacRouterNas PF Main Configuration
      # Generated on 2023-01-01 00:00:00 -0000

      # Include system anchors
      anchor "com.apple/*"
      load anchor "com.apple" from "/etc/pf.anchors/com.apple"

      # MacRouterNas NAT anchor
      anchor "com.macrouternas"
      load anchor "com.macrouternas" from "/etc/pf.anchors/com.macrouternas"
      CONF
      
      allow(renderer).to receive(:render).with('pf_main_conf', {
        anchor_name: described_class::PF_ANCHOR_NAME,
        anchor_file: described_class::PF_ANCHOR_FILE
      }).and_return(expected_conf)
      
      # Call the private method
      conf = pf_manager.send(:generate_main_conf)
      
      # Verify the configuration contains the expected content
      expect(conf).to include('anchor "com.apple/*"')
      expect(conf).to include('load anchor "com.apple" from "/etc/pf.anchors/com.apple"')
      expect(conf).to include('anchor "com.macrouternas"')
      expect(conf).to include('load anchor "com.macrouternas" from "/etc/pf.anchors/com.macrouternas"')
    end
  end

  describe '#verify_interfaces' do
    context 'when checking a PPP WAN interface' do
      let(:ppp_manager) { described_class.new('ppp0', 'en5') }

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

        # Execute the private method
        expect { ppp_manager.send(:verify_interfaces) }.not_to raise_error

        # The method doesn't return a value, but it logs an info message for active PPP interfaces
        expect_any_instance_of(SemanticLogger::Logger).to receive(:info).with(/PPP interface ppp0 is active/)
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

        # The method warns but doesn't error
        expect_any_instance_of(SemanticLogger::Logger).to receive(:warn).with(/PPP interface ppp0 has RUNNING flag but no IP address/)
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

        # The method warns but doesn't error
        expect_any_instance_of(SemanticLogger::Logger).to receive(:warn).with(/PPP interface ppp0 has IP address but RUNNING flag not set/)
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

        # Mock successful anchor check with our NAT rules
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -sa').and_return({
          success: true,
          stdout: "... anchor \"com.macrouternas\" ... match out on en0 from en5:network to any nat-to (en0) ..."
        })
      end

      it 'returns true' do
        expect(pf_manager.verify_running).to be true
      end
    end

    context 'when PF is disabled' do
      before do
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: "Status: Disabled\nSome other PF info..."
        })
      end

      it 'returns false' do
        expect(pf_manager.verify_running).to be false
      end
    end

    context 'when PF is enabled but NAT is not configured' do
      before do
        # Mock successful PF status check
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: "Status: Enabled\nSome other PF info..."
        })

        # Mock anchor check without our NAT rules
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -sa').and_return({
          success: true,
          stdout: "... other anchors but not ours ..."
        })
      end

      it 'returns false' do
        expect(pf_manager.verify_running).to be false
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
      
      let(:pfctl_anchor_output) {
        <<~OUTPUT
        anchor "com.apple/*" all
        anchor "com.macrouternas" all
          match out on en0 from en5:network to any nat-to (en0)
          pass out on en0 from en5:network to any
          pass in on en5 all
        OUTPUT
      }
      
      before do
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: pfctl_info_output
        })
        
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -sa').and_return({
          success: true,
          stdout: pfctl_anchor_output
        })
        
        allow(File).to receive(:exist?).with(described_class::PF_ANCHOR_FILE).and_return(true)
      end
      
      it 'returns correct status information' do
        status = pf_manager.check_status
        
        expect(status[:enabled]).to be true
        expect(status[:nat_configured]).to be true
        expect(status[:interfaces][:wan]).to eq('en0')
        expect(status[:interfaces][:lan]).to eq('en5')
        expect(status[:anchor]).to eq(described_class::PF_ANCHOR_FILE)
      end
    end
    
    context 'when using older nat syntax' do
      let(:pfctl_info_output) {
        <<~OUTPUT
        Status: Enabled
        Debug: Urgent
        OUTPUT
      }
      
      let(:pfctl_anchor_output) {
        <<~OUTPUT
        anchor "com.apple/*" all
        anchor "com.macrouternas" all
          nat on en0 from en5:network to any -> (en0)
          pass out on en0 all
          pass in on en5 all
        OUTPUT
      }
      
      before do
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: pfctl_info_output
        })
        
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -sa').and_return({
          success: true,
          stdout: pfctl_anchor_output
        })
        
        allow(File).to receive(:exist?).with(described_class::PF_ANCHOR_FILE).and_return(true)
      end
      
      it 'returns correct status information with old nat syntax' do
        status = pf_manager.check_status
        
        expect(status[:enabled]).to be true
        expect(status[:nat_configured]).to be true
        expect(status[:interfaces][:wan]).to eq('en0')
        expect(status[:interfaces][:lan]).to eq('en5')
        expect(status[:anchor]).to eq(described_class::PF_ANCHOR_FILE)
      end
    end
    
    context 'when PF is enabled but NAT is not configured' do
      let(:pfctl_info_output) {
        <<~OUTPUT
        Status: Enabled
        Debug: Urgent
        OUTPUT
      }
      
      let(:pfctl_anchor_output) {
        <<~OUTPUT
        anchor "com.apple/*" all
        OUTPUT
      }
      
      before do
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -s info').and_return({
          success: true,
          stdout: pfctl_info_output
        })
        
        allow(pf_manager).to receive(:execute_command_with_output).with('sudo pfctl -sa').and_return({
          success: true,
          stdout: pfctl_anchor_output
        })
        
        allow(File).to receive(:exist?).with(described_class::PF_ANCHOR_FILE).and_return(false)
      end
      
      it 'returns status with NAT not configured' do
        status = pf_manager.check_status
        
        expect(status[:enabled]).to be true
        expect(status[:nat_configured]).to be false
        expect(status[:interfaces]).to be_nil
        expect(status[:anchor]).to be_nil
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