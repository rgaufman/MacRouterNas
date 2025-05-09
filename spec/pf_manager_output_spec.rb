#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe MacRouterUtils::PFManager do
  let(:wan_interface) { 'ppp0' }
  let(:lan_interface) { 'en5' }
  let(:subnet) { '192.168.1.0/24' }
  let(:pf_manager) { described_class.new(wan_interface, lan_interface, false, subnet) }

  # Test the parse_nat_rule_output method
  describe '#parse_nat_rule_output' do
    context 'when processing output from pfctl -s all | grep nat' do
      it 'correctly parses conventional nat rule output' do
        # Example output from: sudo pfctl -s all | grep nat
        pfctl_output = "No ALTQ support in kernel\nALTQ related functions disabled\nnat on ppp0 inet from 192.168.1.0/24 to any -> (ppp0) round-robin"
        
        result = pf_manager.send(:parse_nat_rule_output, pfctl_output)
        
        expect(result[:nat_configured]).to be true
        expect(result[:interfaces][:wan]).to eq('ppp0')
        expect(result[:subnet]).to eq('192.168.1.0/24')
      end

      it 'correctly parses output with additional text and ALTQ messages' do
        pfctl_output = <<~OUTPUT
          No ALTQ support in kernel
          ALTQ related functions disabled
          nat on ppp0 inet from 192.168.1.0/24 to any -> (ppp0) round-robin
          Some other text that might be in the output
        OUTPUT
        
        result = pf_manager.send(:parse_nat_rule_output, pfctl_output)
        
        expect(result[:nat_configured]).to be true
        expect(result[:interfaces][:wan]).to eq('ppp0')
        expect(result[:subnet]).to eq('192.168.1.0/24')
      end

      it 'correctly handles output with multiple NAT rules' do
        pfctl_output = <<~OUTPUT
          No ALTQ support in kernel
          ALTQ related functions disabled
          nat on en0 inet from 10.0.0.0/24 to any -> (en0) round-robin
          nat on ppp0 inet from 192.168.1.0/24 to any -> (ppp0) round-robin
        OUTPUT
        
        result = pf_manager.send(:parse_nat_rule_output, pfctl_output)
        
        expect(result[:nat_configured]).to be true
        # Should match the last rule found (latest rule)
        expect(result[:interfaces][:wan]).to eq('ppp0')
        expect(result[:subnet]).to eq('192.168.1.0/24')
      end
    end

    context 'when processing output from pfctl -s nat' do
      it 'handles output without inet and round-robin' do
        pfctl_output = "nat on ppp0 from 192.168.1.0/24 to any -> (ppp0)"
        
        result = pf_manager.send(:parse_nat_rule_output, pfctl_output)
        
        expect(result[:nat_configured]).to be true
        expect(result[:interfaces][:wan]).to eq('ppp0')
        expect(result[:subnet]).to eq('192.168.1.0/24')
      end
      
      it 'handles the older direct-style NAT rule format' do
        pfctl_output = "nat on en0 from 192.168.2.0/24 to any -> (en0)"
        
        result = pf_manager.send(:parse_nat_rule_output, pfctl_output)
        
        expect(result[:nat_configured]).to be true
        expect(result[:interfaces][:wan]).to eq('en0')
        expect(result[:subnet]).to eq('192.168.2.0/24')
      end
    end
    
    context 'when processing Internet Sharing NAT rules' do
      it 'handles Internet Sharing style NAT rules' do
        pfctl_output = <<~OUTPUT
          nat on en0 from 192.168.2.0/24 to any -> (en0)
          nat on bridge100 from 192.168.137.0/24 to any -> (en0)
        OUTPUT
        
        result = pf_manager.send(:parse_nat_rule_output, pfctl_output)
        
        expect(result[:nat_configured]).to be true
        # Should match the last rule found (bridge interface used by Internet Sharing)
        expect(result[:interfaces][:wan]).to eq('bridge100')
        expect(result[:subnet]).to eq('192.168.137.0/24')
      end
    end

    context 'when no NAT rules are found' do
      it 'returns not configured when output has no NAT rules' do
        pfctl_output = "No ALTQ support in kernel\nALTQ related functions disabled\nSome other rules here"
        
        result = pf_manager.send(:parse_nat_rule_output, pfctl_output)
        
        expect(result[:nat_configured]).to be false
        expect(result[:interfaces]).to be_nil
        expect(result[:subnet]).to be_nil
      end

      it 'returns not configured when output is empty' do
        pfctl_output = ""
        
        result = pf_manager.send(:parse_nat_rule_output, pfctl_output)
        
        expect(result[:nat_configured]).to be false
        expect(result[:interfaces]).to be_nil
        expect(result[:subnet]).to be_nil
      end
    end
  end

  # Test parsing pfctl -s info output
  describe '#parse_pf_info' do
    it 'correctly detects when PF is enabled' do
      pfctl_output = <<~OUTPUT
        Status: Enabled
        Debug: Urgent
        Hostid: 0x0
        Version: 4.6
        Options: ALTQ, NAT-anchor, NF_UNKNOWN_ALG, PF_INPLACE, PF_MOD_REF
      OUTPUT
      
      result = pf_manager.send(:parse_pf_info, pfctl_output)
      
      expect(result[:enabled]).to be true
      expect(result[:debug]).to eq('Urgent')
      expect(result[:version]).to eq('4.6')
    end
    
    it 'correctly detects when PF is disabled' do
      pfctl_output = <<~OUTPUT
        Status: Disabled
        Debug: Urgent
        Hostid: 0x0
        Version: 4.6
        Options: ALTQ, NAT-anchor, NF_UNKNOWN_ALG, PF_INPLACE, PF_MOD_REF
      OUTPUT
      
      result = pf_manager.send(:parse_pf_info, pfctl_output)
      
      expect(result[:enabled]).to be false
      expect(result[:debug]).to eq('Urgent')
      expect(result[:version]).to eq('4.6')
    end
    
    it 'handles unusual formatting in pfctl output' do
      pfctl_output = <<~OUTPUT
        No ALTQ support in kernel
        ALTQ related functions disabled
        Status: Enabled for 13d 2h 34m 12s
        Debug: Urgent
        Version: 4.6
      OUTPUT
      
      result = pf_manager.send(:parse_pf_info, pfctl_output)
      
      expect(result[:enabled]).to be true
      expect(result[:debug]).to eq('Urgent')
      expect(result[:version]).to eq('4.6')
    end
    
    it 'handles empty or invalid output' do
      result = pf_manager.send(:parse_pf_info, "")
      expect(result[:enabled]).to be false
      expect(result[:error]).to eq('Invalid pfctl output')
    end
  end

  # Test the check_status method that combines different checks
  describe '#check_status_from_output' do
    context 'when both PF and NAT are configured' do
      it 'correctly identifies both PF and NAT status' do
        pf_info = <<~OUTPUT
          Status: Enabled
          Debug: Urgent
          Version: 4.6
        OUTPUT
        
        nat_rules = <<~OUTPUT
          nat on ppp0 inet from 192.168.1.0/24 to any -> (ppp0) round-robin
        OUTPUT
        
        internet_sharing = "Enabled = 0"
        
        result = pf_manager.send(:check_status_from_output, pf_info, nat_rules, internet_sharing)
        
        expect(result[:enabled]).to be true
        expect(result[:nat_configured]).to be true
        expect(result[:interfaces][:wan]).to eq('ppp0')
        expect(result[:subnet]).to eq('192.168.1.0/24')
        expect(result[:managed_by_us]).to be true
        expect(result[:internet_sharing_enabled]).to be false
      end
    end
    
    context 'when PF is enabled but NAT is not configured' do
      it 'correctly shows PF enabled but NAT not configured' do
        pf_info = <<~OUTPUT
          Status: Enabled
          Debug: Urgent
          Version: 4.6
        OUTPUT
        
        nat_rules = ""
        internet_sharing = "Enabled = 0"
        
        result = pf_manager.send(:check_status_from_output, pf_info, nat_rules, internet_sharing)
        
        expect(result[:enabled]).to be true
        expect(result[:nat_configured]).to be false
        expect(result[:internet_sharing_enabled]).to be false
      end
    end
    
    context 'when Internet Sharing is enabled' do
      it 'correctly identifies Internet Sharing as providing NAT' do
        pf_info = <<~OUTPUT
          Status: Enabled
          Debug: Urgent
          Version: 4.6
        OUTPUT
        
        nat_rules = <<~OUTPUT
          nat on bridge100 from 192.168.137.0/24 to any -> (en0)
        OUTPUT
        
        internet_sharing = "Enabled = 1"
        
        result = pf_manager.send(:check_status_from_output, pf_info, nat_rules, internet_sharing)
        
        expect(result[:enabled]).to be true
        expect(result[:nat_configured]).to be true
        expect(result[:internet_sharing_enabled]).to be true
        expect(result[:managed_by_system]).to be true
        expect(result[:interfaces][:wan]).to eq('bridge100')
        expect(result[:subnet]).to eq('192.168.137.0/24')
      end
    end
    
    context 'when PF is disabled' do
      it 'correctly shows PF is disabled regardless of NAT configuration' do
        pf_info = "Status: Disabled"
        nat_rules = "nat on ppp0 inet from 192.168.1.0/24 to any -> (ppp0) round-robin"
        internet_sharing = "Enabled = 0"
        
        result = pf_manager.send(:check_status_from_output, pf_info, nat_rules, internet_sharing)
        
        expect(result[:enabled]).to be false
        expect(result[:nat_configured]).to be false
      end
    end
  end
end