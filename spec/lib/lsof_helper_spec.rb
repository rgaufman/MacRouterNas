#!/usr/bin/env ruby
# frozen_string_literal: true

require 'spec_helper'
require_relative '../../lib/lsof_helper'

RSpec.describe MacRouterUtils::LsofHelper do
  describe '.port_info' do
    it 'returns process info when port is in use' do
      lsof_output = <<~OUTPUT
        COMMAND    PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
        dnsmasq  12345  root    4u  IPv4 0x123456      0t0  UDP *:bootps
      OUTPUT

      allow(MacRouterUtils::Shell).to receive(:run).with('sudo lsof -i :67', raise_on_failure: false)
                                                   .and_return({ success: true, stdout: lsof_output })

      result = described_class.port_info(67)
      expect(result).to eq({ process: 'dnsmasq', pid: 12345, user: 'root' })
    end

    it 'returns nil when port is not in use' do
      allow(MacRouterUtils::Shell).to receive(:run).with('sudo lsof -i :80', raise_on_failure: false)
                                                   .and_return({ success: false, stdout: '' })

      result = described_class.port_info(80)
      expect(result).to be_nil
    end

    it 'returns nil when lsof output is empty' do
      allow(MacRouterUtils::Shell).to receive(:run).with('sudo lsof -i :80', raise_on_failure: false)
                                                   .and_return({ success: true, stdout: '' })

      result = described_class.port_info(80)
      expect(result).to be_nil
    end

    it 'returns nil when lsof output only has header' do
      lsof_output = "COMMAND    PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"

      allow(MacRouterUtils::Shell).to receive(:run).with('sudo lsof -i :80', raise_on_failure: false)
                                                   .and_return({ success: true, stdout: lsof_output })

      result = described_class.port_info(80)
      expect(result).to be_nil
    end
  end

  describe '.port_used_by?' do
    it 'returns true when specified process is using the port' do
      allow(described_class).to receive(:port_info).with(67)
                                                   .and_return({ process: 'dnsmasq', pid: 12345, user: 'root' })

      result = described_class.port_used_by?(67, 'dnsmasq')
      expect(result).to be true
    end

    it 'returns false when different process is using the port' do
      allow(described_class).to receive(:port_info).with(67)
                                                   .and_return({ process: 'bootpd', pid: 12345, user: 'root' })

      result = described_class.port_used_by?(67, 'dnsmasq')
      expect(result).to be false
    end

    it 'returns false when port is not in use' do
      allow(described_class).to receive(:port_info).with(67).and_return(nil)

      result = described_class.port_used_by?(67, 'dnsmasq')
      expect(result).to be false
    end
  end

  describe '.port_in_use?' do
    it 'returns true when port is in use' do
      allow(described_class).to receive(:port_info).with(67)
                                                   .and_return({ process: 'dnsmasq', pid: 12345, user: 'root' })

      result = described_class.port_in_use?(67)
      expect(result).to be true
    end

    it 'returns false when port is not in use' do
      allow(described_class).to receive(:port_info).with(80).and_return(nil)

      result = described_class.port_in_use?(80)
      expect(result).to be false
    end
  end

  describe '.port_processes' do
    it 'returns array of all processes using the port' do
      lsof_output = <<~OUTPUT
        COMMAND    PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
        dnsmasq  12345  root    4u  IPv4 0x123456      0t0  UDP *:bootps
        dnsmasq  12346  root    5u  IPv6 0x123457      0t0  UDP *:bootps
      OUTPUT

      allow(MacRouterUtils::Shell).to receive(:run).with('sudo lsof -i :67', raise_on_failure: false)
                                                   .and_return({ success: true, stdout: lsof_output })

      result = described_class.port_processes(67)
      expect(result).to eq([
                             { process: 'dnsmasq', pid: 12345, user: 'root' },
                             { process: 'dnsmasq', pid: 12346, user: 'root' }
                           ])
    end

    it 'returns empty array when port is not in use' do
      allow(MacRouterUtils::Shell).to receive(:run).with('sudo lsof -i :80', raise_on_failure: false)
                                                   .and_return({ success: false, stdout: '' })

      result = described_class.port_processes(80)
      expect(result).to eq([])
    end
  end
end
