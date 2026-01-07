#!/usr/bin/env ruby
# frozen_string_literal: true

require 'spec_helper'
require_relative '../../lib/process_helper'

RSpec.describe MacRouterUtils::ProcessHelper do
  describe '.pids' do
    it 'returns array of PIDs when process is found' do
      allow(MacRouterUtils::Shell).to receive(:run).with('pgrep  dnsmasq', raise_on_failure: false)
                                               .and_return({ success: true, stdout: "12345\n12346\n" })

      result = described_class.pids('dnsmasq')
      expect(result).to eq([12345, 12346])
    end

    it 'returns empty array when process not found' do
      allow(MacRouterUtils::Shell).to receive(:run).with('pgrep  not_running', raise_on_failure: false)
                                               .and_return({ success: false, stdout: '' })

      result = described_class.pids('not_running')
      expect(result).to eq([])
    end

    it 'uses -f flag when full_match option is true' do
      allow(MacRouterUtils::Shell).to receive(:run).with('pgrep -f dnsmasq', raise_on_failure: false)
                                               .and_return({ success: true, stdout: "12345\n" })

      result = described_class.pids('dnsmasq', full_match: true)
      expect(result).to eq([12345])
    end

    it 'handles single PID output' do
      allow(MacRouterUtils::Shell).to receive(:run).with('pgrep  dnsmasq', raise_on_failure: false)
                                               .and_return({ success: true, stdout: '12345' })

      result = described_class.pids('dnsmasq')
      expect(result).to eq([12345])
    end
  end

  describe '.pid' do
    it 'returns first PID when multiple processes found' do
      allow(described_class).to receive(:pids).with('dnsmasq', {}).and_return([12345, 12346])

      result = described_class.pid('dnsmasq')
      expect(result).to eq(12345)
    end

    it 'returns nil when no process found' do
      allow(described_class).to receive(:pids).with('not_running', {}).and_return([])

      result = described_class.pid('not_running')
      expect(result).to be_nil
    end
  end

  describe '.running?' do
    it 'returns true when process is running' do
      allow(described_class).to receive(:pids).with('dnsmasq', {}).and_return([12345])

      result = described_class.running?('dnsmasq')
      expect(result).to be true
    end

    it 'returns false when process is not running' do
      allow(described_class).to receive(:pids).with('not_running', {}).and_return([])

      result = described_class.running?('not_running')
      expect(result).to be false
    end
  end

  describe '.find_detailed' do
    it 'returns array of process info with PIDs and commands' do
      output = "12345 /opt/homebrew/sbin/dnsmasq\n12346 /opt/homebrew/sbin/dnsmasq --test\n"
      allow(MacRouterUtils::Shell).to receive(:run).with('pgrep -l dnsmasq', raise_on_failure: false)
                                               .and_return({ success: true, stdout: output })

      result = described_class.find_detailed('dnsmasq')
      expect(result).to eq([
                             { pid: 12345, command: '/opt/homebrew/sbin/dnsmasq' },
                             { pid: 12346, command: '/opt/homebrew/sbin/dnsmasq --test' }
                           ])
    end

    it 'returns empty array when no processes found' do
      allow(MacRouterUtils::Shell).to receive(:run).with('pgrep -l not_running', raise_on_failure: false)
                                               .and_return({ success: false, stdout: '' })

      result = described_class.find_detailed('not_running')
      expect(result).to eq([])
    end

    it 'uses -fl flag when full_match option is true' do
      allow(MacRouterUtils::Shell).to receive(:run).with('pgrep -fl dnsmasq', raise_on_failure: false)
                                               .and_return({ success: true, stdout: "12345 /opt/homebrew/sbin/dnsmasq\n" })

      result = described_class.find_detailed('dnsmasq', full_match: true)
      expect(result).to eq([{ pid: 12345, command: '/opt/homebrew/sbin/dnsmasq' }])
    end
  end
end
