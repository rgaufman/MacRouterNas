#!/usr/bin/env ruby
# frozen_string_literal: true

require 'spec_helper'
require_relative '../../lib/brew_services'

RSpec.describe MacRouterUtils::BrewServices do
  describe '.list' do
    it 'returns array of services' do
      brew_output = <<~OUTPUT
        Name      Status  User  File
        dnsmasq   started root  ~/Library/LaunchAgents/homebrew.mxcl.dnsmasq.plist
        mysql     stopped
      OUTPUT

      allow(MacRouterUtils::Shell).to receive(:run).with('brew services list', raise_on_failure: false)
                                                   .and_return({ success: true, stdout: brew_output })

      result = described_class.list
      expect(result).to eq([
                             { name: 'dnsmasq', status: 'started', user: 'root' },
                             { name: 'mysql', status: 'stopped', user: nil }
                           ])
    end

    it 'returns empty array when no services' do
      allow(MacRouterUtils::Shell).to receive(:run).with('brew services list', raise_on_failure: false)
                                                   .and_return({ success: false, stdout: '' })

      result = described_class.list
      expect(result).to eq([])
    end
  end

  describe '.status' do
    it 'returns service info when found' do
      allow(described_class).to receive(:list).and_return([
                                                             { name: 'dnsmasq', status: 'started', user: 'root' },
                                                             { name: 'mysql', status: 'stopped', user: nil }
                                                           ])

      result = described_class.status('dnsmasq')
      expect(result).to eq({ name: 'dnsmasq', status: 'started', user: 'root' })
    end

    it 'returns nil when service not found' do
      allow(described_class).to receive(:list).and_return([])

      result = described_class.status('dnsmasq')
      expect(result).to be_nil
    end
  end

  describe '.running?' do
    it 'returns true when service is started' do
      allow(described_class).to receive(:status).with('dnsmasq')
                                                .and_return({ name: 'dnsmasq', status: 'started', user: 'root' })

      result = described_class.running?('dnsmasq')
      expect(result).to be true
    end

    it 'returns false when service is stopped' do
      allow(described_class).to receive(:status).with('dnsmasq')
                                                .and_return({ name: 'dnsmasq', status: 'stopped', user: nil })

      result = described_class.running?('dnsmasq')
      expect(result).to be false
    end

    it 'returns false when service not found' do
      allow(described_class).to receive(:status).with('dnsmasq').and_return(nil)

      result = described_class.running?('dnsmasq')
      expect(result).to be false
    end
  end

  describe '.start' do
    it 'starts service without sudo by default' do
      allow(MacRouterUtils::Shell).to receive(:run).with('brew services start dnsmasq')
                                                   .and_return({ success: true, stdout: '' })

      result = described_class.start('dnsmasq')
      expect(result).to be true
    end

    it 'starts service with sudo when requested' do
      allow(MacRouterUtils::Shell).to receive(:run).with('sudo brew services start dnsmasq')
                                                   .and_return({ success: true, stdout: '' })

      result = described_class.start('dnsmasq', use_sudo: true)
      expect(result).to be true
    end
  end

  describe '.stop' do
    it 'stops service without sudo by default' do
      allow(MacRouterUtils::Shell).to receive(:run).with('brew services stop dnsmasq')
                                                   .and_return({ success: true, stdout: '' })

      result = described_class.stop('dnsmasq')
      expect(result).to be true
    end

    it 'stops service with sudo when requested' do
      allow(MacRouterUtils::Shell).to receive(:run).with('sudo brew services stop dnsmasq')
                                                   .and_return({ success: true, stdout: '' })

      result = described_class.stop('dnsmasq', use_sudo: true)
      expect(result).to be true
    end
  end

  describe '.restart' do
    it 'restarts service without sudo by default' do
      allow(MacRouterUtils::Shell).to receive(:run).with('brew services restart dnsmasq')
                                                   .and_return({ success: true, stdout: '' })

      result = described_class.restart('dnsmasq')
      expect(result).to be true
    end

    it 'restarts service with sudo when requested' do
      allow(MacRouterUtils::Shell).to receive(:run).with('sudo brew services restart dnsmasq')
                                                   .and_return({ success: true, stdout: '' })

      result = described_class.restart('dnsmasq', use_sudo: true)
      expect(result).to be true
    end
  end

  describe '.logs' do
    it 'returns log output' do
      allow(MacRouterUtils::Shell).to receive(:run).with('brew services log dnsmasq', raise_on_failure: false)
                                                   .and_return({ success: true, stdout: 'log content' })

      result = described_class.logs('dnsmasq')
      expect(result).to eq('log content')
    end

    it 'returns empty string on failure' do
      allow(MacRouterUtils::Shell).to receive(:run).with('brew services log dnsmasq', raise_on_failure: false)
                                                   .and_return({ success: false, stdout: '' })

      result = described_class.logs('dnsmasq')
      expect(result).to eq('')
    end
  end

  describe '.cleanup' do
    it 'runs cleanup command' do
      allow(MacRouterUtils::Shell).to receive(:run).with('brew services cleanup', raise_on_failure: false)
                                                   .and_return({ success: true, stdout: '' })

      result = described_class.cleanup
      expect(result).to be true
    end
  end
end
