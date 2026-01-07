#!/usr/bin/env ruby
# frozen_string_literal: true

require 'spec_helper'
require_relative '../../lib/launch_ctl'

RSpec.describe MacRouterUtils::LaunchCtl do
  describe '.list' do
    it 'returns array of service labels' do
      launchctl_output = <<~OUTPUT
        PID   Status  Label
        123   0       com.apple.Spotlight
        456   0       com.macrouternas.ipforwarding
      OUTPUT

      allow(MacRouterUtils::Shell).to receive(:run).with('sudo launchctl list', raise_on_failure: false)
                                                   .and_return({ success: true, stdout: launchctl_output })

      result = described_class.list
      expect(result).to eq(['com.apple.Spotlight', 'com.macrouternas.ipforwarding'])
    end

    it 'returns empty array when no services' do
      allow(MacRouterUtils::Shell).to receive(:run).with('sudo launchctl list', raise_on_failure: false)
                                                   .and_return({ success: false, stdout: '' })

      result = described_class.list
      expect(result).to eq([])
    end
  end

  describe '.loaded?' do
    it 'returns true when service is loaded' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl list | grep com.macrouternas.ipforwarding', raise_on_failure: false)
        .and_return({ success: true, stdout: '456   0  com.macrouternas.ipforwarding' })

      result = described_class.loaded?('com.macrouternas.ipforwarding')
      expect(result).to be true
    end

    it 'returns false when service is not loaded' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl list | grep com.example.notfound', raise_on_failure: false)
        .and_return({ success: false, stdout: '' })

      result = described_class.loaded?('com.example.notfound')
      expect(result).to be false
    end
  end

  describe '.load' do
    it 'loads plist without force flag by default' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl load  /Library/LaunchDaemons/com.example.plist')
        .and_return({ success: true, stdout: '' })

      result = described_class.load('/Library/LaunchDaemons/com.example.plist')
      expect(result).to be true
    end

    it 'loads plist with -w flag when force_load is true' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl load -w /Library/LaunchDaemons/com.example.plist')
        .and_return({ success: true, stdout: '' })

      result = described_class.load('/Library/LaunchDaemons/com.example.plist', force_load: true)
      expect(result).to be true
    end
  end

  describe '.unload' do
    it 'unloads plist without force flag by default' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl unload  /Library/LaunchDaemons/com.example.plist', raise_on_failure: false)
        .and_return({ success: true, stdout: '' })

      result = described_class.unload('/Library/LaunchDaemons/com.example.plist')
      expect(result).to be true
    end

    it 'unloads plist with -w flag when force_unload is true' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl unload -w /Library/LaunchDaemons/com.example.plist', raise_on_failure: false)
        .and_return({ success: true, stdout: '' })

      result = described_class.unload('/Library/LaunchDaemons/com.example.plist', force_unload: true)
      expect(result).to be true
    end
  end

  describe '.bootstrap' do
    it 'bootstraps a service' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.plist')
        .and_return({ success: true, stdout: '' })

      result = described_class.bootstrap('system', '/Library/LaunchDaemons/com.example.plist')
      expect(result).to be true
    end
  end

  describe '.bootout' do
    it 'boots out a service' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl bootout system /Library/LaunchDaemons/com.example.plist', raise_on_failure: false)
        .and_return({ success: true, stdout: '' })

      result = described_class.bootout('system', '/Library/LaunchDaemons/com.example.plist')
      expect(result).to be true
    end
  end

  describe '.info' do
    it 'returns service info when found' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl print system/com.macrouternas.ipforwarding', raise_on_failure: false)
        .and_return({ success: true, stdout: 'service info here' })

      result = described_class.info('com.macrouternas.ipforwarding')
      expect(result).to eq({ label: 'com.macrouternas.ipforwarding', info: 'service info here' })
    end

    it 'returns nil when service not found' do
      allow(MacRouterUtils::Shell).to receive(:run)
        .with('sudo launchctl print system/com.example.notfound', raise_on_failure: false)
        .and_return({ success: false, stdout: '' })

      result = described_class.info('com.example.notfound')
      expect(result).to be_nil
    end
  end
end
