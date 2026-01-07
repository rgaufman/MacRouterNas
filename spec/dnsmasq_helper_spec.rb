# frozen_string_literal: true

require_relative 'spec_helper'
require_relative '../utils/dnsmasq_helper'
require_relative '../utils/system_manager'

# Test class to include the module
class DnsmasqHelperTest < MacRouterUtils::SystemManager
  include MacRouterUtils::DnsmasqHelper
end

RSpec.describe MacRouterUtils::DnsmasqHelper do
  let(:test_object) { DnsmasqHelperTest.new }

  describe '#generate_blacklist_entry' do
    it 'generates correct dnsmasq address entry' do
      expect(test_object.generate_blacklist_entry('example.com')).to eq('address=/example.com/0.0.0.0')
    end
  end

  describe '#generate_blacklist_content' do
    let(:domains) { ['example.com', 'test.com'] }

    it 'generates blacklist content with single-line header' do
      result = test_object.generate_blacklist_content(domains, header: 'Test Blacklist')

      expect(result).to include('# Test Blacklist')
      expect(result).to include('# Generated at')
      expect(result).to include('address=/example.com/0.0.0.0')
      expect(result).to include('address=/test.com/0.0.0.0')
    end

    it 'generates blacklist content with default header when none provided' do
      result = test_object.generate_blacklist_content(domains)

      expect(result).to include('# DNS Blacklist')
      expect(result).to include('# Generated at')
    end

    it 'properly comments all lines in multiline headers' do
      multiline_header = "Permanent blacklist - always blocked domains\n" \
                         "Auto-generated on #{Time.now}\n" \
                         'Managed by PermanentBlacklistManager'
      result = test_object.generate_blacklist_content(domains, header: multiline_header)

      # Split result into lines and check each line
      lines = result.split("\n")

      # First 3 lines should be the multiline header (all commented)
      expect(lines[0]).to start_with('# Permanent blacklist')
      expect(lines[1]).to start_with('# Auto-generated on')
      expect(lines[2]).to start_with('# Managed by')

      # Fourth line should be the "Generated at" timestamp
      expect(lines[3]).to start_with('# Generated at')

      # Fifth line should be empty (blank line before entries)
      expect(lines[4]).to eq('')

      # Subsequent lines should be address entries (not comments)
      expect(lines[5]).to eq('address=/example.com/0.0.0.0')
      expect(lines[6]).to eq('address=/test.com/0.0.0.0')

      # CRITICAL: Ensure no uncommented non-empty lines exist before address entries
      # This would cause "bad option" errors in dnsmasq
      header_lines = lines[0..4]
      header_lines.each do |line|
        # Each line should either be empty or start with #
        expect(line).to match(/^(#.*|)$/), "Found uncommented line in header: '#{line}'"
      end
    end

    it 'validates that generated content is valid dnsmasq syntax' do
      multiline_header = "Line 1\nLine 2\nLine 3"
      result = test_object.generate_blacklist_content(domains, header: multiline_header)

      # Write to temp file and test with dnsmasq --test
      temp_file = "/tmp/test_blacklist_#{Process.pid}.conf"
      File.write(temp_file, result)

      # This would normally run: sudo dnsmasq --test --conf-file=#{temp_file}
      # For now, just verify the content structure
      lines = result.split("\n")
      lines.each_with_index do |line, _idx|
        next if line.empty?

        # Non-empty lines must be either comments or valid address entries
        is_comment = line.start_with?('#')
        is_address = line.match?(%r{^address=/[a-z0-9.-]+/\d+\.\d+\.\d+\.\d+$})

        expect(is_comment || is_address).to be_truthy
      end

      FileUtils.rm_f(temp_file)
    end
  end
end
