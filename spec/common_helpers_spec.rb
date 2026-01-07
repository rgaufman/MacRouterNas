# frozen_string_literal: true

require_relative 'spec_helper'
require_relative '../utils/common_helpers'
require_relative '../utils/system_manager'

# Test class to include the module
class CommonHelpersTest < MacRouterUtils::SystemManager
  include MacRouterUtils::CommonHelpers
end

RSpec.describe MacRouterUtils::CommonHelpers do
  let(:test_object) { CommonHelpersTest.new }

  describe '#valid_time_format?' do
    it 'validates correct time formats' do
      expect(test_object.valid_time_format?('12:00')).to be true
      expect(test_object.valid_time_format?('00:00')).to be true
      expect(test_object.valid_time_format?('23:59')).to be true
    end

    it 'rejects invalid time formats' do
      expect(test_object.valid_time_format?('12:0')).to be false
      expect(test_object.valid_time_format?('12')).to be false
      expect(test_object.valid_time_format?('abc')).to be false
      expect(test_object.valid_time_format?(nil)).to be false
    end

    # NOTE: The validation only checks format (HH:MM), not validity of values
    it 'accepts format but does not validate hour/minute values' do
      expect(test_object.valid_time_format?('25:00')).to be true # Format valid even though hour is invalid
      expect(test_object.valid_time_format?('12:99')).to be true # Format valid even though minute is invalid
    end
  end

  describe '#valid_time_window_format?' do
    it 'validates correct time window formats' do
      expect(test_object.valid_time_window_format?('12:00-14:00')).to be true
      expect(test_object.valid_time_window_format?('00:00-23:59')).to be true
    end

    it 'rejects invalid time window formats' do
      expect(test_object.valid_time_window_format?('12:00')).to be false
      expect(test_object.valid_time_window_format?('12:00-')).to be false
      expect(test_object.valid_time_window_format?('-14:00')).to be false
      expect(test_object.valid_time_window_format?(nil)).to be false
    end
  end

  describe '#parse_time_window' do
    it 'parses valid time windows' do
      start, finish = test_object.parse_time_window('12:00-14:00')
      expect(start).to eq('12:00')
      expect(finish).to eq('14:00')
    end

    it 'returns nil for invalid windows' do
      start, finish = test_object.parse_time_window('invalid')
      expect(start).to be_nil
      expect(finish).to be_nil
    end
  end

  describe '#crosses_midnight?' do
    it 'detects windows that cross midnight' do
      expect(test_object.crosses_midnight?('23:00', '01:00')).to be true
      expect(test_object.crosses_midnight?('22:00', '06:00')).to be true
    end

    it 'detects windows that do not cross midnight' do
      expect(test_object.crosses_midnight?('12:00', '14:00')).to be false
      expect(test_object.crosses_midnight?('06:00', '22:00')).to be false
    end
  end

  describe '#time_in_window?' do
    context 'normal windows' do
      it 'detects time inside window' do
        expect(test_object.time_in_window?('13:00', '12:00-14:00')).to be true
        expect(test_object.time_in_window?('12:00', '12:00-14:00')).to be true
      end

      it 'detects time outside window' do
        expect(test_object.time_in_window?('11:59', '12:00-14:00')).to be false
        expect(test_object.time_in_window?('14:00', '12:00-14:00')).to be false
        expect(test_object.time_in_window?('15:00', '12:00-14:00')).to be false
      end
    end

    context 'midnight-crossing windows' do
      it 'detects time inside window before midnight' do
        expect(test_object.time_in_window?('23:30', '23:00-01:00')).to be true
      end

      it 'detects time inside window after midnight' do
        expect(test_object.time_in_window?('00:30', '23:00-01:00')).to be true
      end

      it 'detects time outside window' do
        expect(test_object.time_in_window?('12:00', '23:00-01:00')).to be false
        expect(test_object.time_in_window?('22:00', '23:00-01:00')).to be false
      end
    end

    context 'nil window' do
      it 'returns false for any time' do
        expect(test_object.time_in_window?('12:00', nil)).to be false
      end
    end
  end

  describe '#generate_domain_variants' do
    it 'generates www variant for regular domains' do
      variants = test_object.generate_domain_variants('example.com')
      expect(variants).to include('example.com', 'www.example.com')
    end

    it 'does not duplicate www for www domains' do
      variants = test_object.generate_domain_variants('www.example.com')
      expect(variants.count('www.example.com')).to eq(1)
    end

    it 'generates platform-specific variants for YouTube' do
      variants = test_object.generate_domain_variants('youtube.com')
      expect(variants).to include('youtube.com', 'www.youtube.com',
                                  'm.youtube.com', 'music.youtube.com',
                                  'gaming.youtube.com', 'tv.youtube.com')
    end

    it 'generates platform-specific variants for Instagram' do
      variants = test_object.generate_domain_variants('instagram.com')
      expect(variants).to include('instagram.com', 'www.instagram.com',
                                  'm.instagram.com', 'i.instagram.com')
    end

    it 'generates platform-specific variants for Twitter/X' do
      variants = test_object.generate_domain_variants('x.com')
      expect(variants).to include('x.com', 'www.x.com',
                                  'mobile.x.com', 'm.x.com')
    end
  end
end
