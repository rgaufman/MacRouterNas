#!/usr/bin/env ruby
# frozen_string_literal: true

# Common helper utilities shared across MacRouterNas
# Provides DRY utilities for file operations, logging, and validation

require_relative 'system_manager'

module MacRouterUtils
  # Common helper methods for file operations, logging, and utilities
  module CommonHelpers
    # Write a file to a system location using sudo
    # Handles temp file creation, sudo copy, permissions, and cleanup
    def write_file_with_sudo(destination, content, permissions = '644')
      temp_file = "/tmp/#{File.basename(destination)}_#{Process.pid}"

      begin
        File.write(temp_file, content)
        shell("sudo cp #{temp_file} #{destination}")
        shell("sudo chmod #{permissions} #{destination}")
        logger.debug "Wrote file to #{destination}"
        true
      rescue StandardError => e
        logger.error "Failed to write file to #{destination}: #{e.message}"
        false
      ensure
        FileUtils.rm_f(temp_file)
      end
    end

    # Validate time format (HH:MM)
    def valid_time_format?(time_string)
      !time_string.nil? && time_string.match?(/^\d{2}:\d{2}$/)
    end

    # Validate time window format (HH:MM-HH:MM)
    def valid_time_window_format?(window_string)
      !window_string.nil? && window_string.match?(/^\d{2}:\d{2}-\d{2}:\d{2}$/)
    end

    # Parse time window into start and end times
    def parse_time_window(window_string)
      return [nil, nil] unless valid_time_window_format?(window_string)

      parts = window_string.split('-')
      [parts[0].strip, parts[1].strip]
    end

    # Check if a time range crosses midnight
    def crosses_midnight?(start_time, end_time)
      start_time > end_time
    end

    # Check if current time is within a time window
    def time_in_window?(current_time, window_string)
      return false unless window_string

      start_time, end_time = parse_time_window(window_string)
      return false unless start_time && end_time

      if crosses_midnight?(start_time, end_time)
        # Window crosses midnight
        current_time >= start_time || current_time < end_time
      else
        # Normal window
        current_time >= start_time && current_time < end_time
      end
    end

    # Ensure directory exists (with sudo if needed)
    def ensure_directory_exists(directory, use_sudo: true)
      if use_sudo
        shell("sudo mkdir -p #{directory}")
      else
        FileUtils.mkdir_p(directory)
      end
    end

    # Generate domain variants (www., mobile., etc.)
    def generate_domain_variants(domain)
      variants = [domain]

      # Add www. variant
      variants << "www.#{domain}" unless domain.start_with?('www.')

      # Add platform-specific variants for major platforms
      variants.concat(platform_specific_variants(domain))

      variants.uniq
    end

    private

    # Get platform-specific subdomain variants
    def platform_specific_variants(domain)
      case domain
      when /youtube\.com/
        ['m.youtube.com', 'music.youtube.com', 'gaming.youtube.com', 'tv.youtube.com']
      when /instagram\.com/
        ['m.instagram.com', 'i.instagram.com']
      when /facebook\.com/
        ['m.facebook.com', 'mobile.facebook.com', 'touch.facebook.com']
      when /twitter\.com/, /x\.com/
        ['mobile.twitter.com', 'm.twitter.com', 'mobile.x.com', 'm.x.com']
      when /tiktok\.com/
        ['m.tiktok.com', 'vm.tiktok.com']
      when /reddit\.com/
        ['old.reddit.com', 'new.reddit.com', 'i.reddit.com', 'm.reddit.com']
      else
        []
      end
    end
  end
end
