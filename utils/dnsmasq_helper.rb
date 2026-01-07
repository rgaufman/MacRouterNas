#!/usr/bin/env ruby
# frozen_string_literal: true

# DNSMasq helper utilities
# Provides shared functionality for dnsmasq operations

require_relative 'system_manager'
require_relative '../lib/process_helper'

module MacRouterUtils
  # Helper module for dnsmasq-specific operations
  module DnsmasqHelper
    DNSMASQ_CONF = '/opt/homebrew/etc/dnsmasq.conf'
    DNSMASQ_BLACKLIST_DIR = '/opt/homebrew/etc/dnsmasq.d'

    # Validate dnsmasq configuration
    def validate_dnsmasq_config
      shell('sudo dnsmasq --test')
      logger.debug 'dnsmasq configuration is valid'
      true
    rescue StandardError => e
      logger.error 'dnsmasq configuration validation failed!'
      logger.error "Error: #{e.message}"
      logger.error "Please check configuration files in #{DNSMASQ_BLACKLIST_DIR}"
      raise
    end

    # Reload dnsmasq configuration (sends SIGHUP)
    def reload_dnsmasq
      # Validate configuration before reloading
      validate_dnsmasq_config

      pid = ProcessHelper.pid('dnsmasq')

      if pid
        shell("sudo kill -HUP #{pid}")
        logger.info "Reloaded dnsmasq configuration (PID: #{pid})"
        true
      else
        logger.warn 'dnsmasq is not running, cannot reload'
        raise 'dnsmasq is not running'
      end
    end

    # Check if dnsmasq is running
    def dnsmasq_running?
      ProcessHelper.running?('dnsmasq')
    end

    # Get dnsmasq PID
    def dnsmasq_pid
      ProcessHelper.pid('dnsmasq')
    end

    # Generate dnsmasq blacklist entry for a domain
    def generate_blacklist_entry(domain)
      "address=/#{domain}/0.0.0.0"
    end

    # Generate blacklist content from domain list
    def generate_blacklist_content(domains, header: nil)
      # Handle multiline headers by prefixing each line with #
      header_text = header || 'DNS Blacklist'
      header_lines = header_text.split("\n").map { |line| "# #{line}" }.join("\n")

      content = "#{header_lines}\n"
      content += "# Generated at #{Time.now}\n\n"

      domains.each do |domain|
        content += "#{generate_blacklist_entry(domain)}\n"
      end

      content
    end

    # Ensure dnsmasq conf-dir directive is present
    def ensure_conf_dir_directive(conf_file = DNSMASQ_CONF, dir = DNSMASQ_BLACKLIST_DIR)
      return false unless File.exist?(conf_file)

      content = File.read(conf_file)
      directive = "conf-dir=#{dir},*.blacklist"

      if content.include?(directive)
        false
      else
        logger.info "Adding conf-dir directive to #{conf_file}"

        # Append the directive
        new_content = content + "\n#{directive}\n"

        temp_file = "/tmp/dnsmasq_conf_#{Process.pid}"
        File.write(temp_file, new_content)

        shell("sudo cp #{temp_file} #{conf_file}")
        shell("sudo chmod 644 #{conf_file}")
        FileUtils.rm_f(temp_file)

        reload_dnsmasq
        true
      end
    end
  end
end
