#!/usr/bin/env ruby
# frozen_string_literal: true

# Script to update blacklists and reload dnsmasq
# Can be run as a cron job to keep blacklists fresh

require_relative 'utils/logger_config'
require 'open3'
require 'logger'

# Use standard logger if logger_config isn't available
begin
  logger = MacRouterUtils::LoggerConfig.new('update_blacklists_script').logger
rescue NameError
  logger = Logger.new(STDOUT)
  logger.level = Logger::INFO
  logger.formatter = proc do |severity, datetime, progname, msg|
    "#{datetime.strftime('%Y-%m-%d %H:%M:%S.%L')} #{severity} [#{Process.pid}] #{msg}\n"
  end
end

logger.info "Starting blacklist update process"

# Step 1: Update the blacklists
logger.info "Updating blacklists..."
whitelist_path = File.join(File.dirname(__FILE__), 'blacklists/whitelist.txt')
blacklist_update_cmd = File.join(File.dirname(__FILE__), 'utils/update_blacklists.rb')
blacklist_update_cmd += " --verbose --whitelist #{whitelist_path} --output /opt/homebrew/etc/dnsmasq.blacklist"
# Use sudo to ensure we can write to the destination directory
stdout, stderr, status = Open3.capture3("sudo #{blacklist_update_cmd}")

unless status.success?
  logger.error "Failed to update blacklists: #{stderr}"
  exit 1
end

logger.info "Blacklists updated successfully"
logger.info stdout if stdout && !stdout.empty?

# Step 2: Check if dnsmasq is running
logger.info "Checking if dnsmasq is running..."
dnsmasq_status, stderr, status = Open3.capture3('pgrep dnsmasq')

unless status.success?
  logger.warn "Dnsmasq doesn't appear to be running. Blacklists updated but service not reloaded."
  exit 0
end

# Step 3: Signal dnsmasq to reload its configuration
logger.info "Reloading dnsmasq configuration..."
pid = dnsmasq_status.strip.split("\n").first
# Always use sudo for operations that modify system processes
reload_cmd = "sudo kill -HUP #{pid}"
stdout, stderr, status = Open3.capture3(reload_cmd)

unless status.success?
  logger.error "Failed to reload dnsmasq: #{stderr}"
  logger.info "Will attempt to restart the service instead"
  
  # Try restarting the service
  restart_cmd = "sudo brew services restart dnsmasq"
  stdout, stderr, status = Open3.capture3(restart_cmd)
  
  unless status.success?
    logger.error "Failed to restart dnsmasq service: #{stderr}"
    exit 1
  end
  
  logger.info "Dnsmasq service restarted successfully"
else
  logger.info "Dnsmasq configuration reloaded successfully"
end

logger.info "Blacklist update and reload process completed"