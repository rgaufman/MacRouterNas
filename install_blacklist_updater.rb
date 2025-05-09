#!/usr/bin/env ruby
# frozen_string_literal: true

# Script to install the blacklist updater LaunchAgent
# This will configure automatic weekly updates of ad/tracking blacklists

require_relative 'utils/template_renderer'
require_relative 'utils/logger_config'
require 'fileutils'
require 'open3'

logger = MacRouterUtils::LoggerConfig.new('blacklist_installer').logger

# Get the absolute path to the update script
script_dir = File.expand_path(File.dirname(__FILE__))
script_path = File.join(script_dir, 'update_and_reload_blacklists.rb')

# Check if the script exists
unless File.exist?(script_path)
  logger.error "Update script not found at #{script_path}"
  exit 1
end

# Make sure the script is executable
FileUtils.chmod('+x', script_path)

# Render the LaunchAgent template
logger.info "Generating LaunchAgent plist..."
renderer = MacRouterUtils::TemplateRenderer.new
plist_content = renderer.render('blacklist_updater_launchagent', {
  script_path: script_path
})

# Define paths
user_home = ENV['HOME']
launch_agents_dir = File.join(user_home, 'Library/LaunchAgents')
plist_path = File.join(launch_agents_dir, 'com.macrouternas.blacklist.updater.plist')

# Create LaunchAgents directory if it doesn't exist
FileUtils.mkdir_p(launch_agents_dir) unless Dir.exist?(launch_agents_dir)

# Write the plist file
File.write(plist_path, plist_content)
FileUtils.chmod(0644, plist_path)

logger.info "LaunchAgent plist created at #{plist_path}"

# Unload the LaunchAgent if it's already loaded (to avoid errors)
logger.info "Unloading existing LaunchAgent (if any)..."
unload_cmd = "launchctl unload #{plist_path} 2>/dev/null || true"
system(unload_cmd)

# Load the LaunchAgent
logger.info "Loading LaunchAgent..."
load_cmd = "launchctl load #{plist_path}"
stdout, stderr, status = Open3.capture3(load_cmd)

if status.success?
  logger.info "LaunchAgent successfully loaded"
  logger.info "Blacklists will be updated automatically once a week"

  # Run the updater immediately
  logger.info "Running initial blacklist update..."
  system(script_path)
  
  logger.info "Blacklist updater installation complete"
else
  logger.error "Failed to load LaunchAgent: #{stderr}"
  exit 1
end