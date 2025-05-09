#!/usr/bin/env ruby
# frozen_string_literal: true

# LaunchDaemon manager for MacRouter utilities
# Provides functionality for managing macOS LaunchDaemons

require_relative 'system_manager'
require_relative 'template_renderer'
require 'tempfile'

module MacRouterUtils
  class LaunchDaemonManager < SystemManager
    attr_reader :plist_path

    def initialize(service_name, paths = {})
      @service_name = service_name
      @plist_path = paths[:plist_path] || "/Library/LaunchDaemons/#{service_name}.plist"
      @stdout_log = paths[:stdout_log] || "/var/log/#{service_name}.out"
      @stderr_log = paths[:stderr_log] || "/var/log/#{service_name}.err"
      @logger = SemanticLogger["#{service_name.capitalize}LaunchDaemon"]
    end

    def generate_plist(program_arguments = nil)
      renderer = MacRouterUtils::TemplateRenderer.new

      variables = {
        label: @service_name,
        program_arguments: program_arguments || [@caddy_bin, 'run', '--config', @caddyfile_path],
        stdout_log: @stdout_log,
        stderr_log: @stderr_log
      }

      renderer.render('launchdaemon', variables)
    end

    def install(plist_content)
      if File.exist?(@plist_path)
        @logger.info('Unloading existing LaunchDaemon...')
        system("sudo launchctl bootout system #{@plist_path}")
      end

      Tempfile.create("#{@service_name}.plist") do |f|
        f.write(plist_content)
        f.flush
        @logger.info("Writing new plist to #{@plist_path}...")
        system("sudo cp #{f.path} #{@plist_path}")
      end

      system("sudo chown root:wheel #{@plist_path}")
      system("sudo chmod 644 #{@plist_path}")
      true
    end

    def uninstall
      if File.exist?(@plist_path)
        @logger.info('Unloading LaunchDaemon...')
        system("sudo launchctl bootout system #{@plist_path}")
        @logger.info('Removing LaunchDaemon plist...')
        system("sudo rm #{@plist_path}")
        true
      else
        @logger.info("No LaunchDaemon plist found at #{@plist_path}.")
        false
      end
    end

    def exists?
      File.exist?(@plist_path)
    end

    def loaded?
      system("sudo launchctl list #{@service_name} &>/dev/null")
    end
  end
end
