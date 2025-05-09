#!/usr/bin/env ruby
# frozen_string_literal: true

# Caddy Setup Utility for Seafile
# ===============================
#
# This script sets up Caddy as a reverse proxy for a Seafile server on macOS.
# It configures Caddy to proxy requests to the Seafile web interface (port 8080)
# and the Seafile file transfer service (port 8082).
#
# The script:
# - Creates and validates a Caddyfile configuration
# - Sets up a macOS LaunchDaemon to run Caddy as a system service
# - Manages the Caddy service (start/reload/stop)
#
# Usage examples:
#   ./setup_caddy.rb                      # Install with default settings
#   ./setup_caddy.rb --hostname my.domain # Install with custom hostname
#   ./setup_caddy.rb --status             # Check current Caddy status
#   ./setup_caddy.rb --uninstall          # Remove Caddy setup

require_relative 'utils'

# Class to handle command-line interface for Caddy setup
class CaddyCLI < MacRouterUtils::CLIBase
  def initialize
    super({
      hostname: 'seafile.local',
      plain_http: false,
      status: false,
      uninstall: false,
      verbose: false
    })
  end

  def parse
    OptionParser.new do |opts|
      opts.banner = "Usage: #{File.basename($PROGRAM_NAME)} [options]"

      opts.on('-H', '--hostname NAME', 'Primary hostname for the Caddy site') do |h|
        @options[:hostname] = h
      end

      opts.on('-P', '--http', 'Force plain HTTP mode (no TLS, bind to :80)') do
        @options[:plain_http] = true
      end

      # Add common options (status, uninstall, verbose, help)
      add_common_options(opts)
    end.parse!

    @options
  end
end

# Class to handle Caddyfile configuration
class CaddyConfig < MacRouterUtils::SystemManager
  attr_reader :caddyfile_path, :access_log_path, :caddy_bin

  def initialize(hostname, plain_http, paths = {})
    @hostname = hostname
    @plain_http = plain_http
    @caddyfile_path = paths[:caddyfile] || '/etc/caddy/Caddyfile'
    @access_log_path = paths[:access_log] || '/var/log/caddy-access.log'
    @caddy_bin = paths[:caddy_bin] || '/opt/homebrew/bin/caddy'
    @logger = SemanticLogger['CaddyConfig']
  end

  def generate
    proto = @plain_http ? 'http' : 'https'
    tls_line = !@plain_http && @hostname.end_with?('.local') ? 'tls internal' : ''
    site_block_name = @plain_http ? ':80' : @hostname

    renderer = MacRouterUtils::TemplateRenderer.new

    variables = {
      plain_http: @plain_http,
      tls_line: tls_line,
      site_block_name: site_block_name,
      access_log_path: @access_log_path,
      proto: proto
    }

    renderer.render('caddyfile', variables)
  end

  def update
    expected = generate

    if !File.exist?(@caddyfile_path) || File.read(@caddyfile_path) != expected
      @logger.info("Writing Caddyfile to #{@caddyfile_path}...")
      FileUtils.mkdir_p(File.dirname(@caddyfile_path))
      File.write(@caddyfile_path, expected)
      @logger.info('Formatting Caddyfile...')
      system(@caddy_bin, 'fmt', '--overwrite', @caddyfile_path)
      true
    else
      @logger.info('Caddyfile is up to date.')
      false
    end
  end

  def validate
    @logger.info('Validating Caddyfile syntax...')
    result = system(@caddy_bin, 'validate', '--config', @caddyfile_path)

    unless result
      @logger.error('Caddyfile validation failed — aborting.')
      exit 1
    end

    result
  end

  def remove
    if File.exist?(@caddyfile_path)
      @logger.info("Removing Caddyfile at #{@caddyfile_path}...")
      FileUtils.rm(@caddyfile_path)
      true
    else
      @logger.info("No Caddyfile found at #{@caddyfile_path}.")
      false
    end
  end

  def exists?
    File.exist?(@caddyfile_path)
  end
end

# Class to interact with the Caddy service
class CaddyService < MacRouterUtils::ServiceManager
  def initialize(paths = {})
    @caddyfile_path = paths[:caddyfile] || '/etc/caddy/Caddyfile'
    @caddy_bin = paths[:caddy_bin] || '/opt/homebrew/bin/caddy'
    super('com.caddy.server', paths)
  end

  def reload
    if running?
      @logger.info('Reloading Caddy with new config...')
      result = system(@caddy_bin, 'reload', '--config', @caddyfile_path)

      unless result
        @logger.error('Caddy reload failed — aborting.')
        exit 1
      end

      result
    else
      @logger.warn('Caddy is not running, cannot reload.')
      false
    end
  end
end

# Main class to orchestrate the Caddy setup process
class CaddySetup < MacRouterUtils::SetupBase
  def initialize(options)
    super
    @paths = {
      caddyfile: '/etc/caddy/Caddyfile',
      access_log: '/var/log/caddy-access.log',
      plist_path: '/Library/LaunchDaemons/com.caddy.server.plist',
      caddy_bin: '/opt/homebrew/bin/caddy',
      stdout_log: '/var/log/caddy.out',
      stderr_log: '/var/log/caddy.err'
    }
    @logger = SemanticLogger['CaddySetup']

    @config = CaddyConfig.new(
      @options[:hostname],
      @options[:plain_http],
      @paths
    )

    @daemon_manager = MacRouterUtils::LaunchDaemonManager.new('com.caddy.server', @paths)
    @service = CaddyService.new(@paths)
  end

  def check_status
    @logger.info('Checking Caddy setup status...')

    config_exists = @config.exists?
    daemon_exists = @daemon_manager.exists?
    daemon_loaded = @daemon_manager.loaded?
    service_running = @service.running?

    @logger.info("Caddyfile exists: #{config_exists}")
    @logger.info("LaunchDaemon plist exists: #{daemon_exists}")
    @logger.info("LaunchDaemon loaded: #{daemon_loaded}")
    @logger.info("Caddy service running: #{service_running}")

    if config_exists && daemon_exists && daemon_loaded && service_running
      @logger.info("✅ Caddy is fully set up and running for hostname #{@options[:hostname]}.")
    else
      @logger.warn('⚠️ Caddy setup is incomplete or not running.')
    end
  end

  def install
    @logger.info("Setting up Caddy for hostname #{@options[:hostname]}...")

    config_updated = @config.update
    @config.validate

    @daemon_manager.install(generate_plist)

    if @service.running? && config_updated
      @service.reload
    else
      @service.start
    end

    @logger.info("✅ Setup complete for hostname #{@options[:hostname]}.")
  end

  def uninstall
    @logger.info('Uninstalling Caddy setup...')

    @service.stop
    @daemon_manager.uninstall
    @config.remove

    @logger.info('✅ Caddy has been uninstalled.')
  end

  private

  def generate_plist
    program_arguments = [
      @paths[:caddy_bin],
      'run',
      '--config',
      @paths[:caddyfile]
    ]

    @daemon_manager.generate_plist(program_arguments)
  end
end

# Main execution
begin
  logger = MacRouterUtils.logger('CaddySetup')
  cli = CaddyCLI.new
  options = cli.parse

  setup = CaddySetup.new(options)
  setup.run
rescue StandardError => e
  logger.error("Error: #{e.message}")
  logger.debug(e.backtrace.join("\n"))
  exit 1
end
