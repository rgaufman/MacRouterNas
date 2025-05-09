#!/usr/bin/env ruby
# frozen_string_literal: true

# CLI base class for MacRouter utilities
# Provides common command-line interface functionality

require 'optparse'
require_relative 'logger_config'

module MacRouterUtils
  class CLIBase
    attr_reader :options

    def initialize(default_options = {})
      @options = default_options
    end

    def add_common_options(opts)
      opts.on('-v', '--verbose', 'Enable verbose logging') do
        @options[:verbose] = true
        MacRouterUtils.enable_verbose_logging
      end

      opts.on('-s', '--status', 'Check current setup status') do
        @options[:status] = true
      end

      opts.on('-u', '--uninstall', 'Remove setup') do
        @options[:uninstall] = true
      end

      opts.on('-h', '--help', 'Show this help message') do
        puts opts
        exit
      end
    end

    def parse
      # To be implemented by subclasses
      raise NotImplementedError, 'Subclasses must implement parse method'
    end
  end
end
