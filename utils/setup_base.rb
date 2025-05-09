#!/usr/bin/env ruby
# frozen_string_literal: true

# Setup base class for MacRouter utilities
# Provides common setup functionality

require 'semantic_logger'

module MacRouterUtils
  class SetupBase
    include SemanticLogger::Loggable

    def initialize(options)
      @options = options
    end

    def run
      if @options[:status]
        check_status
      elsif @options[:uninstall]
        uninstall
      else
        install
      end
    end

    # These methods should be implemented by subclasses
    def check_status
      raise NotImplementedError, 'Subclasses must implement check_status method'
    end

    def install
      raise NotImplementedError, 'Subclasses must implement install method'
    end

    def uninstall
      raise NotImplementedError, 'Subclasses must implement uninstall method'
    end
  end
end
