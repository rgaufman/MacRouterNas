#!/usr/bin/env ruby
# frozen_string_literal: true

# Logger configuration for MacRouter utilities
# Provides consistent logging setup across all scripts

require 'semantic_logger'

# Configure semantic logger
SemanticLogger.default_level = :info
SemanticLogger.add_appender(io: $stdout, formatter: :color)

module MacRouterUtils
  # Get a logger for a specific component
  def self.logger(component_name)
    SemanticLogger[component_name]
  end

  # Set verbose logging
  def self.enable_verbose_logging
    SemanticLogger.default_level = :debug
  end
end
