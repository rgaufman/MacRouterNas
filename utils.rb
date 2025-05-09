#!/usr/bin/env ruby
# frozen_string_literal: true

# MacRouter Utilities
# ==================
#
# This file is the main entry point for MacRouter utilities.
# It requires all the individual utility files.

# Load all utility files
require_relative 'utils/logger_config'
require_relative 'utils/system_manager'
require_relative 'utils/launch_daemon_manager'
require_relative 'utils/service_manager'
require_relative 'utils/cli_base'
require_relative 'utils/setup_base'
require_relative 'utils/network_utils'
require_relative 'utils/template_renderer'
require_relative 'utils/pf_manager'
require_relative 'utils/dnsmasq_manager'
require_relative 'utils/interface_manager'
require_relative 'utils/sysctl_manager'

# MacRouterUtils module provides access to all utility classes and functions
module MacRouterUtils
  # Version of the utilities
  VERSION = '1.0.0'

  # Returns the version of the utilities
  def self.version
    VERSION
  end
end
