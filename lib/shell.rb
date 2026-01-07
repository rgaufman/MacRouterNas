#!/usr/bin/env ruby
# frozen_string_literal: true

require 'tty-command'

module MacRouterUtils
  # Shell command execution utility
  # Provides a clean API for running shell commands with proper error handling
  class Shell
    # Execute a shell command
    # By default, raises an exception on failure (fail loudly)
    # Set raise_on_failure: false to allow failures
    #
    # Returns: { success: boolean, stdout: string, stderr: string }
    #
    # Example:
    #   Shell.run('ls -la')                              # Raises on failure
    #   Shell.run('pgrep dnsmasq', raise_on_failure: false)  # Returns result even if fails
    def self.run(command, raise_on_failure: true)
      cmd = TTY::Command.new(printer: :null)
      result = cmd.run(command)
      { success: true, stdout: result.out, stderr: result.err }
    rescue TTY::Command::ExitError => e
      raise "Command failed: #{command}\nError: #{e.message}" if raise_on_failure

      { success: false, stdout: '', stderr: e.message }
    end
  end
end
