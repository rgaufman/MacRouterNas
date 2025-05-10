#!/usr/bin/env ruby
# frozen_string_literal: true

# This script fixes the syntax errors in the dnsmasq_manager.rb file

require 'fileutils'

DNSMASQ_FILE = '/Volumes/980Pro/home/hackeron/Development/MacRouterNas/utils/dnsmasq_manager.rb'

# Create a backup of the original file
backup_file = "#{DNSMASQ_FILE}.bak"
FileUtils.cp(DNSMASQ_FILE, backup_file)
puts "Created backup: #{backup_file}"

# Read the file content
content = File.read(DNSMASQ_FILE)

# Fix the verify_running method
content.gsub!(/      # Return false - DNSMASQ is not running\n      false\n\n          # Step 4: Detailed diagnostics/, 
              "      # Return false - DNSMASQ is not running\n      false\n    end\n    \n    # Detailed diagnostics method\n    def detailed_diagnostics")

# Fix process_static_mappings method
content = content.gsub(/(          end\n\n          logger.warn "No matching mapping found for: \#{mapping_spec}" unless removed\n        end)/, 
                        "\\1\n      end")

# Write the fixed content back to the file
File.write(DNSMASQ_FILE, content)
puts "Fixed syntax errors in #{DNSMASQ_FILE}"

# Fix the MSS clamping value in PF manager
PF_MANAGER_FILE = '/Volumes/980Pro/home/hackeron/Development/MacRouterNas/utils/pf_manager.rb'
pf_content = File.read(PF_MANAGER_FILE)

# Update MSS clamping value from 1440 to 1452
pf_content.gsub!('scrub out on #{@wan} proto tcp all max-mss 1440', 
                 'scrub out on #{@wan} proto tcp all max-mss 1452')

# Write the updated content back to the file
File.write(PF_MANAGER_FILE, pf_content)
puts "Updated MSS clamping value to 1452 in #{PF_MANAGER_FILE}"

# Update template file
TEMPLATE_FILE = '/Volumes/980Pro/home/hackeron/Development/MacRouterNas/templates/nat_launchdaemon.erb'
template_content = File.read(TEMPLATE_FILE)

# Update MSS clamping value in template
template_content.gsub!('scrub out on <%= @wan_interface %> proto tcp all max-mss 1440', 
                       'scrub out on <%= @wan_interface %> proto tcp all max-mss 1452')

# Write the updated content back to the file
File.write(TEMPLATE_FILE, template_content)
puts "Updated MSS clamping value to 1452 in #{TEMPLATE_FILE}"

puts "All fixes have been applied successfully!"