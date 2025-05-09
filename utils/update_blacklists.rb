#!/usr/bin/env ruby
# frozen_string_literal: true

# Script to download and prepare DNS blacklists for dnsmasq
# This script fetches popular blacklists, processes them, and creates a dnsmasq-compatible format

require 'open-uri'
require 'fileutils'
require 'set'

class BlacklistUpdater
  BLACKLIST_DIR = File.expand_path('../blacklists', __dir__)
  BLACKLIST_SOURCES = {
    'stevenblack' => 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'adaway' => 'https://adaway.org/hosts.txt',
    'malwaredomains' => 'https://mirror1.malwaredomains.com/files/justdomains',
    'disconnect' => 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt',
    'energized' => 'https://block.energized.pro/basic/formats/domains.txt'
  }
  
  WHITELIST = [
    'localhost',
    'localhost.localdomain',
    'local',
    'broadcasthost',
    'ip6-localhost',
    'ip6-loopback',
    'ip6-localnet',
    'ip6-mcastprefix',
    'ip6-allnodes',
    'ip6-allrouters',
    'ip6-allhosts'
  ]

  def initialize(options = {})
    @verbose = options[:verbose] || false
    @sources = options[:sources] || BLACKLIST_SOURCES.keys
    @output_file = options[:output_file] || File.join(BLACKLIST_DIR, 'dnsmasq.blacklist')
    @whitelist_file = options[:whitelist_file]
    
    FileUtils.mkdir_p(BLACKLIST_DIR) unless Dir.exist?(BLACKLIST_DIR)
  end
  
  def update
    puts "Updating blacklists..." if @verbose
    
    # Download and process each source
    all_domains = Set.new
    
    @sources.each do |source|
      url = BLACKLIST_SOURCES[source]
      if url.nil?
        puts "Unknown source: #{source}" if @verbose
        next
      end
      
      puts "Downloading #{source} from #{url}..." if @verbose
      
      begin
        domains = download_and_parse(url)
        puts "  Found #{domains.size} domains" if @verbose
        all_domains.merge(domains)
      rescue StandardError => e
        puts "  Error downloading #{source}: #{e.message}" if @verbose
      end
    end
    
    # Add user whitelist if provided
    if @whitelist_file && File.exist?(@whitelist_file)
      user_whitelist = File.readlines(@whitelist_file).map(&:strip).reject { |line| line.empty? || line.start_with?('#') }
      puts "Added #{user_whitelist.size} domains from user whitelist" if @verbose
      WHITELIST.concat(user_whitelist)
    end
    
    # Remove whitelisted domains
    WHITELIST.each { |domain| all_domains.delete(domain) }
    
    # Write to dnsmasq format
    write_dnsmasq_format(all_domains)
    
    puts "Done! Blacklist updated with #{all_domains.size} domains" if @verbose
    puts "Output file: #{@output_file}" if @verbose
  end
  
  private
  
  def download_and_parse(url)
    domains = Set.new
    
    URI.open(url) do |file|
      file.each_line do |line|
        line = line.strip.downcase
        
        # Skip comments and empty lines
        next if line.empty? || line.start_with?('#')
        
        # Extract domain from hosts file format or plain domain list
        domain = if line.include?(' ')
                   parts = line.split(/\s+/)
                   parts[1] if parts.size > 1 && !%w[localhost broadcasthost].include?(parts[1])
                 else
                   line unless line.include?('/') # Skip any URL paths
                 end
        
        # Add if it looks like a valid domain
        domains.add(domain) if domain && domain.include?('.') && !domain.start_with?('0.0.0.0') && !domain.start_with?('127.0.0.1')
      end
    end
    
    domains
  end
  
  def write_dnsmasq_format(domains)
    File.open(@output_file, 'w') do |file|
      file.puts "# Blacklist generated on #{Time.now}"
      file.puts "# Total domains: #{domains.size}"
      file.puts
      
      domains.each do |domain|
        file.puts "address=/#{domain}/0.0.0.0"
      end
    end
  end
end

# When run directly
if __FILE__ == $PROGRAM_NAME
  require 'optparse'
  
  options = {
    verbose: false,
    sources: BlacklistUpdater::BLACKLIST_SOURCES.keys
  }
  
  OptionParser.new do |opts|
    opts.banner = "Usage: update_blacklists.rb [options]"
    
    opts.on("-v", "--verbose", "Run verbosely") do |v|
      options[:verbose] = v
    end
    
    opts.on("-s", "--sources SOURCE1,SOURCE2", Array, "Specific sources to use") do |s|
      options[:sources] = s
    end
    
    opts.on("-o", "--output FILE", "Output file path") do |o|
      options[:output_file] = o
    end
    
    opts.on("-w", "--whitelist FILE", "Path to whitelist file") do |w|
      options[:whitelist_file] = w
    end
    
    opts.on("-h", "--help", "Show this help") do
      puts opts
      exit
    end
  end.parse!
  
  updater = BlacklistUpdater.new(options)
  updater.update
end