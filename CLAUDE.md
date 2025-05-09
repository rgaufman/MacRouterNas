# Instructions for Claude when working with this repository

## General Coding Guidelines

### Using Templates
1. Always use ERB templates for configuration files and plist files
2. Place templates in the `./templates` directory
3. Use the MacRouterUtils::TemplateRenderer class to render templates
4. Never use inline template strings for complex configuration files
5. Templates should have descriptive names and .erb extension

Example:
```ruby
# DO NOT do this:
plist_content = <<~XML
<?xml version="1.0" encoding="UTF-8"?>
...
XML

# INSTEAD do this:
# 1. Create a template file in ./templates/my_template.erb
# 2. Use the template renderer:
renderer = MacRouterUtils::TemplateRenderer.new
variables = { key: value }
content = renderer.render('my_template', variables)
```

## NAT Configuration for macOS - Working Solution Guide

### What works:
1. The direct approach that successfully enables NAT:
   ```bash
   sudo pfctl -d
   sudo pfctl -F all
   echo "nat on ppp0 from 192.168.1.0/24 to any -> (ppp0)" > /tmp/nat_rule
   sudo pfctl -f /tmp/nat_rule
   sudo pfctl -e
   ```

2. This simple approach correctly configures NAT without using complex anchor setups or modifying the main pf.conf.

## Command Output Handling

### Always Run Commands to Understand Output
1. NEVER assume the output format of system commands
2. Always run the command first and capture its actual output
3. Document several examples of output with different configurations
4. Write tests with real-world examples, not assumed formats

### Interface Detection Guidelines
1. Different interface types have different status indicators
2. Ethernet interfaces use "status: active" in ifconfig output
3. PPP interfaces require checking for RUNNING flag AND an IP address
4. Always add test cases for different interface types

#### PPP Interface Detection Examples
```
# Active PPP interface (has both RUNNING flag and IP address)
ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1492
    inet 100.66.91.122 --> 203.134.4.189 netmask 0xff000000
    inet6 fe80::d211:e5ff:fe88:7787%ppp0 prefixlen 64 scopeid 0x19
    nd6 options=201<PERFORMNUD,DAD>

# PPP interface with RUNNING flag but no IP (not fully active)
ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1492
    inet6 fe80::d211:e5ff:fe88:7787%ppp0 prefixlen 64 scopeid 0x19
    nd6 options=201<PERFORMNUD,DAD>

# Inactive PPP interface (no RUNNING flag)
ppp0: flags=8050<POINTOPOINT,MULTICAST> mtu 1492
    nd6 options=201<PERFORMNUD,DAD>
```

#### PPP Interface Detection Code
```ruby
# For PPP interfaces, check for RUNNING flag and IP address
has_running = result[:stdout].include?('RUNNING')
has_ip = result[:stdout].match(/inet\s+\d+\.\d+\.\d+\.\d+/) ? true : false
status[:active] = has_running && has_ip

# Also extract destination address if present (specific to PPP)
dst_match = result[:stdout].match(/-->\s+(\d+\.\d+\.\d+\.\d+)/)
status[:destination] = dst_match[1] if dst_match
```

### For PF Commands in Particular:
```bash
# Example real output from pfctl -s info
sudo pfctl -s info
# Status: Enabled
# Debug: Urgent
# Hostid: 0x0
# ...

# Example real output from pfctl -s nat
sudo pfctl -s nat
# nat on ppp0 inet from 192.168.1.0/24 to any -> (ppp0) round-robin

# Example from pfctl -s all | grep nat
sudo pfctl -s all | grep nat
# No ALTQ support in kernel
# ALTQ related functions disabled
# nat on ppp0 inet from 192.168.1.0/24 to any -> (ppp0) round-robin
```

### Testing Command Output Parsers:
1. Create test cases for each variant of output format
2. Test both success and error cases
3. Include tests for unusual formatting and empty output
4. When formats change across macOS versions, expand tests to handle all versions

### What doesn't work:
1. Using PF anchors and trying to add references to them in pf.conf
2. Using complex NAT rules or syntax (match out on, nat-to, etc.)
3. Using modified PF syntax for newer macOS versions
4. Trying to modify the main pf.conf file directly
5. Any attempt to use the following commands:
   - `sudo pfctl -a com.macrouternas -f /etc/pf.anchors/com.macrouternas`
   - Complex configurations with scrub-anchor, nat-anchor, rdr-anchor
6. Using `ipfw` commands (no longer available in modern macOS)
7. Trying to use the Internet Sharing preferences directly

### Guidelines for future NAT setup:
1. Keep PF rules extremely simple
2. Use the working direct approach that loads a single NAT rule
3. Always disable PF completely before applying new rules
4. Flush all rules before applying new ones
5. Use the exact NAT rule syntax that's known to work
6. Don't try to modify system files or use approaches designed for older macOS versions
7. The NAT rule must be in its own file, not part of a larger configuration

### Troubleshooting:
If NAT stops working after a restart or system changes:
1. Run the exact working commands listed above
2. If there are issues, check:
   - The WAN interface name may have changed
   - The LAN subnet may have changed (but 192.168.1.0/24 works reliably)
   - PF may have been disabled or reconfigured by another process

### Script Implementation:
When implementing NAT in the script, use this approach:
```ruby
# Step 1: Create the NAT rule file with MSS clamping for PPP interfaces
# Important: The scrub rule must come BEFORE the NAT rule per PF requirements
nat_rule = <<~RULES
  # TCP MSS clamping to fix issues with PPP and HTTPS connections
  scrub out on #{wan_interface} proto tcp all max-mss 1440

  # NAT rule for routing traffic
  nat on #{wan_interface} from 192.168.1.0/24 to any -> (#{wan_interface})
RULES

tmp_nat_rule = '/tmp/nat_rule'
File.write(tmp_nat_rule, nat_rule)

# Step 2: Use the exact commands that we know work
# Flush NAT rules while keeping PF enabled
execute_command_with_output("sudo pfctl -F nat")

# Load the NAT rule that we know works
execute_command_with_output("sudo pfctl -f #{tmp_nat_rule}")

# Enable PF if needed
execute_command_with_output("sudo pfctl -e || true")
```

### MSS Clamping for PPP Interfaces

When using a PPP interface (like ppp0), you may encounter issues with certain HTTPS websites that hang or timeout. This is usually due to packet fragmentation issues caused by the lower MTU of PPP interfaces.

To solve this, always add an MSS clamping rule when using PPP interfaces:

```
# TCP MSS clamping for PPP interfaces (PF rule syntax)
scrub out on ppp0 proto tcp all max-mss 1440
```

This rule ensures that TCP connections have their MSS (Maximum Segment Size) clamped to a value that works with the MTU of PPP interfaces, preventing fragmentation issues.

### Testing NAT:
To verify NAT is working:
1. Check if the NAT rule is loaded: `sudo pfctl -s nat`
2. Try pinging from a client device on the LAN to an external address (e.g., 8.8.8.8)
3. Try accessing a website from a client device

## DNS Blacklist Usage Guidelines

### Terminology
IMPORTANT: Always use the term "blacklist" (not "blocklist", "denylist", or other alternatives) in all code, comments, documentation, and templates. This applies to:
- File names (e.g., dnsmasq.blacklist, update_blacklists.rb)
- Class names (e.g., BlacklistUpdater)
- Variable names (e.g., @blacklist_file, blacklist_dir)
- Constants (e.g., BLACKLIST_SOURCES)
- User-facing messages (e.g., "Updating DNS blacklists")

The blacklist functionality blocks ads, trackers, and malicious domains by redirecting them to 0.0.0.0 in the DNS resolver.

### File Permissions
When writing configuration files or blacklists to system locations:
1. Always use sudo when writing to system directories like /opt/homebrew/etc/
2. Write to a temporary file first, then use sudo to copy it to the final location
3. Ensure proper permissions (644) for configuration files

Example:
```ruby
# Generate the config content
config_content = generate_config()

# Write to a temporary file first
temp_file = "/tmp/config_#{Process.pid}.conf"
File.write(temp_file, config_content)

# Use sudo to copy to the final location
execute_command("sudo cp #{temp_file} /opt/homebrew/etc/final.conf")
execute_command("sudo chmod 644 /opt/homebrew/etc/final.conf")

# Clean up the temporary file
File.unlink(temp_file) if File.exist?(temp_file)
```