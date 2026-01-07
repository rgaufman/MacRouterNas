# Instructions for Claude when working with this repository

## Critical Project Standards

### Code Quality and Linting
- **ALWAYS run rubocop after writing or modifying Ruby code**
- Run `bundle exec rubocop -A` to auto-correct style violations
- Fix any remaining offenses that cannot be auto-corrected
- Ensure specs still pass after rubocop corrections: `bundle exec rspec`
- Rubocop is configured to enforce consistent code style across the project
- Common corrections include:
  - String literal quotes (prefer single quotes)
  - Trailing whitespace removal
  - Proper indentation and spacing
  - Frozen string literal comments
- Only commit code that passes rubocop checks (metrics warnings like ClassLength are acceptable)

### Error Handling and Exit Codes
- **Commands raise by default** - The `shell()` method raises exceptions on failure automatically
- **Use raise_on_failure: false only when failures are expected**:
  ```ruby
  # Default behavior - raises on failure (GOOD!)
  shell("sudo cp file dest")

  # Only for commands that may legitimately fail
  shell("sudo pkill dnsmasq || true", raise_on_failure: false)
  shell("pgrep dnsmasq", raise_on_failure: false)  # May not be running
  ```
- **Never check [:success] when using default behavior** - The command already raised if it failed:
  ```ruby
  # WRONG - unnecessary check, command already raised if it failed
  result = shell("sudo cp file dest")
  raise "Failed" unless result[:success]

  # CORRECT - just run it, will raise automatically
  shell("sudo cp file dest")

  # CORRECT - only when you need the output
  result = shell("cat file")
  puts result[:stdout]
  ```
- Validate critical operations (like dnsmasq config) before applying them
- **Debugging principle**: Fail loudly by default, only suppress when intentional

### Clean Command Wrappers - Favor Ruby Over Shell Pipes

**Core Principles**:

1. **Avoid shell pipes** - Pipes hide errors, are hard to test, and obscure intent
   - BAD: `shell("ps aux | grep dnsmasq | grep -v grep")`
   - GOOD: `ProcessHelper.find_by_name('dnsmasq')`

2. **Create utility wrappers** for common operations:
   - `ProcessHelper` - Process management (pgrep, pid checking)
   - `FileGrep` - File searching and pattern matching
   - `LsofHelper` - Port and file descriptor inspection
   - `BrewServices` - Homebrew service management
   - `LaunchCtl` - LaunchDaemon/LaunchAgent management

3. **Wrappers should**:
   - Inherit from `SystemManager` to access `shell()` method
   - Use class methods for stateless operations
   - Return structured data (hashes/arrays) not raw strings
   - Handle parsing errors gracefully
   - Have comprehensive specs with real command output examples

4. **Process data in Ruby** - Use Ruby's superior string/array processing instead of bash
   - Use `select`, `map`, `reject`, `split`, `match` etc.
   - Easier to test, debug, and understand

5. **Wrapper files location**: Place in `lib/` directory (e.g., `lib/process_helper.rb`)

6. **When pipes ARE acceptable**:
   - One-time diagnostic scripts in `scripts/` directory
   - When creating a wrapper would be more complex than the pipe itself
   - Even then, if used more than once, create a wrapper

### Logging
- **NEVER write logs to `/var/log/`** - This requires sudo and is a system directory
- **ALWAYS use `./log/` directory** - Project-local, auto-created, no permissions needed
- Example: `LOG_FILE = File.expand_path('../../log', __dir__) + '/app.log'`
- Ensure log directory exists: `FileUtils.mkdir_p(LOG_DIR) unless Dir.exist?(LOG_DIR)`

### Parameter Parsing
- **ALL scripts with arguments MUST use optparse** - No raw ARGV manipulation
- Provide `--help` for every command
- Use consistent patterns across all scripts
- Example structure:
  ```ruby
  options = {}
  OptionParser.new do |opts|
    opts.banner = "Usage: script.rb [options]"
    opts.on('-n', '--name NAME', 'Description') { |v| options[:name] = v }
    opts.on('-h', '--help', 'Show help') { puts opts; exit }
  end.parse!
  ```

### Scheduled Blocker System
- Default allowed times: **17:00-19:00** (5-7 PM) for weekdays
- Separate parameters for: `weekday_allowed`, `saturday_allowed`, `sunday_allowed`
- Saturday is NOT automatically blocked (Shabbat observance is user-configurable)
- Logs to `./log/scheduled_blocker.log` and `./log/internet_downtime.log`
- Uses gems: rufus-scheduler, holidays, activesupport, daemons, tty-command
- See `BLOCKED_SITES.md` for philosophy and reasoning

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

### CRITICAL: pfctl -f FLUSHES ALL RULES

**This is an extremely dangerous pitfall that can break your entire network configuration!**

When you run `pfctl -f /path/to/rules.conf`, it does NOT merge or add rules - it **FLUSHES ALL EXISTING RULES** and replaces them with only what's in that file!

**Example of the bug:**
```ruby
# Load complete NAT rules (has NAT, rdr, filter, scrub rules)
shell("sudo pfctl -f /usr/local/etc/MacRouterNas/nat_rules.conf")  # All rules loaded ✓

# Later, try to "fix" missing MSS clamping rule
shell("sudo pfctl -f /usr/local/etc/MacRouterNas/mss_clamp_rule.conf")  # DISASTER! ✗
# This FLUSHES all NAT, rdr, and filter rules, leaving ONLY the scrub rule!
```

**The fix:**
- ALWAYS reload the COMPLETE rule file that contains ALL your rules
- NEVER use `pfctl -f` with a partial file containing only some rules

```ruby
# WRONG - This will flush all other rules!
shell("sudo pfctl -f /usr/local/etc/MacRouterNas/mss_clamp_rule.conf")  # Only has scrub

# CORRECT - Reload the complete file
shell("sudo pfctl -f /usr/local/etc/MacRouterNas/nat_rules.conf")  # Has all rules
```

**This has been documented in:**
1. Code comments in `utils/pf_manager.rb` (lines 285-287, 317-319, 518-520)
2. Template comments in `templates/nat_launchdaemon.erb` (lines 27-28)
3. This documentation section

**Favor Ruby parsing over shell pipes:**
- BAD: `shell("sudo pfctl -sa | grep 'max-mss'")`  - Hides timing issues
- GOOD: Use the `mss_clamping_rule_loaded?` helper method that parses output in Ruby

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

### PF Rule Directions: Critical Understanding

**CRITICAL**: The most common mistake with PF rules is using the wrong direction (in vs out). Understanding packet flow is essential.

#### Packet Flow Direction
When traffic flows from LAN clients through the router:
```
LAN client → (IN) → LAN interface (en8) → router → (OUT) → WAN interface (en0) → Internet
```

#### Rule Direction Guidelines
- **"in"** = traffic coming INTO the interface
- **"out"** = traffic leaving FROM the interface
- **For blocking LAN client traffic**: Use "in" on the LAN interface (NOT "out")
- **Why**: Traffic from LAN clients comes IN to the LAN interface before routing

#### Common Mistakes and Fixes

**WRONG** - Using "out" on LAN interface:
```
# This will NOT work - traffic from LAN clients comes IN, not out
block drop out quick on en8 proto tcp from 192.168.1.0/24 to 8.8.8.8 port 443
```

**CORRECT** - Using "in" on LAN interface:
```
# This works - traffic from LAN clients comes IN to the LAN interface
block drop in quick on en8 proto tcp from 192.168.1.0/24 to 8.8.8.8 port 443
```

**WRONG** - Blocking on WAN interface after NAT:
```
# This will NOT work - NAT changes the source IP before the packet reaches WAN
block drop out quick on en0 proto tcp from 192.168.1.0/24 to 8.8.8.8 port 443
```

#### Why Block Rules Must Be on LAN Interface
1. **NAT changes source IP**: After NAT, the source IP is the WAN interface IP, not the LAN client IP
2. **Filter before NAT**: Block rules must filter BEFORE NAT translation occurs
3. **LAN interface sees original traffic**: The LAN interface sees the original source IP from clients

#### DNS Interception and DoH Blocking
For DNS interception and DoH (DNS over HTTPS) blocking:

```
# DNS interception - redirect on LAN interface where traffic enters
rdr pass on en8 inet proto udp from any to any port 53 -> 127.0.0.1 port 53

# Block direct DNS - block IN on LAN interface before NAT
block drop in quick on en8 proto udp from 192.168.1.0/24 to any port 53

# Block DoH to Cloudflare - block IN on LAN interface before NAT
block drop in quick on en8 proto tcp from 192.168.1.0/24 to 1.1.1.1 port 443
```

#### PF Rule Order
PF processes rules in this order:
1. **scrub** - packet normalization (MSS clamping, etc.)
2. **rdr/nat** - address translation (NAT, port forwarding, DNS interception)
3. **filter** - allow/block rules

**Always maintain this order** in your rule files, or PF will reject them with "Rules must be in order" error.

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