# MacRouterNas

A collection of Ruby utilities for setting up macOS as a router and NAS.

## Features

- **Network Address Translation (NAT)**: Configure your Mac to share its internet connection with devices connected to a secondary network interface
- **Port Forwarding**: Forward external ports to internal devices on your network
- **DNS Blacklists**: Block ads, trackers, and malware at the DNS level
- **DHCP/DNS**: Configure DNSMASQ for DHCP and DNS services
- **Static IP Mappings**: Easily add and remove static MAC to IP mappings
- **Caddy Server**: Set up Caddy as a reverse proxy for services like Seafile

## Todo

- **DynDNS & LetsEncrypt**: add support for getting a hostname and generating https certificates for it
- **Complete persistance**: the challenge is with PPPoE, the connection is initiated on login
- **Blacklist Auto-update**: Implemented but not yet tested
- **ZFS NAS**: Add support for setting up a NAS with ZFS (beyond just filesystem sharing)
- **UPnP**: Hacked miniupnpd to work on latest MacOS with Apple Silicon, but not well tested
- **IoT/Homekit**: Pick a dashboard / integration for smart home management
- **VPN Server**: Automate setup of OpenVPN and WireGuard
- **Immich**: Automate setup of Imich (Synology Photos replacement)
* **Seafile**: Automate setup of Seafile (Synology Drive replacement)
* **Incremental Backups**: Automate setup of Borg + Vorta or Duplicacy Web

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/MacRouterNas.git
   cd MacRouterNas
   ```

2. Install dependencies:
   ```
   bundle install
   ```

## Quick Start Guide

Here's the typical workflow to get everything running:

### 1. Set Up NAT & Router
First, configure your Mac as a router with NAT:

```bash
./setup_nat.rb --wan-interface en0 --lan-interface en8 --static-ip 192.168.1.1 --dhcp-range 192.168.1.11,192.168.1.249,12h
```

This sets up:
- NAT routing between WAN (en0) and LAN (en8)
- DHCP server on the LAN interface
- DNS server with dnsmasq

### 2. Set Up Digital Wellness Blocking
Configure time-based website blocking (optional but recommended):

```bash
sudo ./scripts/setup_blocking.rb
```

This configures:
- Permanent blocking of spam domains
- Time-based blocking of social media (YouTube, Instagram, X, Facebook)
- Default schedule: 5-7 PM weekdays, 12-8 PM Sunday
- See [BLOCKED_SITES.md](BLOCKED_SITES.md) for philosophy and reasoning

**Optional - Add Automatic Ad/Malware Blocking:**
```bash
# Download and activate ad/malware/tracker blacklists
sudo ./update_and_reload_blacklists.rb

# Schedule weekly automatic updates
sudo ./install_blacklist_updater.rb
```

This is SEPARATE from time-based blocking:
- **Automatic blacklist**: Always blocks ads, trackers, malware (StevenBlack, AdAway, etc.)
- **Scheduled blocking**: Time-based social media blocking
- Both work together independently

### 3. Start the Scheduled Blocker Daemon
Start the background daemon that manages time-based blocking:

```bash
sudo ./scripts/scheduled_blocker_ctl.rb start
```

### 4. Check Status
Verify everything is running:

```bash
# Check router/NAT status
./setup_nat.rb --status

# Check scheduled blocker status
sudo ./scripts/scheduled_blocker_ctl.rb status

# Check DHCP leases
./setup_nat.rb --list-dhcp-leases
```

### 5. View Logs
Monitor what's happening:

```bash
# View blocking logs
sudo ./scripts/scheduled_blocker_ctl.rb logs

# View internet downtime logs
sudo ./scripts/scheduled_blocker_ctl.rb downtime-logs

# View DNS queries (see what domains are being accessed)
sudo ./scripts/analyze_dns_queries.rb --show-devices
```

### 6. Manage Blocking Schedules
Add or modify blocking schedules:

```bash
# Add a custom schedule
sudo ./scripts/scheduled_blocker_ctl.rb add-schedule \
  --name "Gaming Sites" \
  --domains "twitch.tv,discord.com" \
  --weekday-allowed "18:00-20:00" \
  --saturday-allowed "14:00-18:00" \
  --sunday-allowed "12:00-20:00"

# List all schedules
sudo ./scripts/scheduled_blocker_ctl.rb list-schedules

# Remove a schedule (by name or index)
sudo ./scripts/scheduled_blocker_ctl.rb remove-schedule --name "Gaming Sites"
sudo ./scripts/scheduled_blocker_ctl.rb remove-schedule --index 0
```

### 7. Daemon Control
Manage the blocker daemon:

```bash
sudo ./scripts/scheduled_blocker_ctl.rb stop      # Stop the daemon
sudo ./scripts/scheduled_blocker_ctl.rb restart   # Restart the daemon
sudo ./scripts/scheduled_blocker_ctl.rb run       # Run in foreground (for testing)
```

### Common Workflows

**Daily Use:**
- Everything runs automatically once set up
- Websites are blocked/unblocked based on schedule
- Internet downtime is logged automatically
- DHCP assigns IPs to new devices automatically

**Troubleshooting:**
```bash
# If blocking isn't working
sudo ./scripts/scheduled_blocker_ctl.rb status
sudo brew services restart dnsmasq

# If NAT isn't working
./setup_nat.rb --status
sudo pfctl -s nat  # Check NAT rules

# Test DNS blocking manually
dig @127.0.0.1 youtube.com  # Should return 0.0.0.0 when blocked
```

**Customization:**
- Edit schedules using `scheduled_blocker_ctl.rb add-schedule`
- Modify defaults in `scripts/setup_blocking.rb`
- See [BLOCKED_SITES.md](BLOCKED_SITES.md) for philosophy

## Usage

### Setting up NAT and DHCP

```bash
# Basic setup with default settings
./setup_nat.rb --wan-interface en0 --lan-interface en5

# Custom setup with specific IP and DHCP range
./setup_nat.rb --wan-interface en0 --lan-interface en5 --static-ip 192.168.100.1 --dhcp-range 192.168.100.10,192.168.100.100,12h
```

The `--dhcp-range` parameter accepts values in the format `start_ip,end_ip,lease_time` where:
- `start_ip`: The first IP address in the DHCP range
- `end_ip`: The last IP address in the DHCP range
- `lease_time`: How long a DHCP lease is valid (can use suffixes: s for seconds, m for minutes, h for hours, d for days)

### Managing Static IP Mappings

```bash
# Add a static MAC to IP mapping
./setup_nat.rb --add-static-mapping AA:BB:CC:DD:EE:FF,device1,192.168.100.50

# List all static MAC to IP mappings
./setup_nat.rb --list-static-mappings

# Remove a static mapping by MAC address
./setup_nat.rb --remove-static-mapping AA:BB:CC:DD:EE:FF

# Remove a static mapping by device name
./setup_nat.rb --remove-static-mapping device1

# Remove a static mapping by IP address
./setup_nat.rb --remove-static-mapping 192.168.100.50
```

### Managing Port Forwarding

Port forwarding allows you to redirect traffic from your WAN interface to internal devices:

```bash
# Add a port forward (external_port,internal_ip,internal_port[,protocol])
# Protocol is optional and defaults to tcp if not specified
./setup_nat.rb --wan-interface ppp0 --add-port-forward 8080,192.168.100.10,80,tcp

# Add a port forward with UDP protocol
./setup_nat.rb --wan-interface ppp0 --add-port-forward 53,192.168.100.53,53,udp

# For both TCP and UDP on the same port, use the 'both' protocol option
./setup_nat.rb --wan-interface ppp0 --add-port-forward 8080,192.168.100.10,80,both

# List all configured port forwards
./setup_nat.rb --wan-interface ppp0 --list-port-forwards

# Remove a port forward (defaults to tcp if protocol not specified)
./setup_nat.rb --wan-interface ppp0 --remove-port-forward 8080

# Remove a UDP port forward
./setup_nat.rb --wan-interface ppp0 --remove-port-forward 8080,udp

# Remove both TCP and UDP port forwards for a port
./setup_nat.rb --wan-interface ppp0 --remove-port-forward 8080,both
```

Port forwarding can also be used to enable remote access to services like Plex:

```bash
# Forward external port 32400 to a Plex server
./setup_nat.rb --wan-interface ppp0 --add-port-forward 32400,192.168.100.10,32400,tcp
```

### Managing Services

```bash
# Check status of all services
./setup_nat.rb --status

# List available network interfaces
./setup_nat.rb --list-interfaces

# List active DHCP leases
./setup_nat.rb --list-dhcp-leases

# Show DNS cache statistics
./setup_nat.rb --dns-stats

# Flush DNS cache
./setup_nat.rb --flush-dns-cache

# Uninstall NAT configuration
./setup_nat.rb --uninstall

# Force configuration even if services are already running
./setup_nat.rb --wan-interface en0 --lan-interface en5 --force
```

### Setting up Caddy Server

```bash
# Basic setup with default settings
./setup_caddy.rb

# Custom setup with specific hostname
./setup_caddy.rb --hostname my.domain.com

# Force plain HTTP mode (no TLS)
./setup_caddy.rb --http

# Check status
./setup_caddy.rb --status

# Uninstall Caddy configuration
./setup_caddy.rb --uninstall
```

## Development

### Running Tests

```bash
bundle exec rspec
```

### Project Structure

- `utils/`: Shared utility classes
  - `system_manager.rb`: Base class for system operations
  - `launch_daemon_manager.rb`: LaunchDaemon management
  - `service_manager.rb`: Service management
  - `cli_base.rb`: Command-line interface base
  - `setup_base.rb`: Setup operations base
  - `network_utils.rb`: Network utilities
  - `template_renderer.rb`: ERB template rendering
  - `pf_manager.rb`: Packet Filter management
  - `port_forwards.rb`: Port forwarding management
  - `dnsmasq_manager.rb`: DNSMASQ configuration
  - `interface_manager.rb`: Network interface management
  - `sysctl_manager.rb`: Sysctl configuration
  - `update_blacklists.rb`: DNS blacklist management
- `templates/`: ERB templates
  - `caddyfile.erb`: Caddy server configuration
  - `launchdaemon.erb`: macOS service configuration
  - `pf_rules.erb`: Packet filter rules
  - `nat_launchdaemon.erb`: NAT service configuration
  - `dnsmasq_config.erb`: DHCP/DNS server configuration
  - `blacklist_updater_launchagent.erb`: Blacklist updater scheduling
- `blacklists/`: DNS blacklist files and whitelist
- `spec/`: Test files

## DNS-based Blocking for Ads, Tracking, and Spam

MacRouterNas includes powerful DNS-based blocking of ads, trackers, malware, and spam domains:

### How it Works

The DNS blacklist system uses dnsmasq to block unwanted domains:

1. The system downloads blacklists from multiple reputable sources
2. Blocked domains are redirected to 0.0.0.0 (which prevents connections)
3. The blacklists are automatically updated weekly

### DNS Interception and DoH Blocking

MacRouterNas automatically configures DNS interception and DNS-over-HTTPS (DoH) blocking to ensure all devices use the router's DNS filtering:

#### DNS Interception
All DNS queries (port 53) from LAN clients are automatically redirected to the local dnsmasq server. This ensures:
- No client can bypass DNS filtering by using external DNS servers (like 8.8.8.8)
- All DNS queries go through your blacklists and time-based blocking
- Even manually configured DNS servers on devices are intercepted

#### DoH Blocking
DNS-over-HTTPS (DoH) allows devices to bypass traditional DNS filtering by encrypting DNS queries through HTTPS (port 443). MacRouterNas blocks DoH connections to major public DNS providers:

**Blocked DoH Providers:**
- **Cloudflare**: 1.1.1.1, 1.0.0.1
- **Google**: 8.8.8.8, 8.8.4.4
- **Quad9**: 9.9.9.9, 149.112.112.112
- **OpenDNS**: 208.67.222.222, 208.67.220.220

This prevents modern browsers and apps (especially on iOS/Android) from circumventing your DNS filtering.

#### How It's Configured
These security features are automatically enabled when you run `./setup_nat.rb`:

```ruby
# Both are enabled by default in pf_manager.rb
enable_dns_intercept: true   # Redirects all port 53 traffic to local DNS
block_doh: true              # Blocks HTTPS to known DoH providers
```

#### Testing DNS Security

Verify DNS interception is working:
```bash
# From a LAN client, try to query Google DNS directly
dig @8.8.8.8 google.com
# Should fail or be redirected to local dnsmasq

# Query local DNS (should work)
dig @192.168.1.1 google.com
```

Verify DoH blocking is working:
```bash
# From a LAN client, try to connect to Cloudflare DoH
curl -v https://1.1.1.1
# Should timeout or be blocked
```

Check that blocked domains return 0.0.0.0:
```bash
# Query a blocked domain (when scheduled blocking is active)
dig @192.168.1.1 instagram.com
# Should return: instagram.com. 0 IN A 0.0.0.0
```

### Setting Up Ad Blocking

1. After setting up the main NAT/DHCP functionality, run:
   ```
   sudo ./update_and_reload_blacklists.rb
   ```

2. To schedule automatic weekly updates:
   ```
   sudo ./install_blacklist_updater.rb
   ```

### Customizing Blocked Content

You can whitelist domains that should never be blocked by editing:
```
blacklists/whitelist.txt
```

Add one domain per line. Comments start with #.

### Managing Blacklists

- **Update Blacklists**: `./update_and_reload_blacklists.rb`
- **View Current Blacklist Sources**: Check the `BLACKLIST_SOURCES` constant in `utils/update_blacklists.rb`
- **Add Custom Blacklists**: Edit the `BLACKLIST_SOURCES` hash in `utils/update_blacklists.rb`

### Blacklist Sources

By default, the system uses several reputable blacklists:
- StevenBlack Hosts (unified blacklist for ads, malware and more)
- AdAway (mobile-focused ad blocking)
- MalwareDomains (security threat blocking)
- Disconnect (privacy protection)
- Energized (comprehensive protection)

You can specify which sources to use with the `--sources` option when running `update_blacklists.rb` manually.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Plex Media Server

MacRouterNas can be used to set up Plex Media Server with port forwarding for remote access:

```bash
# Install Plex Media Server
brew install plex-media-server

# Launch Plex and follow the setup instructions
open /Applications/Plex\ Media\ Server.app

# Add port forwarding to enable remote access (replace with your local static IP)
./setup_nat.rb --wan-interface ppp0 --add-port-forward 32400,192.168.1.1,32400,tcp
```
