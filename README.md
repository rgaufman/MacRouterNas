# MacRouterNas

A collection of Ruby utilities for setting up macOS as a router and NAS.

## Features

- **Network Address Translation (NAT)**: Configure your Mac to share its internet connection with devices connected to a secondary network interface
- **DHCP Server Only Mode**: Set up just a DHCP server without NAT for network environments where routing is handled separately
- **NAT Only Mode**: Configure just NAT without DHCP (works alongside Internet Sharing)
- **Caddy Server**: Set up Caddy as a reverse proxy for services like Seafile
- **DHCP/DNS**: Configure DNSMASQ for DHCP and DNS services
- **Static IP Mappings**: Easily add and remove static MAC to IP mappings

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

## Usage

### Setting up NAT

```bash
# Basic setup with default settings
./setup_nat.rb --wan-interface en0 --lan-interface en5

# Custom setup with specific IP and DHCP range
./setup_nat.rb --wan-interface en0 --lan-interface en5 --static-ip 192.168.100.1 --dhcp-range 192.168.100.10,192.168.100.100,12h

# Add static MAC to IP mapping
./setup_nat.rb --add-static-mapping AA:BB:CC:DD:EE:FF,device1,192.168.100.50
```

### Setting up DHCP-only Mode

Use the `--only-dhcp` flag to set up just a DHCP server without NAT functionality. This is useful when you want to use your Mac as a DHCP server in a network where routing is handled by another device.

```bash
# Basic DHCP-only setup with custom IP range and 4-hour lease time
./setup_nat.rb --only-dhcp --lan-interface en5 --static-ip 192.168.1.1 --dhcp-range 192.168.1.11,192.168.1.249,4h

# DHCP-only setup with default settings
./setup_nat.rb --only-dhcp --lan-interface en5

# Uninstall DHCP-only configuration
./setup_nat.rb --only-dhcp --uninstall
```

### Setting up NAT-only Mode

Use the `--only-nat` flag to set up just NAT without a DHCP server. This is particularly useful when:
- You already have Internet Sharing enabled and just want to enhance it with custom NAT rules
- You have another DHCP server on your network
- You want to use static IP assignments only

```bash
# Basic NAT-only setup with custom static IP
./setup_nat.rb --only-nat --wan-interface en0 --lan-interface en5 --static-ip 192.168.1.1

# NAT-only with specific WAN and LAN interfaces
./setup_nat.rb --only-nat --wan-interface ppp0 --lan-interface en8 --static-ip 192.168.1.1

# Uninstall NAT-only configuration
./setup_nat.rb --only-nat --uninstall
```

The `--dhcp-range` parameter accepts values in the format `start_ip,end_ip,lease_time` where:
- `start_ip`: The first IP address in the DHCP range
- `end_ip`: The last IP address in the DHCP range
- `lease_time`: How long a DHCP lease is valid (can use suffixes: s for seconds, m for minutes, h for hours, d for days)

### Managing Services

```bash
# Check status
./setup_nat.rb --status

# List available network interfaces
./setup_nat.rb --list-interfaces

# List current static MAC to IP mappings
./setup_nat.rb --list-static-mappings

# List active DHCP leases
./setup_nat.rb --list-dhcp-leases

# Uninstall NAT configuration
./setup_nat.rb --uninstall

# Force configuration even if services are already running
./setup_nat.rb --wan-interface en0 --lan-interface en5 --force

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
  - `dnsmasq_manager.rb`: DNSMASQ configuration
  - `interface_manager.rb`: Network interface management
  - `sysctl_manager.rb`: Sysctl configuration
- `templates/`: ERB templates
  - `caddyfile.erb`: Caddy server configuration
  - `launchdaemon.erb`: macOS service configuration
  - `pf_rules.erb`: Packet filter rules
  - `dnsmasq_config.erb`: DHCP/DNS server configuration
- `spec/`: Test files

## DNS-based Blocking for Ads, Tracking, and Spam

MacRouterNas includes powerful DNS-based blocking of ads, trackers, malware, and spam domains:

### How it Works

The DNS blacklist system uses dnsmasq to block unwanted domains:

1. The system downloads blacklists from multiple reputable sources
2. Blocked domains are redirected to 0.0.0.0 (which prevents connections)
3. The blacklists are automatically updated weekly

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

# Plex Setup
```
$ brew install plex-media-server
$ open /Applications/Plex\ Media\ Server.app # follow the on screen instructions

# e.g. to allow remote access
$ ./setup_nat.rb --wan-interface ppp0 --lan-interface en8 --add-port-forward 32400,192.168.1.1,32400,tcp
```
