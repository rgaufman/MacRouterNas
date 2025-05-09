# MacRouterNas

A collection of Ruby utilities for setting up macOS as a router and NAS.

## Features

- **Network Address Translation (NAT)**: Configure your Mac to share its internet connection with devices connected to a secondary network interface
- **Port Forwarding**: Forward external ports to internal devices on your network
- **DNS Blacklists**: Block ads, trackers, and malware at the DNS level
- **DHCP/DNS**: Configure DNSMASQ for DHCP and DNS services
- **Static IP Mappings**: Easily add and remove static MAC to IP mappings
- **Caddy Server**: Set up Caddy as a reverse proxy for services like Seafile

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
