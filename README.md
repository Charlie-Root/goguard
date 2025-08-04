# GoGuard - Advanced Intrusion Detection & Response System

GoGuard is a comprehensive fail2ban-like intrusion detection system written in Go that monitors log files for suspicious activity and automatically blocks malicious IP addresses using multiple firewall backends. It includes abuse reporting capabilities and a web interface for monitoring.

## Features

### Core Functionality
- **Real-time log monitoring** - Monitors multiple log files simultaneously for suspicious patterns
- **Flexible pattern matching** - Configurable regex patterns with custom thresholds and ban times
- **Multiple firewall backends** - Support for iptables, ufw, nftables, and mock testing
- **Auto-detection** - Automatically detects and uses the best available firewall backend
- **IP whitelisting** - Protect trusted IPs from being banned
- **Persistent state** - Maintains ban state across restarts with `monitor_state.json`

### Abuse Reporting
- **Multiple reporting services** - Integrated support for AbuseIPDB.com and AbuseDB.info
- **Automatic reporting** - Reports banned IPs to abuse databases with proper categorization
- **Mock reporting** - Test mode for development without sending real reports
- **Configurable categories** - Custom abuse categories per pattern and service
- **Retry mechanism** - Robust error handling with exponential backoff

### Web Interface
- **Real-time dashboard** - Monitor active bans, statistics, and system status
- **RESTful API** - JSON endpoints for integration with other tools
- **Statistics tracking** - View ban counts, recent activity, and trending data
- **Responsive design** - Works on desktop and mobile devices

### Monitoring & Logging
- **Comprehensive logging** - Detailed logs of all detection and action events
- **Performance monitoring** - Track processing speed and system resources
- **Graceful shutdown** - Clean shutdown with state preservation
- **Production mode** - Optimized settings for production environments

## Installation

### Prerequisites
- Go 1.19 or later
- Root privileges (for iptables/firewall management)
- One of: iptables, ufw, or nftables installed

### Build from Source
```bash
git clone https://github.com/yourusername/goguard.git
cd goguard
go build -o goguard .
```

### Quick Start
```bash
# Create configuration file
cp config.yaml.example config.yaml

# Edit configuration
nano config.yaml

# Run with root privileges (for firewall access)
sudo ./goguard

# Or run in test mode with mock firewall
./goguard -config config.yaml
```

## Configuration

### Basic Configuration
```yaml
# Log files and patterns to monitor
log_files:
- path: /var/log/nginx/access.log
  patterns:
  - ban_time: 2h
    ip_group: 1
    regex: (\d+\.\d+\.\d+\.\d+) .* "[^"]*" 404
    threshold: 5
    abuse_categories:
      abuseipdb: 21    # Web application attack
      abusedb: 2       # HTTP attacks

# Firewall configuration
firewall:
  type: auto              # auto, iptables, ufw, nftables, mock
  chain: INPUT            # iptables chain
  table: filter           # nftables table
  set: goguard           # nftables set name

# Global whitelist
whitelist:
- 127.0.0.1
- ::1
- 192.168.1.0/24
```

### Abuse Reporting Setup
```yaml
abuse_reporting:
  enabled: true
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s
  
  # AbuseIPDB.com configuration
  abuseipdb:
    enabled: true
    api_key: "your-abuseipdb-api-key"
    categories: [14, 18, 20]  # Hacking, SSH, Brute Force
  
  # AbuseDB.info configuration
  abusedb:
    enabled: true
    api_key: "your-abusedb-api-key"
    categories: [1, 2, 3]
```

### Web Interface
```yaml
web:
  enabled: true
  port: 8080
```

## Supported Log Formats

GoGuard includes built-in patterns for common services:

### Web Services
- **Nginx** - Access logs, error logs, rate limiting
- **Apache** - Access logs, error logs, ModSecurity
- **HAProxy** - SSL failures, authentication errors, HTTP errors

### System Services
- **SSH** - Failed logins, invalid users, brute force attempts
- **System logs** - Authentication failures, suspicious activity

### Mail Services
- **Postfix/Dovecot** - SMTP/IMAP authentication failures
- **Exim** - Authentication and relay attempts

### Applications
- **Bitwarden** - Failed login attempts
- **Grafana** - Authentication failures
- **Traefik** - HTTP authentication errors
- **MongoDB** - Authentication failures

## API Endpoints

### Statistics
```bash
# Get current statistics
curl http://localhost:8080/api/stats

# Response
{
  "total_bans": 15,
  "total_attempts": 1250,
  "recent_bans": 3,
  "active_bans": [
    {
      "ip": "192.168.1.100",
      "reason": "Pattern matched in /var/log/nginx/access.log",
      "banned_at": "2023-12-10T10:00:00Z",
      "expires_at": "2023-12-10T12:00:00Z"
    }
  ]
}
```

### Health Check
```bash
# Check system health
curl http://localhost:8080/health
```

## Command Line Options

```bash
# Specify custom configuration file
./goguard -config /path/to/config.yaml

# Run in test mode (with mock firewall)
./goguard -config config-test.yaml

# Display version information
./goguard -version
```

## Firewall Backend Details

### IPTables
- Automatically creates DROP rules in specified chain
- Supports custom chains and tables
- Handles rule cleanup on shutdown

### UFW (Uncomplicated Firewall)
- Uses `ufw deny` commands
- Integrates with existing UFW configuration
- Maintains rule consistency

### NFTables
- Uses named sets for efficient IP blocking
- Supports custom tables and sets
- Atomic rule updates

### Mock (Testing)
- Simulates firewall operations without system changes
- Perfect for development and testing
- Logs all operations for verification

## State Management

GoGuard maintains persistent state in `monitor_state.json`:

```json
{
  "bans": {
    "192.168.1.100": {
      "ip": "192.168.1.100",
      "reason": "SSH brute force",
      "banned_at": "2023-12-10T10:00:00Z",
      "expires_at": "2023-12-10T12:00:00Z"
    }
  },
  "failure_counts": {
    "192.168.1.101": 3
  },
  "last_seen": {
    "192.168.1.101": "2023-12-10T10:30:00Z"
  }
}
```

## Production Deployment

### Systemd Service
```ini
# /etc/systemd/system/goguard.service
[Unit]
Description=GoGuard Intrusion Detection System
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/goguard -config /etc/goguard/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Log Rotation
```bash
# /etc/logrotate.d/goguard
/var/log/goguard/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload goguard
    endscript
}
```

## Performance & Scaling

- **Memory efficient** - Minimal memory footprint with efficient data structures
- **CPU optimized** - Compiled regex patterns and optimized processing
- **Concurrent processing** - Parallel log file monitoring
- **Configurable limits** - Adjust thresholds and timeouts for your environment

## Security Considerations

- **Run with minimal privileges** - Only requires firewall access
- **Secure API keys** - Store abuse reporting credentials securely
- **Whitelist protection** - Always whitelist management IPs
- **Regular updates** - Keep patterns updated for new attack vectors

## Troubleshooting

### Common Issues

1. **Permission denied on iptables**
   ```bash
   # Run with root privileges
   sudo ./goguard
   ```

2. **File not found errors**
   ```bash
   # Check log file paths in configuration
   ls -la /var/log/nginx/access.log
   ```

3. **Pattern not matching**
   ```bash
   # Test regex patterns online or use debug mode
   # Enable verbose logging in configuration
   ```

### Debug Mode
Set `production_mode: false` in configuration for detailed logging.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Comprehensive docs available in the `/docs` directory
- **Community**: Join our Discord/Slack for support and discussions

## Changelog

### v1.0.0-simple
- Initial release with core functionality
- Multiple firewall backend support
- Abuse reporting integration
- Web interface and API
- Comprehensive log pattern library
- Production-ready monitoring system