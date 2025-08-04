# GoGuard

A dramatically simplified fail2ban-like implementation in Go that focuses on core security requirements without unnecessary complexity.

## Overview

GoGuard Simple monitors log files for suspicious activity, automatically blocks malicious IP addresses using iptables, and optionally reports them to abuse databases. This is a complete rewrite that reduces the original complex codebase from **5000+ lines** to just **~500 lines** across 4 core files.

## Key Features

✅ **Real-time Log Monitoring** - Tail log files with regex pattern matching  
✅ **Automatic IP Blocking** - Direct iptables integration for immediate blocking  
✅ **Abuse Database Reporting** - Report banned IPs to AbuseIPDB and AbuseDB  
✅ **Web Dashboard** - Simple interface for monitoring and management  
✅ **In-Memory State** - Fast operations with JSON persistence  
✅ **Whitelist Protection** - IP and CIDR whitelist support  
✅ **Automatic Cleanup** - Expired bans are automatically removed  
✅ **Production Ready** - Graceful shutdown and signal handling  

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   config.yaml   │───▶│     main.go      │───▶│   monitor.go    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │     web.go       │    │    iptables     │
                       └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │   Dashboard      │    │   Blocked IPs   │
                       └──────────────────┘    └─────────────────┘
```

### Core Components

- **[main.go](main.go)** (81 lines) - Application entry point and coordination
- **[config.go](config.go)** (73 lines) - Configuration management and validation
- **[monitor.go](monitor.go)** (267 lines) - Log monitoring, pattern matching, and IP blocking
- **[web.go](web.go)** (162 lines) - Web dashboard with real-time statistics
- **[abuse_reporter.go](abuse_reporter.go)** - Abuse database reporting functionality

## Installation

### Quick Start

```bash
# Clone and build
git clone <repository-url>
cd goguard
go build -o goguard .

# Run with root privileges (required for iptables)
sudo ./goguard
```

### Production Installation

```bash
# Install to system path
sudo cp goguard /usr/local/bin/

# Create systemd service (optional)
sudo cp goguard.service /etc/systemd/system/
sudo systemctl enable goguard
sudo systemctl start goguard
```

## Configuration

Create or edit `config.yaml`:

```yaml
# Log files to monitor
log_files:
  - path: "/var/log/auth.log"
    patterns:
      # SSH brute force attempts
      - regex: "Failed password for .* from (\\d+\\.\\d+\\.\\d+\\.\\d+)"
        ip_group: 1
        threshold: 3
        ban_time: "1h"
      
      # Invalid SSH users
      - regex: "Invalid user .* from (\\d+\\.\\d+\\.\\d+\\.\\d+)"
        ip_group: 1
        threshold: 5
        ban_time: "2h"

  - path: "/var/log/nginx/access.log"
    patterns:
      # HTTP brute force (adapt regex to your log format)
      - regex: "\\\"POST /wp-login.php.*\\\" 40[0-9] .* \\\"(\\d+\\.\\d+\\.\\d+\\.\\d+)\\\""
        ip_group: 1
        threshold: 10
        ban_time: "6h"

# Web interface
web:
  enabled: true
  port: 8080

# IP whitelist (never ban these)
whitelist:
  - "127.0.0.1"
  - "::1"
  - "192.168.1.0/24"
  - "10.0.0.0/8"

# Optional: Report banned IPs to abuse databases
abuse_reporting:
  enabled: true
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s
  
  abuseipdb:
    enabled: true
    api_key: "your-abuseipdb-api-key"
    categories: [14, 18, 20]  # Hacking, SSH, Brute Force
  
  abusedb:
    enabled: false
    api_key: "your-abusedb-api-key"
    categories: [1, 2, 3]

# Advanced options
production_mode: false  # Start monitoring from end of file
firewall:
  chain: "INPUT"
  target: "DROP"
```

## Usage

### Command Line Options

```bash
# Run with default config
sudo ./goguard

# Use custom config file
sudo ./goguard -config /path/to/config.yaml

# Enable debug logging
sudo ./goguard -debug

# Show version information
./goguard -version
```

### Web Dashboard

Access the web interface at `http://localhost:8080` to:

- **View Active Bans** - See currently blocked IPs with ban timestamps
- **Monitor Statistics** - Track total bans, patterns matched, and abuse reports
- **Manual Management** - Manually unban IPs when needed
- **System Status** - Monitor log files being watched and application health

## How It Works

1. **Startup**: [`main.go`](main.go) loads configuration and initializes components
2. **Log Monitoring**: [`monitor.go`](monitor.go) tails log files using file seeking and watches for new lines
3. **Pattern Matching**: Each new log line is tested against configured regex patterns
4. **IP Tracking**: Failed attempts are counted per IP address in memory
5. **Threshold Detection**: When an IP exceeds the threshold, it's automatically banned
6. **Firewall Integration**: Direct iptables commands block malicious IPs immediately
7. **Abuse Reporting**: Banned IPs are optionally reported to external abuse databases
8. **State Persistence**: Current state is saved to JSON for recovery after restarts
9. **Automatic Cleanup**: A background process removes expired bans

### Production Mode

When `production_mode: true`, the application:
- Starts monitoring from the end of existing log files (avoids processing old entries)
- Uses optimized file tracking for high-volume environments
- Reduces startup time for large log files

## Comparison with Original Complex Version

| Aspect | Original Complex | GoGuard Simple |
|--------|------------------|----------------|
| **Lines of Code** | 5000+ | ~500 |
| **Files** | 50+ | 4 core files |
| **Database** | SQLite with 8+ tables | In-memory + JSON backup |
| **Configuration** | Complex YAML + DB schema | Single YAML file |
| **Dependencies** | Many (fsnotify, sqlite, uuid, etc.) | Minimal (`gopkg.in/yaml.v3`) |
| **Memory Usage** | High (database overhead) | Low (efficient maps) |
| **Startup Time** | Slow (database initialization) | Fast (direct start) |
| **Maintenance** | Complex debugging | Simple troubleshooting |
| **Architecture** | Inlet-based with abstractions | Direct implementation |

## Migration from Complex Version

If you're migrating from the complex GoGuard implementation, see the detailed [MIGRATION.md](MIGRATION.md) guide which covers:

- Configuration conversion
- Feature mapping
- Common migration issues
- Rollback procedures
- Performance differences

## Abuse Reporting

GoGuard Simple can automatically report banned IPs to abuse databases:

### Supported Services

- **[AbuseIPDB.com](https://www.abuseipdb.com/)** - Community-driven IP abuse database
- **[AbuseDB.info](https://abusedb.info/)** - Alternative abuse reporting service

### Key Features

- **Asynchronous Reporting** - Non-blocking, doesn't slow down ban operations
- **Automatic Retry** - Exponential backoff for failed reports
- **Pattern-Specific Categories** - Different abuse categories per pattern type
- **Real-time Metrics** - Track reporting success/failure rates
- **Mock Reporter** - Testing support without external API calls

### Configuration Example

```yaml
abuse_reporting:
  enabled: true
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s
  
  abuseipdb:
    enabled: true
    api_key: "your-api-key-here"
    categories: [14, 18, 20]  # SSH, Hacking, Brute Force
```

## Requirements

- **Operating System**: Linux with iptables support
- **Go Version**: 1.21+ (for building from source)
- **Privileges**: Root access (required for iptables operations)
- **Dependencies**: Minimal - only `gopkg.in/yaml.v3` for configuration

## Security Considerations

- **Root Privileges**: Required for iptables operations - ensure secure deployment
- **Whitelist Configuration**: Always whitelist your management IPs to avoid lockout
- **Web Interface**: Consider restricting access or using reverse proxy authentication
- **Regex Validation**: Test regex patterns thoroughly to avoid false positives
- **Log File Access**: Ensure proper permissions for log file reading

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure running as root for iptables access
2. **Config Not Found**: Verify config file path and permissions
3. **Regex Not Matching**: Test patterns with online regex validators
4. **Web Interface Not Accessible**: Check port availability and firewall rules

### Debug Mode

Enable debug logging for detailed operation information:

```bash
sudo ./goguard -debug
```

This provides:
- Detailed log file monitoring information
- Pattern matching results
- Iptables command execution
- Abuse reporting status
- Performance metrics

## Performance

### Resource Usage
- **Memory**: ~10-20MB typical usage
- **CPU**: Low impact, event-driven processing
- **Disk I/O**: Minimal, mainly log file reading
- **Network**: Only for abuse reporting (optional)

### Scalability
- Efficiently handles multiple log files
- In-memory operations for fast response
- Optimized file tailing with proper seeking
- Automatic cleanup prevents memory leaks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with appropriate tests
4. Ensure code follows Go conventions
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

- **Documentation**: See [examples/](examples/) for configuration samples
- **Issues**: Report bugs via GitHub issues
- **Questions**: Check existing issues or create new ones