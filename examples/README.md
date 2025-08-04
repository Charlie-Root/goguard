# Fail2Ban Simple Configuration Examples

This directory contains configuration examples for different firewall backends supported by Fail2Ban Simple.

## Available Examples

### 1. IPTables Configuration (`config-iptables.yaml`)
- **Use Case**: Production servers, most Linux distributions
- **Features**: Traditional iptables firewall with custom chains
- **Best For**: Established infrastructure, maximum compatibility

### 2. UFW Configuration (`config-ufw.yaml`)
- **Use Case**: Ubuntu/Debian desktop and server systems
- **Features**: User-friendly firewall management
- **Best For**: Ubuntu servers, simplified firewall management

### 3. NFTables Configuration (`config-nftables.yaml`)
- **Use Case**: Modern Linux systems, high-performance environments
- **Features**: Set-based IP matching, better performance
- **Best For**: High-traffic servers, modern distributions

### 4. Auto-Detection Configuration (`config-auto.yaml`)
- **Use Case**: Mixed environments, containerized deployments
- **Features**: Automatic firewall detection and fallback
- **Best For**: Docker containers, cloud deployments, CI/CD

### 5. Mock Configuration (`config-mock.yaml`)
- **Use Case**: Development, testing, CI/CD pipelines
- **Features**: No actual blocking, comprehensive logging
- **Best For**: Development environments, testing, debugging

## Quick Start

1. **Choose the appropriate configuration** based on your system:
   ```bash
   # For iptables (most common)
   cp examples/config-iptables.yaml config.yaml
   
   # For UFW (Ubuntu/Debian)
   cp examples/config-ufw.yaml config.yaml
   
   # For nftables (modern systems)
   cp examples/config-nftables.yaml config.yaml
   
   # For auto-detection
   cp examples/config-auto.yaml config.yaml
   
   # For testing/development
   cp examples/config-mock.yaml config.yaml
   ```

2. **Customize the configuration** for your environment:
   - Update log file paths
   - Modify whitelist entries
   - Adjust thresholds and ban times
   - Configure web interface settings

3. **Test the configuration**:
   ```bash
   # Test with mock firewall first
   ./fail2ban-simple -config examples/config-mock.yaml
   ```

4. **Run in production**:
   ```bash
   # Run with your chosen firewall
   sudo ./fail2ban-simple -config config.yaml
   ```

## Configuration Sections

### Firewall Section
```yaml
firewall:
  type: iptables          # Firewall type: iptables, ufw, nftables, mock, auto
  chain: INPUT            # IPTables specific: target chain
  table: filter           # NFTables specific: table name
  set: goguard           # NFTables specific: set name
  whitelist: []           # Additional firewall-specific whitelist
```

### Supported Firewall Types

| Type | Description | Requirements |
|------|-------------|--------------|
| `iptables` | Traditional Linux firewall | `iptables` command, root privileges |
| `ufw` | Uncomplicated Firewall | `ufw` command, UFW enabled |
| `nftables` | Modern Linux firewall | `nft` command, kernel 3.13+ |
| `auto` | Auto-detect best available | Detects and uses best option |
| `mock` | Testing/development mode | No requirements, logs only |

### Auto-Detection Priority

When using `type: auto`, the system detects firewalls in this order:
1. **nftables** (modern, efficient)
2. **iptables** (widely supported)
3. **ufw** (user-friendly)
4. **mock** (always available fallback)

## Log File Patterns

Each configuration includes common patterns for:
- **SSH attacks**: Failed passwords, invalid users
- **Web attacks**: 404 scanning, authentication failures
- **Custom patterns**: Easily add your own regex patterns

Example pattern:
```yaml
- ban_time: 1h
  ip_group: 1
  regex: Failed password for .* from (\d+\.\d+\.\d+\.\d+)
  threshold: 3
```

## Whitelist Configuration

The whitelist supports both individual IPs and CIDR blocks:
```yaml
whitelist:
- 127.0.0.1              # Localhost
- ::1                    # IPv6 localhost
- 192.168.1.0/24         # Local network
- 10.0.0.0/8             # Private network
```

## Web Interface

Enable the web dashboard to monitor bans:
```yaml
web:
  enabled: true
  port: 8080
```

Access at: `http://localhost:8080`

## Production Considerations

### Security
- Always include your management IP in the whitelist
- Test configurations in a safe environment first
- Keep backup access methods available

### Performance
- Use `nftables` for high-traffic environments
- Adjust thresholds based on legitimate traffic patterns
- Monitor system resources

### Monitoring
- Enable the web interface for real-time monitoring
- Check logs regularly for false positives
- Set up external monitoring for the service

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   sudo ./fail2ban-simple -config config.yaml
   ```

2. **Firewall Command Not Found**
   ```bash
   # Install required tools
   sudo apt-get install iptables ufw nftables
   ```

3. **UFW Not Enabled**
   ```bash
   sudo ufw enable
   ```

### Debug Mode
```bash
./fail2ban-simple -config config.yaml -debug
```

### Testing
Use mock firewall for safe testing:
```yaml
firewall:
  type: mock
```

## Migration Between Firewall Types

To switch firewall types:
1. Stop the service
2. Update the configuration
3. Restart the service
4. Verify the new firewall is working

The system will automatically clean up old rules and initialize the new firewall type.

## Support

For issues or questions:
- Check the main project documentation
- Review log files for error messages
- Test with mock firewall first
- Ensure proper permissions and tool availability