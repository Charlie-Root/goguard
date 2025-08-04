package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the simplified configuration
type Config struct {
	LogFiles       []LogFile            `yaml:"log_files"`
	Web            WebConfig            `yaml:"web"`
	Firewall       FirewallConfig       `yaml:"firewall"`
	AbuseReporting *AbuseReportingConfig `yaml:"abuse_reporting"`
	Whitelist      []string             `yaml:"whitelist"`
	ProductionMode bool                 `yaml:"production_mode"` // Start from end of files in production
}

// AbuseReportingConfig represents abuse reporting configuration
type AbuseReportingConfig struct {
	Enabled        bool            `yaml:"enabled"`
	Timeout        time.Duration   `yaml:"timeout"`
	RetryAttempts  int             `yaml:"retry_attempts"`
	RetryDelay     time.Duration   `yaml:"retry_delay"`
	AbuseIPDB      *AbuseIPDBConfig `yaml:"abuseipdb"`
	AbuseDB        *AbuseDBConfig   `yaml:"abusedb"`
}

// AbuseIPDBConfig represents AbuseIPDB.com configuration
type AbuseIPDBConfig struct {
	Enabled    bool  `yaml:"enabled"`
	APIKey     string `yaml:"api_key"`
	Categories []int  `yaml:"categories"`
}

// AbuseDBConfig represents AbuseDB.info configuration
type AbuseDBConfig struct {
	Enabled    bool  `yaml:"enabled"`
	APIKey     string `yaml:"api_key"`
	Categories []int  `yaml:"categories"`
}

// FirewallConfig represents firewall configuration
type FirewallConfig struct {
	Type      string   `yaml:"type"`      // iptables, ufw, nftables, mock, auto
	Chain     string   `yaml:"chain"`     // iptables chain (default: INPUT)
	Table     string   `yaml:"table"`     // nftables table (default: filter)
	Set       string   `yaml:"set"`       // nftables set name (default: goguard)
	Whitelist []string `yaml:"whitelist"` // Additional firewall-specific whitelist
}

// LogFile represents a log file to monitor
type LogFile struct {
	Path     string    `yaml:"path"`
	Patterns []Pattern `yaml:"patterns"`
}

// Pattern represents a regex pattern to match
type Pattern struct {
	Name            string         `yaml:"name"`
	Regex           string         `yaml:"regex"`
	IPGroup         int            `yaml:"ip_group"`
	Threshold       int            `yaml:"threshold"`
	BanTime         time.Duration  `yaml:"ban_time"`
	AbuseCategories map[string]int `yaml:"abuse_categories"` // Override categories per service
}

// WebConfig represents web interface configuration
type WebConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// LoadConfig loads configuration from YAML file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	if config.Web.Port == 0 {
		config.Web.Port = 8080
	}
	
	// Set firewall defaults
	if config.Firewall.Type == "" {
		config.Firewall.Type = "iptables"
	}
	
	// Handle auto-detection
	if config.Firewall.Type == "auto" {
		config.Firewall.Type = detectAvailableFirewall()
		fmt.Printf("Auto-detected firewall type: %s\n", config.Firewall.Type)
	}
	
	if config.Firewall.Chain == "" {
		config.Firewall.Chain = "INPUT"
	}
	if config.Firewall.Table == "" {
		config.Firewall.Table = "filter"
	}
	if config.Firewall.Set == "" {
		config.Firewall.Set = "goguard"
	}

	// Set abuse reporting defaults
	if config.AbuseReporting != nil && config.AbuseReporting.Enabled {
		// Set default timeout if not specified
		if config.AbuseReporting.Timeout == 0 {
			config.AbuseReporting.Timeout = 30 * time.Second
		}
		
		// Set default retry attempts if not specified
		if config.AbuseReporting.RetryAttempts == 0 {
			config.AbuseReporting.RetryAttempts = 3
		}

		// Set default retry delay if not specified
		if config.AbuseReporting.RetryDelay == 0 {
			config.AbuseReporting.RetryDelay = 5 * time.Second
		}

		// Set AbuseIPDB defaults
		if config.AbuseReporting.AbuseIPDB != nil && config.AbuseReporting.AbuseIPDB.Enabled {
			if len(config.AbuseReporting.AbuseIPDB.Categories) == 0 {
				config.AbuseReporting.AbuseIPDB.Categories = []int{14, 18, 20} // Default categories
			}
		}

		// Set AbuseDB defaults
		if config.AbuseReporting.AbuseDB != nil && config.AbuseReporting.AbuseDB.Enabled {
			if len(config.AbuseReporting.AbuseDB.Categories) == 0 {
				config.AbuseReporting.AbuseDB.Categories = []int{1, 2, 3} // Default categories
			}
		}
	}

	// Validate firewall configuration
	if err := validateFirewallConfig(&config.Firewall); err != nil {
		return nil, fmt.Errorf("invalid firewall configuration: %w", err)
	}

	// Validate abuse reporting configuration
	if err := validateAbuseReportingConfig(config.AbuseReporting); err != nil {
		return nil, fmt.Errorf("invalid abuse reporting configuration: %w", err)
	}

	return &config, nil
}

// validateFirewallConfig validates firewall configuration
func validateFirewallConfig(config *FirewallConfig) error {
	validTypes := []string{"iptables", "ufw", "nftables", "mock", "auto"}
	isValid := false
	for _, validType := range validTypes {
		if config.Type == validType {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid firewall type '%s', must be one of: %s", config.Type, strings.Join(validTypes, ", "))
	}

	// Validate iptables-specific configuration
	if config.Type == "iptables" {
		validChains := []string{"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}
		isValidChain := false
		for _, validChain := range validChains {
			if config.Chain == validChain {
				isValidChain = true
				break
			}
		}
		if !isValidChain {
			return fmt.Errorf("invalid iptables chain '%s', must be one of: %s", config.Chain, strings.Join(validChains, ", "))
		}
	}

	// Validate whitelist IPs
	for _, ip := range config.Whitelist {
		if strings.Contains(ip, "/") {
			_, _, err := net.ParseCIDR(ip)
			if err != nil {
				return fmt.Errorf("invalid CIDR in firewall whitelist '%s': %w", ip, err)
			}
		} else {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid IP in firewall whitelist '%s'", ip)
			}
		}
	}

	return nil
}

// detectAvailableFirewall detects the best available firewall type
func detectAvailableFirewall() string {
	// Check for nftables first (modern)
	if _, err := exec.LookPath("nft"); err == nil {
		return "nftables"
	}
	
	// Check for iptables (most common)
	if _, err := exec.LookPath("iptables"); err == nil {
		return "iptables"
	}
	
	// Check for ufw (Ubuntu/Debian)
	if _, err := exec.LookPath("ufw"); err == nil {
		return "ufw"
	}
	
	// Fallback to mock
	return "mock"
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		LogFiles: []LogFile{
			{
				Path: "/var/log/auth.log",
				Patterns: []Pattern{
					{
						Regex:     `Failed password for .* from (\d+\.\d+\.\d+\.\d+)`,
						IPGroup:   1,
						Threshold: 3,
						BanTime:   time.Hour,
					},
					{
						Regex:     `Invalid user .* from (\d+\.\d+\.\d+\.\d+)`,
						IPGroup:   1,
						Threshold: 5,
						BanTime:   2 * time.Hour,
					},
				},
			},
		},
		Web: WebConfig{
			Enabled: true,
			Port:    8080,
		},
		Firewall: FirewallConfig{
			Type:  "iptables",
			Chain: "INPUT",
			Table: "filter",
			Set:   "goguard",
		},
		Whitelist: []string{
			"127.0.0.1",
			"::1",
		},
	}
}
// validateAbuseReportingConfig validates abuse reporting configuration
func validateAbuseReportingConfig(config *AbuseReportingConfig) error {
	if config == nil || !config.Enabled {
		return nil
	}

	// Validate timeout
	if config.Timeout <= 0 {
		return fmt.Errorf("abuse reporting timeout must be positive")
	}

	// Validate retry attempts
	if config.RetryAttempts < 0 {
		return fmt.Errorf("abuse reporting retry attempts cannot be negative")
	}

	// Validate retry delay
	if config.RetryDelay <= 0 {
		return fmt.Errorf("abuse reporting retry delay must be positive")
	}

	// Validate AbuseIPDB configuration
	if config.AbuseIPDB != nil && config.AbuseIPDB.Enabled {
		if config.AbuseIPDB.APIKey == "" {
			return fmt.Errorf("AbuseIPDB API key is required when enabled")
		}
		if len(config.AbuseIPDB.Categories) == 0 {
			return fmt.Errorf("AbuseIPDB categories cannot be empty when enabled")
		}
		for _, cat := range config.AbuseIPDB.Categories {
			if cat < 1 || cat > 23 {
				return fmt.Errorf("invalid AbuseIPDB category %d, must be between 1 and 23", cat)
			}
		}
	}

	// Validate AbuseDB configuration
	if config.AbuseDB != nil && config.AbuseDB.Enabled {
		if config.AbuseDB.APIKey == "" {
			return fmt.Errorf("AbuseDB API key is required when enabled")
		}
		if len(config.AbuseDB.Categories) == 0 {
			return fmt.Errorf("AbuseDB categories cannot be empty when enabled")
		}
		for _, cat := range config.AbuseDB.Categories {
			if cat < 1 || cat > 10 {
				return fmt.Errorf("invalid AbuseDB category %d, must be between 1 and 10", cat)
			}
		}
	}

	// Ensure at least one service is enabled or allow mock reporter fallback
	if config.Enabled {
		hasEnabledService := false
		if config.AbuseIPDB != nil && config.AbuseIPDB.Enabled {
			hasEnabledService = true
		}
		if config.AbuseDB != nil && config.AbuseDB.Enabled {
			hasEnabledService = true
		}
		// If no services are enabled, mock reporter will be used automatically
		// This is valid for testing and development scenarios
		if !hasEnabledService {
			// Log that mock reporter will be used (this will be logged during initialization)
		}
	}

	return nil
}