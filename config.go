package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the simplified configuration
type Config struct {
	LogFiles       []LogFileConfig      `yaml:"log_files"`
	Web            WebConfig            `yaml:"web"`
	Whitelist      []string             `yaml:"whitelist"`
	AbuseReporting AbuseReportingConfig `yaml:"abuse_reporting"`
	ProductionMode bool                 `yaml:"production_mode"`
	Actions        []ActionConfig       `yaml:"actions"`
	Firewall       FirewallConfig       `yaml:"firewall"`
}

// LogFileConfig represents a log file to monitor
type LogFileConfig struct {
	Path     string          `yaml:"path"`
	Patterns []PatternConfig `yaml:"patterns"`
}

// PatternConfig represents a regex pattern to match
type PatternConfig struct {
	Regex     string `yaml:"regex"`
	IPGroup   int    `yaml:"ip_group"`
	Threshold int    `yaml:"threshold"`
	BanTime   string `yaml:"ban_time"`
}

// WebConfig represents web interface configuration
type WebConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// FirewallConfig represents firewall configuration
type FirewallConfig struct {
	Chain  string `yaml:"chain"`
	Target string `yaml:"target"`
}

// AbuseReportingConfig represents abuse reporting configuration
type AbuseReportingConfig struct {
	Enabled       bool            `yaml:"enabled"`
	Timeout       string          `yaml:"timeout"`
	RetryAttempts int             `yaml:"retry_attempts"`
	RetryDelay    string          `yaml:"retry_delay"`
	AbuseIPDB     AbuseIPDBConfig `yaml:"abuseipdb"`
}

// AbuseIPDBConfig represents AbuseIPDB.com configuration
type AbuseIPDBConfig struct {
	Enabled    bool   `yaml:"enabled"`
	APIKey     string `yaml:"api_key"`
	Categories []int  `yaml:"categories"`
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

	config.SetDefaults()
	return &config, config.Validate()
}

// SetDefaults sets default values for the configuration
func (c *Config) SetDefaults() {
	if c.Web.Port == 0 {
		c.Web.Port = 8080
	}

	// Set default actions if none specified
	if len(c.Actions) == 0 {
		chain := c.Firewall.Chain
		target := c.Firewall.Target

		if chain == "" {
			chain = "INPUT"
		}
		if target == "" {
			target = "DROP"
		}

		c.Actions = []ActionConfig{
			{
				Type:   "iptables",
				Chain:  chain,
				Target: target,
			},
		}
	}

	// Set default patterns if none specified
	for i := range c.LogFiles {
		for j := range c.LogFiles[i].Patterns {
			if c.LogFiles[i].Patterns[j].Threshold == 0 {
				c.LogFiles[i].Patterns[j].Threshold = 5
			}
			if c.LogFiles[i].Patterns[j].BanTime == "" {
				c.LogFiles[i].Patterns[j].BanTime = "1h"
			}
			if c.LogFiles[i].Patterns[j].IPGroup == 0 {
				c.LogFiles[i].Patterns[j].IPGroup = 1
			}
		}
	}

	// Default abuse reporting settings
	if c.AbuseReporting.Timeout == "" {
		c.AbuseReporting.Timeout = "30s"
	}
	if c.AbuseReporting.RetryAttempts == 0 {
		c.AbuseReporting.RetryAttempts = 3
	}
	if c.AbuseReporting.RetryDelay == "" {
		c.AbuseReporting.RetryDelay = "5s"
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if len(c.LogFiles) == 0 {
		return fmt.Errorf("at least one log file must be specified")
	}

	for i, logFile := range c.LogFiles {
		if logFile.Path == "" {
			return fmt.Errorf("log file %d: path cannot be empty", i)
		}

		if len(logFile.Patterns) == 0 {
			return fmt.Errorf("log file %d: at least one pattern must be specified", i)
		}

		for j, pattern := range logFile.Patterns {
			if pattern.Regex == "" {
				return fmt.Errorf("log file %d, pattern %d: regex cannot be empty", i, j)
			}
		}
	}

	// Validate whitelist IPs
	for i, ip := range c.Whitelist {
		if ip == "" {
			return fmt.Errorf("whitelist entry %d: IP cannot be empty", i)
		}
	}

	return nil
}

// IsWhitelisted checks if an IP is in the whitelist
func (c *Config) IsWhitelisted(ip string) bool {
	for _, whiteIP := range c.Whitelist {
		if strings.Contains(whiteIP, "/") {
			// CIDR notation
			_, cidr, err := net.ParseCIDR(whiteIP)
			if err != nil {
				continue
			}
			if cidr.Contains(net.ParseIP(ip)) {
				return true
			}
		} else if ip == whiteIP {
			return true
		}
	}
	return false
}
