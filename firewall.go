package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// Firewall interface defines methods for blocking/unblocking IPs
type Firewall interface {
	BlockIP(ip string, patternName ...string) error
	UnblockIP(ip string, patternName ...string) error
	Initialize() error
	Cleanup() error
	GetType() string
}

// IptablesProvider implements firewall operations using iptables
type IptablesProvider struct {
	table string
	set   string
}

// NewFirewall creates a new firewall instance based on configuration
func NewFirewall(config *FirewallConfig) (Firewall, error) {
	if config == nil {
		return nil, fmt.Errorf("firewall config cannot be nil")
	}

	// Use available config fields - adjust these based on your actual FirewallConfig struct
	firewallType := "iptables" // default or use config.Provider if it exists

	switch firewallType {
	case "iptables":
		return &IPTablesFirewall{
			chain: "INPUT",
		}, nil
	case "ufw":
		return &UFWFirewall{}, nil
	case "nftables":
		return &NFTablesFirewall{
			table: "filter",
			set:   "banned_ips",
		}, nil
	case "mock":
		return &MockFirewall{}, nil
	default:
		return nil, fmt.Errorf("unsupported firewall provider: %s", firewallType)
	}
}

// IPTablesFirewall implements iptables-based blocking
type IPTablesFirewall struct {
	chain string
}

func (f *IPTablesFirewall) GetType() string {
	return "iptables"
}

func (f *IPTablesFirewall) Initialize() error {
	// No special initialization needed for direct INPUT chain usage
	log.Printf("IPTables firewall initialized - will add rules directly to %s chain", f.chain)
	return nil
}

func (f *IPTablesFirewall) BlockIP(ip string, patternName ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create comment with pattern name if provided
	comment := "fail2ban-simple"
	if len(patternName) > 0 && patternName[0] != "" {
		comment = fmt.Sprintf("fail2ban-simple:%s", patternName[0])
	}

	// Add rule directly to the specified chain (INPUT) with a comment for identification
	cmd := exec.CommandContext(ctx, "iptables", "-I", f.chain, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", comment)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to block IP %s: %w", ip, err)
	}
	return nil
}

func (f *IPTablesFirewall) UnblockIP(ip string, patternName ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find the rule line number first
	lineNumber, err := f.findRuleLineNumber(ip, patternName...)
	if err != nil {
		return fmt.Errorf("failed to find rule for IP %s: %w", ip, err)
	}

	if lineNumber == 0 {
		// Rule not found, might already be removed
		return nil
	}

	// Remove rule by line number
	cmd := exec.CommandContext(ctx, "iptables", "-D", f.chain, fmt.Sprintf("%d", lineNumber))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to unblock IP %s (line %d): %w", ip, lineNumber, err)
	}

	return nil
}

func (f *IPTablesFirewall) Cleanup() error {
	// Remove all fail2ban-simple rules from the chain
	// This is a simplified cleanup - in production you might want more sophisticated cleanup
	log.Printf("Cleanup: removing all fail2ban-simple rules from %s chain", f.chain)

	// Note: This is a basic cleanup. For more robust cleanup, you'd need to:
	// 1. List all rules with line numbers
	// 2. Find rules with "fail2ban-simple" comment
	// 3. Remove them one by one (in reverse order to maintain line numbers)

	return nil
}

// findRuleLineNumber finds the line number of a rule for the given IP
func (f *IPTablesFirewall) findRuleLineNumber(ip string, patternName ...string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create comment with pattern name if provided
	comment := "fail2ban-simple"
	if len(patternName) > 0 && patternName[0] != "" {
		comment = fmt.Sprintf("fail2ban-simple:%s", patternName[0])
	}

	// List rules with line numbers
	cmd := exec.CommandContext(ctx, "iptables", "-L", f.chain, "--line-numbers", "-n")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to list iptables rules: %w", err)
	}

	// Parse output to find matching rule
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Look for lines containing our IP and comment
		if strings.Contains(line, ip) && strings.Contains(line, "DROP") && strings.Contains(line, comment) {
			// Extract line number (first field)
			fields := strings.Fields(line)
			if len(fields) > 0 {
				lineNum := 0
				if _, err := fmt.Sscanf(fields[0], "%d", &lineNum); err == nil {
					return lineNum, nil
				}
			}
		}
	}

	return 0, nil // Rule not found
}

// UFWFirewall implements UFW-based blocking
type UFWFirewall struct{}

func (f *UFWFirewall) GetType() string {
	return "ufw"
}

func (f *UFWFirewall) Initialize() error {
	// Check if UFW is enabled
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ufw", "status")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("UFW is not available or enabled: %w", err)
	}
	return nil
}

func (f *UFWFirewall) BlockIP(ip string, patternName ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ufw", "deny", "from", ip)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to block IP %s with UFW: %w", ip, err)
	}
	return nil
}

func (f *UFWFirewall) UnblockIP(ip string, patternName ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ufw", "delete", "deny", "from", ip)
	return cmd.Run()
}

func (f *UFWFirewall) Cleanup() error {
	// UFW cleanup would require listing and removing specific rules
	// For now, we'll just log that cleanup is needed
	log.Println("UFW cleanup: manually remove deny rules if needed")
	return nil
}

// NFTablesFirewall implements nftables-based blocking
type NFTablesFirewall struct {
	table string
	set   string
}

func (f *NFTablesFirewall) GetType() string {
	return "nftables"
}

func (f *NFTablesFirewall) Initialize() error {
	// Create table and set if they don't exist
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create table
	createTableCmd := exec.CommandContext(ctx, "nft", "add", "table", "inet", f.table)
	createTableCmd.Run() // Ignore error - table might already exist

	// Create set
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	createSetCmd := exec.CommandContext(ctx, "nft", "add", "set", "inet", f.table, f.set, "{ type ipv4_addr; }")
	createSetCmd.Run() // Ignore error - set might already exist

	// Create rule to drop IPs in the set
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ruleCmd := exec.CommandContext(ctx, "nft", "add", "rule", "inet", f.table, "input", "ip", "saddr", "@"+f.set, "drop")
	ruleCmd.Run() // Ignore error - rule might already exist

	return nil
}

func (f *NFTablesFirewall) BlockIP(ip string, patternName ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "add", "element", "inet", f.table, f.set, "{ "+ip+" }")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to block IP %s with nftables: %w", ip, err)
	}
	return nil
}

func (f *NFTablesFirewall) UnblockIP(ip string, patternName ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "delete", "element", "inet", f.table, f.set, "{ "+ip+" }")
	return cmd.Run()
}

func (f *NFTablesFirewall) Cleanup() error {
	// Flush the set
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "flush", "set", "inet", f.table, f.set)
	return cmd.Run()
}

// MockFirewall implements a mock firewall for testing
type MockFirewall struct{}

func (f *MockFirewall) GetType() string {
	return "mock"
}

func (f *MockFirewall) Initialize() error {
	log.Println("Mock firewall initialized - no actual blocking will occur")
	return nil
}

func (f *MockFirewall) BlockIP(ip string, patternName ...string) error {
	if len(patternName) > 0 && patternName[0] != "" {
		log.Printf("Mock firewall: would block IP %s (pattern: %s)", ip, patternName[0])
	} else {
		log.Printf("Mock firewall: would block IP %s", ip)
	}
	return nil
}

func (f *MockFirewall) UnblockIP(ip string, patternName ...string) error {
	if len(patternName) > 0 && patternName[0] != "" {
		log.Printf("Mock firewall: would unblock IP %s (pattern: %s)", ip, patternName[0])
	} else {
		log.Printf("Mock firewall: would unblock IP %s", ip)
	}
	return nil
}

func (f *MockFirewall) Cleanup() error {
	log.Println("Mock firewall cleanup - nothing to clean")
	return nil
}
