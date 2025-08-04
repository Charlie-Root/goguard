package main

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Action represents a firewall action that can ban/unban IPs
type Action interface {
	Ban(ip string) error
	Unban(ip string) error
	Check(ip string) (bool, error)
	Name() string
	IsAvailable() bool
}

// ActionConfig represents configuration for actions
type ActionConfig struct {
	Type    string            `yaml:"type"`
	Chain   string            `yaml:"chain,omitempty"`
	Target  string            `yaml:"target,omitempty"`
	Options map[string]string `yaml:"options,omitempty"`
}

// ActionManager manages multiple actions
type ActionManager struct {
	actions []Action
	config  []ActionConfig
}

// NewActionManager creates a new action manager
func NewActionManager(configs []ActionConfig) (*ActionManager, error) {
	manager := &ActionManager{
		config: configs,
	}

	for _, config := range configs {
		action, err := createAction(config)
		if err != nil {
			log.Printf("Failed to create action %s: %v", config.Type, err)
			continue
		}

		if !action.IsAvailable() {
			log.Printf("Action %s is not available on this system", config.Type)
			continue
		}

		manager.actions = append(manager.actions, action)
		log.Printf("Loaded action: %s", action.Name())
	}

	if len(manager.actions) == 0 {
		return nil, fmt.Errorf("no actions available")
	}

	return manager, nil
}

// Ban executes ban action across all configured actions
func (am *ActionManager) Ban(ip string) error {
	var errors []string

	for _, action := range am.actions {
		if err := action.Ban(ip); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", action.Name(), err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("ban failures: %s", strings.Join(errors, "; "))
	}

	return nil
}

// Unban executes unban action across all configured actions
func (am *ActionManager) Unban(ip string) error {
	var errors []string

	for _, action := range am.actions {
		if err := action.Unban(ip); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", action.Name(), err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("unban failures: %s", strings.Join(errors, "; "))
	}

	return nil
}

// Check verifies if IP is banned across any action
func (am *ActionManager) Check(ip string) (bool, error) {
	for _, action := range am.actions {
		banned, err := action.Check(ip)
		if err != nil {
			log.Printf("Check failed for %s: %v", action.Name(), err)
			continue
		}
		if banned {
			return true, nil
		}
	}
	return false, nil
}

// GetActions returns list of active actions
func (am *ActionManager) GetActions() []string {
	var names []string
	for _, action := range am.actions {
		names = append(names, action.Name())
	}
	return names
}

// createAction factory function for creating actions
func createAction(config ActionConfig) (Action, error) {
	switch config.Type {
	case "iptables":
		return NewIptablesAction(config)
	case "ufw":
		return NewUfwAction(config)
	case "firewalld":
		return NewFirewalldAction(config)
	case "nftables":
		return NewNftablesAction(config)
	case "route":
		return NewRouteAction(config)
	case "dummy":
		return NewDummyAction(config)
	default:
		return nil, fmt.Errorf("unknown action type: %s", config.Type)
	}
}

// IptablesAction implements iptables-based blocking
type IptablesAction struct {
	chain  string
	target string
	name   string
}

// NewIptablesAction creates a new iptables action
func NewIptablesAction(config ActionConfig) (*IptablesAction, error) {
	chain := config.Chain
	if chain == "" {
		chain = "INPUT"
	}

	target := config.Target
	if target == "" {
		target = "DROP"
	}

	return &IptablesAction{
		chain:  chain,
		target: target,
		name:   fmt.Sprintf("iptables[%s:%s]", chain, target),
	}, nil
}

func (i *IptablesAction) Ban(ip string) error {
	cmd := exec.Command("iptables", "-I", i.chain, "-s", ip, "-j", i.target)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables ban failed: %v, output: %s", err, output)
	}
	return nil
}

func (i *IptablesAction) Unban(ip string) error {
	cmd := exec.Command("iptables", "-D", i.chain, "-s", ip, "-j", i.target)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables unban failed: %v, output: %s", err, output)
	}
	return nil
}

func (i *IptablesAction) Check(ip string) (bool, error) {
	cmd := exec.Command("iptables", "-C", i.chain, "-s", ip, "-j", i.target)
	err := cmd.Run()
	return err == nil, nil
}

func (i *IptablesAction) Name() string {
	return i.name
}

func (i *IptablesAction) IsAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("iptables")
	return err == nil
}

// UfwAction implements UFW-based blocking
type UfwAction struct {
	name string
}

func NewUfwAction(config ActionConfig) (*UfwAction, error) {
	return &UfwAction{
		name: "ufw",
	}, nil
}

func (u *UfwAction) Ban(ip string) error {
	cmd := exec.Command("ufw", "insert", "1", "deny", "from", ip)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ufw ban failed: %v, output: %s", err, output)
	}
	return nil
}

func (u *UfwAction) Unban(ip string) error {
	cmd := exec.Command("ufw", "delete", "deny", "from", ip)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ufw unban failed: %v, output: %s", err, output)
	}
	return nil
}

func (u *UfwAction) Check(ip string) (bool, error) {
	cmd := exec.Command("ufw", "status", "numbered")
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(output), ip), nil
}

func (u *UfwAction) Name() string {
	return u.name
}

func (u *UfwAction) IsAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("ufw")
	return err == nil
}

// FirewalldAction implements firewalld-based blocking
type FirewalldAction struct {
	zone string
	name string
}

func NewFirewalldAction(config ActionConfig) (*FirewalldAction, error) {
	zone := config.Options["zone"]
	if zone == "" {
		zone = "drop"
	}

	return &FirewalldAction{
		zone: zone,
		name: fmt.Sprintf("firewalld[%s]", zone),
	}, nil
}

func (f *FirewalldAction) Ban(ip string) error {
	cmd := exec.Command("firewall-cmd", "--add-rich-rule=rule family=ipv4 source address="+ip+" drop")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("firewalld ban failed: %v, output: %s", err, output)
	}
	return nil
}

func (f *FirewalldAction) Unban(ip string) error {
	cmd := exec.Command("firewall-cmd", "--remove-rich-rule=rule family=ipv4 source address="+ip+" drop")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("firewalld unban failed: %v, output: %s", err, output)
	}
	return nil
}

func (f *FirewalldAction) Check(ip string) (bool, error) {
	cmd := exec.Command("firewall-cmd", "--list-rich-rules")
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(output), ip), nil
}

func (f *FirewalldAction) Name() string {
	return f.name
}

func (f *FirewalldAction) IsAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("firewall-cmd")
	if err != nil {
		return false
	}
	// Check if firewalld is actually running
	cmd := exec.Command("firewall-cmd", "--state")
	return cmd.Run() == nil
}

// NftablesAction implements nftables-based blocking
type NftablesAction struct {
	table string
	chain string
	name  string
}

func NewNftablesAction(config ActionConfig) (*NftablesAction, error) {
	table := config.Options["table"]
	if table == "" {
		table = "filter"
	}

	chain := config.Chain
	if chain == "" {
		chain = "input"
	}

	return &NftablesAction{
		table: table,
		chain: chain,
		name:  fmt.Sprintf("nftables[%s:%s]", table, chain),
	}, nil
}

func (n *NftablesAction) Ban(ip string) error {
	rule := fmt.Sprintf("ip saddr %s drop", ip)
	cmd := exec.Command("nft", "insert", "rule", n.table, n.chain, rule)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nftables ban failed: %v, output: %s", err, output)
	}
	return nil
}

func (n *NftablesAction) Unban(ip string) error {
	// This is more complex with nftables - need to find and delete the specific rule
	cmd := exec.Command("nft", "list", "table", n.table, "-a")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("nftables list failed: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) && strings.Contains(line, "drop") {
			parts := strings.Fields(line)
			if len(parts) > 0 && strings.HasPrefix(parts[len(parts)-1], "#") {
				handle := strings.TrimPrefix(parts[len(parts)-1], "#")
				delCmd := exec.Command("nft", "delete", "rule", n.table, n.chain, "handle", handle)
				if delOutput, delErr := delCmd.CombinedOutput(); delErr != nil {
					return fmt.Errorf("nftables unban failed: %v, output: %s", delErr, delOutput)
				}
				return nil
			}
		}
	}
	return fmt.Errorf("rule for IP %s not found", ip)
}

func (n *NftablesAction) Check(ip string) (bool, error) {
	cmd := exec.Command("nft", "list", "table", n.table)
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(output), ip), nil
}

func (n *NftablesAction) Name() string {
	return n.name
}

func (n *NftablesAction) IsAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("nft")
	return err == nil
}

// RouteAction implements null routing (route to blackhole)
type RouteAction struct {
	name string
}

func NewRouteAction(config ActionConfig) (*RouteAction, error) {
	return &RouteAction{
		name: "route",
	}, nil
}

func (r *RouteAction) Ban(ip string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "add", "blackhole", ip)
	case "darwin":
		cmd = exec.Command("route", "add", "-host", ip, "127.0.0.1")
	case "freebsd":
		cmd = exec.Command("route", "add", "-host", ip, "127.0.0.1")
	default:
		return fmt.Errorf("route action not supported on %s", runtime.GOOS)
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("route ban failed: %v, output: %s", err, output)
	}
	return nil
}

func (r *RouteAction) Unban(ip string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "del", "blackhole", ip)
	case "darwin", "freebsd":
		cmd = exec.Command("route", "delete", "-host", ip)
	default:
		return fmt.Errorf("route action not supported on %s", runtime.GOOS)
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("route unban failed: %v, output: %s", err, output)
	}
	return nil
}

func (r *RouteAction) Check(ip string) (bool, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "show", ip)
	case "darwin", "freebsd":
		cmd = exec.Command("route", "get", ip)
	default:
		return false, fmt.Errorf("route check not supported on %s", runtime.GOOS)
	}

	output, err := cmd.Output()
	if err != nil {
		return false, nil // Route doesn't exist
	}

	outputStr := string(output)
	return strings.Contains(outputStr, "blackhole") || strings.Contains(outputStr, "127.0.0.1"), nil
}

func (r *RouteAction) Name() string {
	return r.name
}

func (r *RouteAction) IsAvailable() bool {
	switch runtime.GOOS {
	case "linux":
		_, err := exec.LookPath("ip")
		return err == nil
	case "darwin", "freebsd":
		_, err := exec.LookPath("route")
		return err == nil
	default:
		return false
	}
}

// DummyAction for testing purposes
type DummyAction struct {
	name    string
	banned  map[string]time.Time
	enabled bool
}

func NewDummyAction(config ActionConfig) (*DummyAction, error) {
	return &DummyAction{
		name:    "dummy",
		banned:  make(map[string]time.Time),
		enabled: true,
	}, nil
}

func (d *DummyAction) Ban(ip string) error {
	if !d.enabled {
		return fmt.Errorf("dummy action disabled")
	}
	d.banned[ip] = time.Now()
	log.Printf("DUMMY: Banned IP %s", ip)
	return nil
}

func (d *DummyAction) Unban(ip string) error {
	if !d.enabled {
		return fmt.Errorf("dummy action disabled")
	}
	delete(d.banned, ip)
	log.Printf("DUMMY: Unbanned IP %s", ip)
	return nil
}

func (d *DummyAction) Check(ip string) (bool, error) {
	_, banned := d.banned[ip]
	return banned, nil
}

func (d *DummyAction) Name() string {
	return d.name
}

func (d *DummyAction) IsAvailable() bool {
	return d.enabled
}

// GetBannedIPs returns all banned IPs (for dummy action testing)
func (d *DummyAction) GetBannedIPs() map[string]time.Time {
	return d.banned
}
