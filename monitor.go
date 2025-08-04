package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"
	"time"
)

// Monitor handles log file monitoring and IP banning
type Monitor struct {
	config        *Config
	state         *MonitorState
	mu            sync.Mutex
	actionManager *ActionManager
	abuseReporter *ReporterManager
	stopCh        chan struct{}
	wg            sync.WaitGroup
	patterns      []*CompiledPattern
}

// CompiledPattern represents a compiled regex pattern
type CompiledPattern struct {
	Regex     *regexp.Regexp
	IPGroup   int
	Threshold int
	BanTime   time.Duration
	LogFile   string
}

// MonitorState represents the current state of the monitor
type MonitorState struct {
	Bans          map[string]*BanInfo  `json:"bans"`
	FailureCounts map[string]int       `json:"failure_counts"`
	LastSeen      map[string]time.Time `json:"last_seen"`
}

// BanInfo represents information about a banned IP
type BanInfo struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewMonitor creates a new monitor instance
func NewMonitor(config *Config) (*Monitor, error) {
	// Load or create state
	state, err := loadState()
	if err != nil {
		log.Printf("Failed to load state, starting fresh: %v", err)
		state = &MonitorState{
			Bans:          make(map[string]*BanInfo),
			FailureCounts: make(map[string]int),
			LastSeen:      make(map[string]time.Time),
		}
	}

	// Create action manager
	actionManager, err := NewActionManager(config.Actions)
	if err != nil {
		return nil, fmt.Errorf("failed to create action manager: %w", err)
	}

	// Create abuse reporter
	var abuseReporter *ReporterManager
	if config.AbuseReporting.Enabled {
		abuseReporter, err = NewReporterManager(&config.AbuseReporting)
		if err != nil {
			log.Printf("Failed to create abuse reporter: %v", err)
		}
	}

	m := &Monitor{
		config:        config,
		state:         state,
		actionManager: actionManager,
		abuseReporter: abuseReporter,
		stopCh:        make(chan struct{}),
	}

	// Compile patterns
	if err := m.compilePatterns(); err != nil {
		return nil, fmt.Errorf("failed to compile patterns: %w", err)
	}

	return m, nil
}

// compilePatterns compiles all regex patterns
func (m *Monitor) compilePatterns() error {
	for _, logFileConfig := range m.config.LogFiles {
		for _, patternConfig := range logFileConfig.Patterns {
			regex, err := regexp.Compile(patternConfig.Regex)
			if err != nil {
				return fmt.Errorf("failed to compile regex %s: %w", patternConfig.Regex, err)
			}

			banTime, err := time.ParseDuration(patternConfig.BanTime)
			if err != nil {
				return fmt.Errorf("failed to parse ban time %s: %w", patternConfig.BanTime, err)
			}

			compiledPattern := &CompiledPattern{
				Regex:     regex,
				IPGroup:   patternConfig.IPGroup,
				Threshold: patternConfig.Threshold,
				BanTime:   banTime,
				LogFile:   logFileConfig.Path,
			}

			m.patterns = append(m.patterns, compiledPattern)
		}
	}

	log.Printf("Compiled %d patterns", len(m.patterns))
	return nil
}

// Start begins monitoring log files
func (m *Monitor) Start() error {
	log.Printf("Starting monitor with %d log files", len(m.config.LogFiles))

	// Start cleanup routine
	m.wg.Add(1)
	go m.cleanupExpiredBans()

	// Start monitoring each log file
	for _, logFileConfig := range m.config.LogFiles {
		m.wg.Add(1)
		go m.monitorLogFile(logFileConfig)
	}

	return nil
}

// Stop stops the monitor
func (m *Monitor) Stop() {
	log.Println("Stopping monitor...")
	close(m.stopCh)
	m.wg.Wait()
	m.saveState()
	log.Println("Monitor stopped")
}

// monitorLogFile monitors a specific log file
func (m *Monitor) monitorLogFile(logFileConfig LogFileConfig) {
	defer m.wg.Done()

	log.Printf("Starting to monitor log file: %s", logFileConfig.Path)

	for {
		select {
		case <-m.stopCh:
			return
		default:
			if err := m.tailFile(logFileConfig.Path); err != nil {
				log.Printf("Error tailing file %s: %v", logFileConfig.Path, err)
				time.Sleep(5 * time.Second)
			}
		}
	}
}

// tailFile continuously reads from a log file
func (m *Monitor) tailFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	// Get initial file size and seek to end
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", filePath, err)
	}
	
	lastSize := stat.Size()
	file.Seek(0, 2) // Seek to end

	log.Printf("File %s opened successfully, starting from end (size: %d)", filePath, lastSize)

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return nil
		case <-ticker.C:
			// Check if file has grown
			stat, err := file.Stat()
			if err != nil {
				return fmt.Errorf("failed to stat file %s: %w", filePath, err)
			}

			currentSize := stat.Size()
			if currentSize > lastSize {
				// File has grown, read new content
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := scanner.Text()
					m.processLogLine(line, filePath)
				}
				lastSize = currentSize
			} else if currentSize < lastSize {
				// File was truncated/rotated, seek to beginning
				file.Seek(0, 0)
				lastSize = 0
			}
		}
	}
}

// processLogLine processes a single log line
func (m *Monitor) processLogLine(line, filePath string) {
	for _, pattern := range m.patterns {
		if pattern.LogFile == filePath {
			matches := pattern.Regex.FindStringSubmatch(line)
			if matches != nil && len(matches) > pattern.IPGroup {
				ip := matches[pattern.IPGroup]

				// Skip whitelisted IPs
				if m.config.IsWhitelisted(ip) {
					continue
				}

				m.handleFailedAttempt(ip, fmt.Sprintf("Pattern matched in %s", filePath), pattern)
			}
		}
	}
}

// handleFailedAttempt handles a failed attempt from an IP
func (m *Monitor) handleFailedAttempt(ip, reason string, pattern *CompiledPattern) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if IP is already banned
	if ban, exists := m.state.Bans[ip]; exists && time.Now().Before(ban.ExpiresAt) {
		return
	}

	// Increment failure count
	m.state.FailureCounts[ip]++
	m.state.LastSeen[ip] = time.Now()

	count := m.state.FailureCounts[ip]
	log.Printf("Failed attempt from %s (%d/%d): %s", ip, count, pattern.Threshold, reason)

	// Check if threshold is reached
	if count >= pattern.Threshold {
		if err := m.banIP(ip, reason, pattern.BanTime); err != nil {
			log.Printf("Failed to ban IP %s: %v", ip, err)
		}
	}

	m.saveState()
}

// banIP bans an IP address using the action manager
func (m *Monitor) banIP(ip, reason string, banTime time.Duration) error {
	// Execute ban using action manager
	if err := m.actionManager.Ban(ip); err != nil {
		return fmt.Errorf("failed to ban IP %s: %w", ip, err)
	}

	// Record ban in state
	ban := &BanInfo{
		IP:        ip,
		Reason:    reason,
		BannedAt:  time.Now(),
		ExpiresAt: time.Now().Add(banTime),
	}
	m.state.Bans[ip] = ban

	log.Printf("Banned IP %s for %v (reason: %s) using actions: %v",
		ip, banTime, reason, m.actionManager.GetActions())

	// Report to abuse databases
	if m.abuseReporter != nil {
		m.abuseReporter.ReportIP(ip, "unknown", "IP banned", nil)
	}

	return nil
}

// unbanIP removes a ban using the action manager
func (m *Monitor) unbanIP(ip string) error {
	// Execute unban using action manager
	if err := m.actionManager.Unban(ip); err != nil {
		return fmt.Errorf("failed to unban IP %s: %w", ip, err)
	}

	// Remove from state
	delete(m.state.Bans, ip)
	delete(m.state.FailureCounts, ip)

	log.Printf("Unbanned IP %s using actions: %v", ip, m.actionManager.GetActions())

	return nil
}

// cleanupExpiredBans removes expired bans
func (m *Monitor) cleanupExpiredBans() {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			var expiredIPs []string

			for ip, ban := range m.state.Bans {
				if now.After(ban.ExpiresAt) {
					expiredIPs = append(expiredIPs, ip)
				}
			}

			for _, ip := range expiredIPs {
				if err := m.unbanIP(ip); err != nil {
					log.Printf("Failed to unban expired IP %s: %v", ip, err)
				}
			}

			if len(expiredIPs) > 0 {
				m.saveState()
			}
			m.mu.Unlock()
		}
	}
}

// Stats represents statistics for the web interface
type Stats struct {
	TotalBans     int        `json:"total_bans"`
	TotalAttempts int        `json:"total_attempts"`
	RecentBans    int        `json:"recent_bans"`
	ActiveBans    []BanEntry `json:"active_bans"`
}

// BanEntry represents a banned IP for API responses
type BanEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetStats returns current statistics
func (m *Monitor) GetStats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats := Stats{
		TotalBans:  len(m.state.Bans),
		ActiveBans: make([]BanEntry, 0),
	}

	// Calculate recent bans (last hour)
	oneHourAgo := time.Now().Add(-time.Hour)

	for ip, ban := range m.state.Bans {
		if time.Now().Before(ban.ExpiresAt) {
			entry := BanEntry{
				IP:        ip,
				Reason:    ban.Reason,
				BannedAt:  ban.BannedAt,
				ExpiresAt: ban.ExpiresAt,
			}
			stats.ActiveBans = append(stats.ActiveBans, entry)

			if ban.BannedAt.After(oneHourAgo) {
				stats.RecentBans++
			}
		}
	}

	return stats
}

// loadState loads the monitor state from disk
func loadState() (*MonitorState, error) {
	data, err := os.ReadFile("monitor_state.json") // Fixed filename
	if err != nil {
		return nil, err
	}

	var state MonitorState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

// saveState saves the monitor state to disk
func (m *Monitor) saveState() error {
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile("monitor_state.json", data, 0644) // Fixed filename
}
