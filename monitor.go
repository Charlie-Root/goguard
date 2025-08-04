package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BanInfo represents information about a banned IP
type BanInfo struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Count     int       `json:"count"`
}

// IPCounter tracks failed attempts per IP
type IPCounter struct {
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// FileState tracks the state of a monitored log file
type FileState struct {
	LastSize        int64                `json:"last_size"`
	LastModTime     time.Time            `json:"last_mod_time"`
	LastLineNumber  int64                `json:"last_line_number"`
	ProcessedHashes map[string]time.Time `json:"processed_hashes"` // Hash -> timestamp for deduplication
}

// MonitorState represents persistent monitoring state
type MonitorState struct {
	FileStates map[string]*FileState `json:"file_states"`
	Counters   map[string]*IPCounter `json:"counters"`
	Bans       map[string]*BanInfo   `json:"bans"`
}

// Monitor handles log monitoring and IP blocking
type Monitor struct {
	config        *Config
	state         *MonitorState
	mu            sync.RWMutex
	patterns      map[string][]*regexp.Regexp
	whitelistNets []*net.IPNet
	firewall      Firewall
	abuseReporter *ReporterManager
}

// NewMonitor creates a new monitor instance
func NewMonitor(config *Config) (*Monitor, error) {
	// Create firewall instance
	firewall, err := NewFirewall(&config.Firewall)
	if err != nil {
		return nil, fmt.Errorf("failed to create firewall: %w", err)
	}

	// Initialize firewall
	if err := firewall.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize firewall: %w", err)
	}

	// Initialize abuse reporter
	abuseReporter, err := NewReporterManager(config.AbuseReporting)
	if err != nil {
		return nil, fmt.Errorf("failed to create abuse reporter: %w", err)
	}

	m := &Monitor{
		config:        config,
		firewall:      firewall,
		abuseReporter: abuseReporter,
		state: &MonitorState{
			FileStates: make(map[string]*FileState),
			Counters:   make(map[string]*IPCounter),
			Bans:       make(map[string]*BanInfo),
		},
		patterns: make(map[string][]*regexp.Regexp),
	}

	// Compile regex patterns
	for _, logFile := range config.LogFiles {
		var patterns []*regexp.Regexp
		for _, pattern := range logFile.Patterns {
			regex, err := regexp.Compile(pattern.Regex)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern %s: %w", pattern.Regex, err)
			}
			patterns = append(patterns, regex)
		}
		// Append patterns for duplicate file paths instead of overwriting
		if existingPatterns, exists := m.patterns[logFile.Path]; exists {
			m.patterns[logFile.Path] = append(existingPatterns, patterns...)
		} else {
			m.patterns[logFile.Path] = patterns
		}
	}

	// Parse whitelist networks
	for _, cidr := range config.Whitelist {
		if strings.Contains(cidr, "/") {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
			}
			m.whitelistNets = append(m.whitelistNets, ipNet)
		} else {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %s", cidr)
			}
			// Convert single IP to /32 or /128 network
			var ipNet *net.IPNet
			if ip.To4() != nil {
				_, ipNet, _ = net.ParseCIDR(cidr + "/32")
			} else {
				_, ipNet, _ = net.ParseCIDR(cidr + "/128")
			}
			m.whitelistNets = append(m.whitelistNets, ipNet)
		}
	}

	// Load existing state from JSON file if it exists
	m.loadState()

	return m, nil
}

// Start begins monitoring log files
func Start(m *Monitor) error {
	log.Println("Starting log monitoring...")

	// Start cleanup goroutine
	go m.cleanupExpiredBans()

	// Start state persistence goroutine
	go m.periodicStateSave()

	// Start monitoring each log file
	log.Printf("Starting %d monitoring goroutines...", len(m.config.LogFiles))
	for i, logFile := range m.config.LogFiles {
		log.Printf("Starting goroutine %d for: %s", i+1, logFile.Path)
		go m.monitorLogFile(logFile)
	}
	log.Printf("All monitoring goroutines started")

	return nil
}

// monitorLogFile monitors a single log file with proper line-by-line tracking
func (m *Monitor) monitorLogFile(logFile LogFile) {
	log.Printf("GOROUTINE STARTED for: %s", logFile.Path)

	// Get or create file state
	m.mu.Lock()
	fileState, exists := m.state.FileStates[logFile.Path]
	if !exists {
		log.Printf("Initializing file state for non existent file: %s", logFile.Path)
		// Initialize file state
		initialLineNumber := int64(0)
		if m.config.ProductionMode {
			// In production mode, start from end of file
			if lineCount := m.countLines(logFile.Path); lineCount > 0 {
				initialLineNumber = lineCount
			}
		}

		fileState = &FileState{
			LastSize:        0,
			LastModTime:     time.Time{},
			LastLineNumber:  initialLineNumber,
			ProcessedHashes: make(map[string]time.Time),
		}
		m.state.FileStates[logFile.Path] = fileState
	}
	m.mu.Unlock()

	for {
		// Check if file exists
		log.Printf("Checking if file exists: %s", logFile.Path)
		// Check file stats
		fileInfo, err := os.Stat(logFile.Path)
		if err != nil {
			// log.Printf("Error checking log file %s: %v", logFile.Path, err)
			time.Sleep(60 * time.Second)
			continue
		}

		// Log file access success (only once per file)
		m.mu.Lock()
		if fileState.LastSize == 0 && fileState.LastModTime.IsZero() {
			log.Printf("Successfully accessing log file: %s (size: %d bytes)", logFile.Path, fileInfo.Size())
		}
		m.mu.Unlock()

		// Check if file has changed
		currentSize := fileInfo.Size()
		currentModTime := fileInfo.ModTime()

		m.mu.Lock()
		hasChanged := currentSize != fileState.LastSize || !currentModTime.Equal(fileState.LastModTime)
		m.mu.Unlock()

		if !hasChanged {
			// File hasn't changed, sleep longer
			log.Printf("No changes detected in file: %s (size: %d bytes, mod time: %s)", logFile.Path, currentSize, currentModTime)
			time.Sleep(60 * time.Second)
			continue
		}

		// Process new lines
		newLines := m.processNewLines(logFile, fileState)
		log.Printf("Processing new lines in file: %s (size: %d bytes, mod time: %s)", logFile.Path, currentSize, currentModTime)
		// Update file state
		m.mu.Lock()
		fileState.LastSize = currentSize
		fileState.LastModTime = currentModTime
		m.mu.Unlock()

		if newLines > 0 {
			// Only log for auth.log to avoid spam
			if strings.Contains(logFile.Path, "auth.log") {
				log.Printf("Processed %d new lines from AUTH LOG: %s", newLines, logFile.Path)
			}
		}

		// Clean up old processed hashes (older than 24 hours)
		m.cleanupOldHashes(fileState)

		// Sleep for a minute before checking again
		time.Sleep(60 * time.Second)
	}
}

// countLines counts the total number of lines in a file
func (m *Monitor) countLines(filePath string) int64 {
	file, err := os.Open(filePath)
	if err != nil {
		// Log error for auth.log only
		if strings.Contains(filePath, "auth.log") {
			log.Printf("Error opening AUTH LOG for line count: %v", err)
		}
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lineCount int64
	for scanner.Scan() {
		lineCount++
	}

	if strings.Contains(filePath, "auth.log") {
		log.Printf("AUTH LOG line count: %d", lineCount)
	}

	return lineCount
}

// processNewLines processes new lines from a log file
func (m *Monitor) processNewLines(logFile LogFile, fileState *FileState) int {
	file, err := os.Open(logFile.Path)
	if err != nil {
		log.Printf("Error opening log file %s: %v", logFile.Path, err)
		return 0
	}
	defer file.Close()

	// For large files in production mode, only process the last 1000 lines to avoid hanging
	if m.config.ProductionMode {
		return m.processRecentLines(logFile, fileState, file, 1000)
	}

	scanner := bufio.NewScanner(file)
	var currentLineNumber int64 = 0
	var newLinesProcessed int = 0

	// Skip to the last processed line
	for scanner.Scan() && currentLineNumber < fileState.LastLineNumber {
		currentLineNumber++
	}

	// Process new lines
	for scanner.Scan() {
		currentLineNumber++
		line := scanner.Text()

		// Create hash for deduplication
		lineHash := m.createLineHash(line)

		m.mu.Lock()
		// Check if we've already processed this exact line recently
		if lastProcessed, exists := fileState.ProcessedHashes[lineHash]; exists {
			// Skip if processed within the last hour (to handle log rotation edge cases)
			if time.Since(lastProcessed) < time.Hour {
				m.mu.Unlock()
				continue
			}
		}

		// Mark as processed
		fileState.ProcessedHashes[lineHash] = time.Now()
		fileState.LastLineNumber = currentLineNumber
		m.mu.Unlock()

		// Process the line
		m.processLogLine(logFile, line)
		newLinesProcessed++
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading log file %s: %v", logFile.Path, err)
	}

	return newLinesProcessed
}

// processRecentLines processes only the last N lines of a file to avoid hanging on large files
func (m *Monitor) processRecentLines(logFile LogFile, fileState *FileState, file *os.File, maxLines int) int {
	log.Printf("Processing only last %d lines of large file: %s", maxLines, logFile.Path)

	// Get file size
	stat, err := file.Stat()
	if err != nil {
		return 0
	}

	// Start from near the end of the file
	fileSize := stat.Size()
	startPos := fileSize - int64(maxLines*100) // Estimate 100 bytes per line
	if startPos < 0 {
		startPos = 0
	}

	_, err = file.Seek(startPos, 0)
	if err != nil {
		return 0
	}

	scanner := bufio.NewScanner(file)
	var lines []string

	// Read all remaining lines
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Keep only the last maxLines
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}

	log.Printf("Processing %d recent lines from %s", len(lines), logFile.Path)

	// Process the recent lines
	newLinesProcessed := 0
	for _, line := range lines {
		// Process the line
		m.processLogLine(logFile, line)
		newLinesProcessed++
	}

	return newLinesProcessed
}

// createLineHash creates a hash for a log line for deduplication
func (m *Monitor) createLineHash(line string) string {
	hash := sha256.Sum256([]byte(line))
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes for efficiency
}

// cleanupOldHashes removes old processed hashes to prevent memory bloat
func (m *Monitor) cleanupOldHashes(fileState *FileState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	for hash, timestamp := range fileState.ProcessedHashes {
		if timestamp.Before(cutoff) {
			delete(fileState.ProcessedHashes, hash)
		}
	}

	// Also limit the total number of hashes to prevent memory issues
	if len(fileState.ProcessedHashes) > 10000 {
		// Keep only the most recent 5000 hashes
		type hashTime struct {
			hash string
			time time.Time
		}

		var hashes []hashTime
		for h, t := range fileState.ProcessedHashes {
			hashes = append(hashes, hashTime{h, t})
		}

		// Sort by time (most recent first) and keep only the first 5000
		for i := 0; i < len(hashes)-1; i++ {
			for j := i + 1; j < len(hashes); j++ {
				if hashes[i].time.Before(hashes[j].time) {
					hashes[i], hashes[j] = hashes[j], hashes[i]
				}
			}
		}

		// Clear and rebuild with only recent hashes
		fileState.ProcessedHashes = make(map[string]time.Time)
		limit := 5000
		if len(hashes) < limit {
			limit = len(hashes)
		}
		for i := 0; i < limit; i++ {
			fileState.ProcessedHashes[hashes[i].hash] = hashes[i].time
		}
	}
}

// processLogLine processes a single log line
func (m *Monitor) processLogLine(logFile LogFile, line string) {
	// Get all compiled patterns for this file path
	compiledPatterns := m.patterns[logFile.Path]

	for _, pattern := range logFile.Patterns {
		// Find the matching compiled regex for this pattern
		var regex *regexp.Regexp
		found := false

		// Search through all compiled patterns to find the one that matches this pattern's regex
		for _, compiledRegex := range compiledPatterns {
			if compiledRegex.String() == pattern.Regex {
				regex = compiledRegex
				found = true
				break
			}
		}

		if !found {
			log.Printf("ERROR: Could not find compiled regex for pattern: %s", pattern.Regex)
			continue
		}

		matches := regex.FindStringSubmatch(line)

		// Skip if no matches at all
		if len(matches) == 0 {
			continue
		}

		// Robust bounds checking - ensure IPGroup is valid and within bounds
		if pattern.IPGroup < 0 || pattern.IPGroup >= len(matches) {
			if len(matches) > 1 { // Only log if there were actual capture groups
				log.Printf("WARNING: Pattern matched but IPGroup %d is out of bounds (matches length: %d)",
					pattern.IPGroup, len(matches))
				log.Printf("WARNING: Pattern: %s", pattern.Regex)
				log.Printf("WARNING: Line: %s", line)
			}
			continue
		}

		// Extract IP from the specified capture group
		ip := matches[pattern.IPGroup]

		// Validate that the extracted IP is actually an IP address
		if net.ParseIP(ip) == nil {
			log.Printf("WARNING: Extracted value '%s' is not a valid IP address from pattern: %s", ip, pattern.Regex)
			continue
		}

		if m.isWhitelisted(ip) {
			continue
		}

		m.recordFailure(ip, pattern, line)
	}
}

// recordFailure records a failure attempt for an IP with improved persistence
func (m *Monitor) recordFailure(ip string, pattern Pattern, line string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if IP is already banned - if so, don't process further failures
	if _, isBanned := m.state.Bans[ip]; isBanned {
		return
	}

	now := time.Now()
	key := fmt.Sprintf("%s:%s", ip, pattern.Regex)

	counter, exists := m.state.Counters[key]
	if !exists {
		counter = &IPCounter{
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
		m.state.Counters[key] = counter
	} else {
		counter.Count++
		counter.LastSeen = now
	}

	log.Printf("Failure recorded for IP %s: count=%d, threshold=%d", ip, counter.Count, pattern.Threshold)

	// Check if threshold is reached
	if counter.Count >= pattern.Threshold {
		m.banIP(ip, pattern, fmt.Sprintf("Threshold reached: %d failures", counter.Count))
		// Remove the counter after banning to prevent repeated processing
		delete(m.state.Counters, key)
	}
}

// banIP bans an IP address
func (m *Monitor) banIP(ip string, pattern Pattern, reason string) {
	// Check if already banned
	if _, exists := m.state.Bans[ip]; exists {
		return
	}

	log.Printf("Banning IP %s: %s", ip, reason)

	// Record ban first (even if iptables fails, we want to track the ban attempt)
	ban := &BanInfo{
		IP:        ip,
		Reason:    reason,
		BannedAt:  time.Now(),
		ExpiresAt: time.Now().Add(pattern.BanTime),
		Count:     1,
	}

	m.state.Bans[ip] = ban

	// Generate pattern name for firewall comment if not provided
	patternName := pattern.Name
	if patternName == "" {
		// Create a fallback name based on regex pattern (first 50 chars)
		patternName = pattern.Regex
		if len(patternName) > 50 {
			patternName = patternName[:50] + "..."
		}
		// Replace problematic characters for firewall comments
		patternName = strings.ReplaceAll(patternName, " ", "_")
		patternName = strings.ReplaceAll(patternName, "\"", "'")
		patternName = strings.ReplaceAll(patternName, "\n", "_")
		patternName = strings.ReplaceAll(patternName, "\t", "_")
	}

	// Block IP using configured firewall
	if err := m.firewall.BlockIP(ip, patternName); err != nil {
		log.Printf("Failed to block IP %s with %s: %v", ip, m.firewall.GetType(), err)
		// Don't return here - we still want to track the ban even if firewall fails
	} else {
		log.Printf("IP %s banned with %s until %s (pattern: %s)", ip, m.firewall.GetType(), ban.ExpiresAt.Format(time.RFC3339), patternName)
	}

	// Report to abuse databases if configured
	if m.abuseReporter != nil {
		// Get pattern-specific categories if available
		var categories map[string]int
		if pattern.AbuseCategories != nil && len(pattern.AbuseCategories) > 0 {
			categories = pattern.AbuseCategories
		}

		// Report the IP asynchronously
		m.abuseReporter.ReportIP(ip, patternName, reason, categories)
	}
}

// isWhitelisted checks if an IP is whitelisted
func (m *Monitor) isWhitelisted(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, ipNet := range m.whitelistNets {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// cleanupExpiredBans removes expired bans
func (m *Monitor) cleanupExpiredBans() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		var expiredIPs []string

		for ip, ban := range m.state.Bans {
			if now.After(ban.ExpiresAt) {
				expiredIPs = append(expiredIPs, ip)
			}
		}

		for _, ip := range expiredIPs {
			log.Printf("Unbanning expired IP: %s", ip)
			if err := m.firewall.UnblockIP(ip); err != nil {
				log.Printf("Failed to unblock IP %s with %s: %v", ip, m.firewall.GetType(), err)
			}
			delete(m.state.Bans, ip)
		}

		m.mu.Unlock()
	}
}

// periodicStateSave saves state periodically
func (m *Monitor) periodicStateSave() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.saveState()
	}
}

// Stats represents statistics about the monitoring system
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
	Country   string    `json:"country,omitempty"`
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

// saveState saves current state to JSON file
func (m *Monitor) saveState() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal state: %v", err)
		return
	}

	if err := os.WriteFile("monitor_state.json", data, 0644); err != nil {
		log.Printf("Failed to save state: %v", err)
	}
}

// loadState loads state from JSON file
func (m *Monitor) loadState() {
	log.Println("Loading state from monitor_state.json...")
	data, err := os.ReadFile("monitor_state.json")
	if err != nil {
		log.Println("No existing state file found, starting fresh")
		return // File doesn't exist, that's OK
	}

	var state MonitorState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("Failed to load state: %v", err)
		return
	}

	// Initialize maps if they're nil
	if state.FileStates == nil {
		state.FileStates = make(map[string]*FileState)
	}
	if state.Counters == nil {
		state.Counters = make(map[string]*IPCounter)
	}
	if state.Bans == nil {
		state.Bans = make(map[string]*BanInfo)
	}

	// Initialize ProcessedHashes for each file state if nil
	for _, fileState := range state.FileStates {
		if fileState.ProcessedHashes == nil {
			fileState.ProcessedHashes = make(map[string]time.Time)
		}
	}

	m.state = &state

	log.Printf("State loaded with %d existing bans", len(m.state.Bans))

	// Skip restoring iptables rules on startup to prevent hanging
	// They will be recreated when new bans occur
	now := time.Now()
	var expiredIPs []string
	for ip, ban := range m.state.Bans {
		if now.After(ban.ExpiresAt) {
			expiredIPs = append(expiredIPs, ip)
		}
	}

	// Remove expired bans from state
	for _, ip := range expiredIPs {
		delete(m.state.Bans, ip)
	}

	log.Printf("Loaded monitoring state with %d active bans (skipped iptables restoration)", len(m.state.Bans))
}

// Cleanup removes all firewall rules created by this application
func (m *Monitor) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove all banned IPs
	for ip := range m.state.Bans {
		if err := m.firewall.UnblockIP(ip); err != nil {
			log.Printf("Failed to unblock IP %s during cleanup: %v", ip, err)
		}
	}

	// Cleanup firewall
	if err := m.firewall.Cleanup(); err != nil {
		log.Printf("Failed to cleanup firewall: %v", err)
	}

	// Save final state
	m.saveState()

	log.Printf("Cleanup completed for %s firewall", m.firewall.GetType())
}
