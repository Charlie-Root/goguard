package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// AbuseDBConfig represents configuration for AbuseDB.info reporting
type AbuseDBConfig struct {
	Enabled    bool   `yaml:"enabled"`
	APIKey     string `yaml:"api_key"`
	Categories []int  `yaml:"categories"`
}

// AbuseReport represents a report to be sent to abuse databases
type AbuseReport struct {
	IP          string    `json:"ip"`
	Categories  []int     `json:"categories"`
	Comment     string    `json:"comment"`
	Hostname    string    `json:"hostname"`
	PatternName string    `json:"pattern_name"`
	Timestamp   time.Time `json:"timestamp"`
}

// AbuseReporter interface defines methods for reporting IPs to abuse databases
type AbuseReporter interface {
	ReportIP(ctx context.Context, report AbuseReport) error
	GetName() string
	IsEnabled() bool
}

// ReporterManager manages multiple abuse reporters
type ReporterManager struct {
	reporters []AbuseReporter
	config    *AbuseReportingConfig
	hostname  string
	// Metrics for monitoring
	totalReports   int64
	successReports int64
	failedReports  int64
}

// NewReporterManager creates a new reporter manager
func NewReporterManager(config *AbuseReportingConfig) (*ReporterManager, error) {
	if config == nil || !config.Enabled {
		return &ReporterManager{
			reporters: []AbuseReporter{},
			config:    config,
		}, nil
	}

	// Get system hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
		log.Printf("Warning: Could not determine hostname: %v", err)
	}

	manager := &ReporterManager{
		reporters: []AbuseReporter{},
		config:    config,
		hostname:  hostname,
	}

	// Parse timeout string to duration
	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		timeout = 30 * time.Second // default timeout
		log.Printf("Warning: Could not parse timeout '%s', using default: %v", config.Timeout, timeout)
	}

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: timeout,
	}

	// Initialize AbuseIPDB reporter if enabled
	if config.AbuseIPDB.Enabled && config.AbuseIPDB.APIKey != "" {
		reporter := &AbuseIPDBReporter{
			config: &config.AbuseIPDB,
			client: httpClient,
		}
		manager.reporters = append(manager.reporters, reporter)
		log.Printf("AbuseIPDB reporter initialized")
	}

	// Initialize AbuseDB reporter if enabled
	if config.AbuseIPDB.Enabled && config.AbuseIPDB.APIKey != "" {
		reporter := &AbuseDBReporter{
			config: &AbuseDBConfig{
				Enabled:    config.AbuseIPDB.Enabled,
				APIKey:     config.AbuseIPDB.APIKey,
				Categories: config.AbuseIPDB.Categories,
			},
			client: httpClient,
		}
		manager.reporters = append(manager.reporters, reporter)
		log.Printf("AbuseDB reporter initialized")
	}

	// Add mock reporter for testing if no real reporters are configured
	if len(manager.reporters) == 0 && config.Enabled {
		manager.reporters = append(manager.reporters, &MockReporter{})
		log.Printf("Mock reporter initialized (no real reporters configured)")
	}

	return manager, nil
}

// ReportIP reports an IP to all enabled abuse databases
func (rm *ReporterManager) ReportIP(ip, patternName, reason string, categories map[string]int) {
	if rm.config == nil || !rm.config.Enabled || len(rm.reporters) == 0 {
		log.Printf("Abuse reporting disabled or no reporters configured for IP %s", ip)
		return
	}

	log.Printf("Starting abuse report for IP %s (pattern: %s, reason: %s)", ip, patternName, reason)

	// Create base report
	report := AbuseReport{
		IP:          ip,
		Comment:     fmt.Sprintf("%s banned on %s - %s", ip, rm.hostname, reason),
		Hostname:    rm.hostname,
		PatternName: patternName,
		Timestamp:   time.Now(),
	}

	// Report to each service asynchronously
	for _, reporter := range rm.reporters {
		if !reporter.IsEnabled() {
			log.Printf("Reporter %s is disabled, skipping", reporter.GetName())
			continue
		}

		// Set categories for this reporter
		if categories != nil {
			switch reporter.GetName() {
			case "abuseipdb":
				if cat, exists := categories["abuseipdb"]; exists {
					report.Categories = []int{cat}
					log.Printf("Using pattern-specific category %d for AbuseIPDB", cat)
				} else if len(rm.config.AbuseIPDB.Categories) > 0 {
					report.Categories = rm.config.AbuseIPDB.Categories
					log.Printf("Using default categories %v for AbuseIPDB", report.Categories)
				}
			case "abusedb":
				if cat, exists := categories["abusedb"]; exists {
					report.Categories = []int{cat}
					log.Printf("Using pattern-specific category %d for AbuseDB", cat)
				} else if len(rm.config.AbuseIPDB.Categories) > 0 {
					report.Categories = rm.config.AbuseIPDB.Categories
					log.Printf("Using default categories %v for AbuseDB", report.Categories)
				}
			}
		} else {
			// Use default categories
			switch reporter.GetName() {
			case "abuseipdb":
				if len(rm.config.AbuseIPDB.Categories) > 0 {
					report.Categories = rm.config.AbuseIPDB.Categories
					log.Printf("Using default categories %v for AbuseIPDB", report.Categories)
				}
			case "abusedb":
				if len(rm.config.AbuseIPDB.Categories) > 0 {
					report.Categories = rm.config.AbuseIPDB.Categories
					log.Printf("Using default categories %v for AbuseDB", report.Categories)
				}
			}
		}

		// Increment total reports counter
		rm.totalReports++
		log.Printf("Initiating report to %s for IP %s (total reports: %d)",
			reporter.GetName(), ip, rm.totalReports)

		// Report asynchronously - single attempt only
		go rm.reportSingleAttempt(reporter, report)
	}
}

// reportSingleAttempt reports to a single service with no retry logic
func (rm *ReporterManager) reportSingleAttempt(reporter AbuseReporter, report AbuseReport) {
	timeout, err := time.ParseDuration(rm.config.Timeout)
	if err != nil {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err = reporter.ReportIP(ctx, report)
	if err == nil {
		rm.successReports++
		log.Printf("✓ Successfully reported IP %s to %s (pattern: %s) - Success rate: %.2f%% (%d/%d)",
			report.IP, reporter.GetName(), report.PatternName,
			float64(rm.successReports)/float64(rm.totalReports)*100,
			rm.successReports, rm.totalReports)
		return
	}

	rm.failedReports++
	log.Printf("✗ Failed to report IP %s to %s: %v - Failure rate: %.2f%% (%d/%d)",
		report.IP, reporter.GetName(), err,
		float64(rm.failedReports)/float64(rm.totalReports)*100,
		rm.failedReports, rm.totalReports)
}

// AbuseIPDBReporter implements reporting to AbuseIPDB.com
type AbuseIPDBReporter struct {
	config *AbuseIPDBConfig
	client *http.Client
}

func (r *AbuseIPDBReporter) GetName() string {
	return "abuseipdb"
}

func (r *AbuseIPDBReporter) IsEnabled() bool {
	return r.config.Enabled && r.config.APIKey != ""
}

func (r *AbuseIPDBReporter) ReportIP(ctx context.Context, report AbuseReport) error {
	if !r.IsEnabled() {
		return fmt.Errorf("AbuseIPDB reporter is not enabled")
	}

	// Prepare form data
	data := url.Values{}
	data.Set("ip", report.IP)
	data.Set("comment", report.Comment)
	if len(report.Categories) > 0 {
		data.Set("categories", fmt.Sprintf("%d", report.Categories[0]))
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.abuseipdb.com/api/v2/report",
		strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Key", r.config.APIKey)
	req.Header.Set("Accept", "application/json")

	// Send request
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code - accept both 200 (OK) and 201 (Created) as success
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Try to parse and log structured response
	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err == nil {
		log.Printf("   Parsed Response: %+v", responseData)
	}

	return nil
}

// AbuseDBReporter implements reporting to AbuseDB.info
type AbuseDBReporter struct {
	config *AbuseDBConfig
	client *http.Client
}

func (r *AbuseDBReporter) GetName() string {
	return "abusedb"
}

func (r *AbuseDBReporter) IsEnabled() bool {
	return r.config.Enabled && r.config.APIKey != ""
}

func (r *AbuseDBReporter) ReportIP(ctx context.Context, report AbuseReport) error {
	if !r.IsEnabled() {
		return fmt.Errorf("AbuseDB reporter is not enabled")
	}

	// Prepare JSON payload
	payload := map[string]interface{}{
		"ip":      report.IP,
		"comment": report.Comment,
	}

	if len(report.Categories) > 0 {
		payload["categories"] = report.Categories
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://abusedb.info/api/v1/report",
		bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Key", r.config.APIKey)

	// Send request
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code - accept both 200 (OK) and 201 (Created) as success
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Try to parse and log structured response
	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err == nil {
		log.Printf("   Parsed Response: %+v", responseData)
	}

	return nil
}

// MockReporter implements a mock reporter for testing
type MockReporter struct {
	shouldFail bool
}

func (r *MockReporter) GetName() string {
	return "mock"
}

func (r *MockReporter) IsEnabled() bool {
	return true
}

func (r *MockReporter) ReportIP(ctx context.Context, report AbuseReport) error {
	if r.shouldFail {
		return fmt.Errorf("mock reporter configured to fail")
	}

	log.Printf("🧪 Mock reporter: Successfully reported IP %s", report.IP)
	log.Printf("   Categories: %v", report.Categories)
	log.Printf("   Comment: %s", report.Comment)
	log.Printf("   Pattern: %s", report.PatternName)
	log.Printf("   Hostname: %s", report.Hostname)
	log.Printf("   Timestamp: %s", report.Timestamp.Format(time.RFC3339))
	return nil
}

// GetMetrics returns current reporting metrics
func (rm *ReporterManager) GetMetrics() (total, success, failed int64) {
	return rm.totalReports, rm.successReports, rm.failedReports
}

// LogMetrics logs current reporting statistics
func (rm *ReporterManager) LogMetrics() {
	if rm.totalReports == 0 {
		log.Printf("📊 Abuse Reporting Metrics: No reports sent yet")
		return
	}

	successRate := float64(rm.successReports) / float64(rm.totalReports) * 100
	failureRate := float64(rm.failedReports) / float64(rm.totalReports) * 100

	log.Printf("📊 Abuse Reporting Metrics:")
	log.Printf("   Total Reports: %d", rm.totalReports)
	log.Printf("   Successful: %d (%.2f%%)", rm.successReports, successRate)
	log.Printf("   Failed: %d (%.2f%%)", rm.failedReports, failureRate)
	log.Printf("   Active Reporters: %d", len(rm.reporters))

	for _, reporter := range rm.reporters {
		status := "enabled"
		if !reporter.IsEnabled() {
			status = "disabled"
		}
		log.Printf("   - %s: %s", reporter.GetName(), status)
	}
}
