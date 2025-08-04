package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const (
	version = "1.0.0-simple"
)

func main() {
	var (
		configFile  = flag.String("config", "config.yaml", "Path to configuration file")
		showVersion = flag.Bool("version", false, "Show version information")
		debug       = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("Fail2Ban Simple v%s\n", version)
		fmt.Println("A simplified fail2ban implementation in Go")
		os.Exit(0)
	}

	// Set up logging
	if *debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(log.LstdFlags)
	}

	log.Printf("Starting Fail2Ban Simple v%s", version)

	// Load configuration
	log.Println("Loading configuration...")
	config, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Loaded configuration from %s", *configFile)
	log.Printf("Monitoring %d log files", len(config.LogFiles))
	log.Printf("Web interface enabled: %v", config.Web.Enabled)

	// Create monitor
	log.Println("Creating monitor...")
	monitor, err := NewMonitor(config)
	if err != nil {
		log.Fatalf("Failed to create monitor: %v", err)
	}
	log.Println("Monitor created successfully")

	// Create web server
	webServer := NewWebServer(monitor, config)
	go func() {
		if err := webServer.Start(); err != nil {
			log.Printf("Web server error: %v", err)
		}
	}()
	log.Printf("Web interface available at http://localhost:%d", config.Web.Port)

	// Start monitor
	log.Println("Starting monitoring...")
	if err := monitor.Start(); err != nil {
		log.Fatalf("Failed to start monitor: %v", err)
	}
	log.Println("Monitoring started successfully")

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Fail2Ban Simple is running. Press Ctrl+C to stop.")

	// Wait for signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)

	log.Println("Shutting down...")

	// Stop monitor
	monitor.Stop()

	// Cleanup (remove iptables rules)
	log.Println("Cleaning up iptables rules...")
	// monitor.Cleanup()

	log.Println("Shutdown complete")
}
