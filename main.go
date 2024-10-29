package main

import (
	"AutomaticCVEResolver/services/docker"
	ntfyclient "AutomaticCVEResolver/services/ntfy"
	"AutomaticCVEResolver/services/tableprinter"
	"context"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"time"
)

// Define the configuration structure
type Config struct {
	Ntfy struct {
		ServerURL      string `yaml:"server_url"`
		Topic          string `yaml:"topic"`
		Username       string `yaml:"username"`
		Password       string `yaml:"password"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
	} `yaml:"ntfy"`
}

// Function to load configuration from a YAML file
func loadConfig(configFile string) (*Config, error) {
	file, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

func main() {
	// Initialize the NtfyClient
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Create Ntfy client using configuration values
	ntfy, err := ntfyclient.NewNtfyClient(
		config.Ntfy.ServerURL, // Ntfy server URL
		config.Ntfy.Topic,     // Topic
		config.Ntfy.Username,  // Username
		config.Ntfy.Password,  // Password
		time.Duration(config.Ntfy.TimeoutSeconds)*time.Second, // Timeout
	)
	if err != nil {
		log.Fatalf("Failed to initialize Ntfy client: %v", err)
	}

	// Initialize the notification service
	notificationService := docker.NewNotificationService(ntfy)

	// Initialize DockerSBOMService with RealCommandExecutor
	executor := &docker.RealCommandExecutor{}
	sbomService := docker.NewDockerSBOMService(executor)

	// Create a context with timeout for all operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Generate SBOMs and scan for CVEs for all running containers
	sbomResults, cveResults, err := sbomService.GenerateSBOMAndScanForCVEs(ctx)
	if err != nil {
		log.Fatalf("Error generating SBOMs and scanning for CVEs: %v", err)
	}

	// Print the SBOM results
	for containerID, sbom := range sbomResults {
		fmt.Printf("SBOM for container %s:\n%s\n", containerID, sbom)
	}

	// Print the CVE results and send notifications
	for containerID, cveReport := range cveResults {
		fmt.Printf("CVE Report for container %s:\n", containerID)
		tableprinter.PrintCVEResults(containerID, cveReport)
		// Format the title and message
		message := fmt.Sprintf("CVE Report for container %s:\n%s", containerID, cveReport)
		title := fmt.Sprintf("CVE Scan Results for Container %s", containerID)

		// Send a notification about the CVE scan
		err := notificationService.SendNotification(message, title)
		if err != nil {
			fmt.Printf("Failed to send notification for container %s: %v\n", containerID, err)
		}
	}

	// Send a final notification that the process is complete
	finalMessage := "SBOM and CVE scanning completed for all running containers"
	finalTitle := "Scan Complete"
	err = notificationService.SendNotification(finalMessage, finalTitle)
	if err != nil {
		fmt.Printf("Failed to send final notification: %v\n", err)
	}
}
