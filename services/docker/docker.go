package docker

import (
	"AutomaticCVEResolver/services/tableprinter"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Worker pool limit
const maxConcurrency = 5

// DockerSBOMService is the service that interacts with Docker, generates SBOMs, and detects CVEs
type DockerSBOMService struct {
	executor CommandExecutor // Use the CommandExecutor interface
}

// NewDockerSBOMService creates a new DockerSBOMService with a given executor
func NewDockerSBOMService(executor CommandExecutor) *DockerSBOMService {
	return &DockerSBOMService{executor: executor}
}

// ListRunningContainers uses the Docker CLI to list running containers
func (ds *DockerSBOMService) ListRunningContainers(ctx context.Context) ([]string, error) {
	output, err := ds.executor.ExecCommand(ctx, "docker", "ps", "--format", "{{.ID}} {{.Image}}")
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("no running containers found")
	}
	return lines, nil
}

// GenerateSBOM generates SBOM for a given Docker container image using Syft
func (ds *DockerSBOMService) GenerateSBOM(ctx context.Context, imageName string) (string, error) {
	output, err := ds.executor.ExecCommand(ctx, "syft", imageName, "-o", "json")
	if err != nil {
		return "", fmt.Errorf("failed to generate SBOM: %v", err)
	}
	return string(output), nil
}

// ScanForCVEs scans a container image for known vulnerabilities using Grype
func (ds *DockerSBOMService) ScanForCVEs(ctx context.Context, imageName string) (string, error) {
	output, err := ds.executor.ExecCommand(ctx, "grype", imageName, "-o", "json")
	if err != nil {
		return "", fmt.Errorf("failed to scan for CVEs: %v", err)
	}
	return string(output), nil
}

func parseCVEs(cveReport string, cveList *[]tableprinter.CVEInfo) error {
	var grypeOutput struct {
		Matches []struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			} `json:"vulnerability"`
			Artifact struct {
				Version   string `json:"version"`
				Locations []struct {
					Path string `json:"path"`
				} `json:"locations"`
			} `json:"artifact"`
			Fix struct {
				State    string   `json:"state"`
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"matches"`
	}

	// Parse the JSON report
	err := json.Unmarshal([]byte(cveReport), &grypeOutput)
	if err != nil {
		return fmt.Errorf("failed to parse CVE report: %v", err)
	}

	// Populate CVEInfo structs
	for _, match := range grypeOutput.Matches {
		cve := tableprinter.CVEInfo{
			CVEName:         match.Vulnerability.ID,
			Date:            time.Now(), // Assuming current date since date is not in the report
			Severity:        match.Vulnerability.Severity,
			CurrentVersion:  match.Artifact.Version,
			ResolvedVersion: "", // Default to empty in case no resolved version is provided
			Path:            match.Artifact.Locations[0].Path,
		}

		// If a fix is available, populate the ResolvedVersion
		if len(match.Fix.Versions) > 0 {
			cve.ResolvedVersion = match.Fix.Versions[0]
		}

		*cveList = append(*cveList, cve)
	}

	return nil
}

func processContainer(ctx context.Context, containerID string, imageName string, ds *DockerSBOMService, sbomResults map[string]string, cveResults map[string][]tableprinter.CVEInfo, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()

	// Acquire the semaphore (blocks if full)
	sem <- struct{}{}
	defer func() {
		// Release the semaphore
		<-sem
	}()

	fmt.Printf("Generating SBOM for container %s (image: %s)\n", containerID, imageName)
	sbom, err := ds.GenerateSBOM(ctx, imageName)
	if err != nil {
		fmt.Printf("Error generating SBOM for %s: %v\n", imageName, err)
		return
	}
	sbomResults[containerID] = sbom

	fmt.Printf("Scanning for CVEs for container %s (image: %s)\n", containerID, imageName)
	cveReport, err := ds.ScanForCVEs(ctx, imageName)
	if err != nil {
		fmt.Printf("Error scanning for CVEs for %s: %v\n", imageName, err)
		return
	}
	// Parse the CVE report into CVEInfo structs
	var cveList []tableprinter.CVEInfo
	err = parseCVEs(cveReport, &cveList)
	if err != nil {
		fmt.Printf("Error parsing CVEs for %s: %v\n", imageName, err)
		return
	}

	// Store the parsed CVEs in the map
	cveResults[containerID] = cveList
}

// GenerateSBOMAndScanForCVEs generates SBOMs for all running containers and scans for vulnerabilities
func (ds *DockerSBOMService) GenerateSBOMAndScanForCVEs(ctx context.Context) (map[string]string, map[string][]tableprinter.CVEInfo, error) {
	containers, err := ds.ListRunningContainers(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Maps to store the results
	sbomResults := make(map[string]string)
	cveResults := make(map[string][]tableprinter.CVEInfo)

	// Channel to limit the number of concurrent goroutines
	sem := make(chan struct{}, maxConcurrency)

	// WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Loop through containers and process them concurrently
	for _, containerInfo := range containers {
		containerDetails := strings.Split(containerInfo, " ")
		containerID := containerDetails[0]
		imageName := containerDetails[1]

		// Increment the WaitGroup counter
		wg.Add(1)

		// Process each container in a separate goroutine
		go processContainer(ctx, containerID, imageName, ds, sbomResults, cveResults, &wg, sem)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	return sbomResults, cveResults, nil
}
