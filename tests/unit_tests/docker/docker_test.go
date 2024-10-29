package docker

import (
	"AutomaticCVEResolver/services/docker"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestListRunningContainers_Success(t *testing.T) {
	executor := &MockCommandExecutor{
		CommandOutputs: map[string]string{
			"docker ps --format {{.ID}} {{.Image}}": "12345 nginx\n67890 redis",
		},
		FailCommands: map[string]bool{},
	}
	ds := docker.NewDockerSBOMService(executor)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	containers, err := ds.ListRunningContainers(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(containers))
	assert.Contains(t, containers[0], "12345 nginx")
	assert.Contains(t, containers[1], "67890 redis")
}

func TestListRunningContainers_Fail(t *testing.T) {
	executor := &MockCommandExecutor{
		FailCommands: map[string]bool{
			"docker ps --format {{.ID}} {{.Image}}": true,
		},
	}
	ds := docker.NewDockerSBOMService(executor)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := ds.ListRunningContainers(ctx)
	assert.Error(t, err)
}

func TestGenerateSBOM_Success(t *testing.T) {
	executor := &MockCommandExecutor{
		CommandOutputs: map[string]string{
			"syft nginx -o json": `{"sbom": "nginx-sbom"}`,
			"syft redis -o json": `{"sbom": "redis-sbom"}`,
		},
	}
	ds := docker.NewDockerSBOMService(executor)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sbom, err := ds.GenerateSBOM(ctx, "nginx")
	assert.NoError(t, err)
	assert.Contains(t, sbom, "nginx-sbom")

	sbom, err = ds.GenerateSBOM(ctx, "redis")
	assert.NoError(t, err)
	assert.Contains(t, sbom, "redis-sbom")
}

func TestGenerateSBOMAndScanForCVEs_Success(t *testing.T) {
	executor := &MockCommandExecutor{
		CommandOutputs: map[string]string{
			"docker ps --format {{.ID}} {{.Image}}": "12345 nginx\n67890 redis",
			"syft nginx -o json":                    `{"sbom": "nginx-sbom"}`,
			"syft redis -o json":                    `{"sbom": "redis-sbom"}`,
			"grype nginx -o json":                   `{"vulnerabilities": [{"id": "CVE-2021-12345", "package": "libxyz", "severity": "Critical"}]}`,
			"grype redis -o json":                   `{"vulnerabilities": [{"id": "CVE-2021-67890", "package": "libabc", "severity": "High"}]}`,
		},
		FailCommands: map[string]bool{},
	}

	ds := docker.NewDockerSBOMService(executor)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Execute SBOM and CVE scan
	sbomResults, cveResults, err := ds.GenerateSBOMAndScanForCVEs(ctx)

	// Assert no errors and validate SBOM and CVE results
	assert.NoError(t, err)
	assert.Equal(t, 2, len(sbomResults))
	assert.Equal(t, 2, len(cveResults))

	// Validate SBOM outputs
	assert.Contains(t, sbomResults["12345"], "nginx-sbom")
	assert.Contains(t, sbomResults["67890"], "redis-sbom")

	// Validate CVE scan results for nginx
	assert.Contains(t, cveResults["12345"], `"CVE-2021-12345"`)
	assert.Contains(t, cveResults["12345"], `"package": "libxyz"`)
	assert.Contains(t, cveResults["12345"], `"severity": "Critical"`)

	// Validate CVE scan results for redis
	assert.Contains(t, cveResults["67890"], `"CVE-2021-67890"`)
	assert.Contains(t, cveResults["67890"], `"package": "libabc"`)
	assert.Contains(t, cveResults["67890"], `"severity": "High"`)
}

func TestGenerateSBOMAndScanForCVEs_FailSBOMGeneration(t *testing.T) {
	executor := &MockCommandExecutor{
		CommandOutputs: map[string]string{
			"docker ps --format {{.ID}} {{.Image}}": "12345 nginx\n67890 redis",
			"grype nginx -o json":                   `{"vulnerabilities": [{"id": "CVE-2021-12345", "package": "libxyz", "severity": "Critical"}]}`,
			"grype redis -o json":                   `{"vulnerabilities": [{"id": "CVE-2021-67890", "package": "libabc", "severity": "High"}]}`,
		},
		FailCommands: map[string]bool{
			"syft nginx -o json": true,
		},
	}

	ds := docker.NewDockerSBOMService(executor)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Execute SBOM and CVE scan with failure in SBOM generation
	sbomResults, cveResults, err := ds.GenerateSBOMAndScanForCVEs(ctx)

	// Assert no error but check that SBOM generation failed for nginx
	assert.NoError(t, err)
	assert.Equal(t, 1, len(sbomResults)) // Only redis should have an SBOM
	assert.Equal(t, 2, len(cveResults))  // CVE scan should still succeed for both

	// Validate CVE scan results
	assert.Contains(t, cveResults["12345"], `"CVE-2021-12345"`)
	assert.Contains(t, cveResults["67890"], `"CVE-2021-67890"`)
}

func TestGenerateSBOMAndScanForCVEs_FailCVEScan(t *testing.T) {
	executor := &MockCommandExecutor{
		CommandOutputs: map[string]string{
			"docker ps --format {{.ID}} {{.Image}}": "12345 nginx\n67890 redis",
			"syft nginx -o json":                    `{"sbom": "nginx-sbom"}`,
			"syft redis -o json":                    `{"sbom": "redis-sbom"}`,
		},
		FailCommands: map[string]bool{
			"grype nginx -o json": true,
		},
	}

	ds := docker.NewDockerSBOMService(executor)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Execute SBOM and CVE scan with failure in CVE scan for nginx
	sbomResults, cveResults, err := ds.GenerateSBOMAndScanForCVEs(ctx)

	// Assert no errors but CVE scan should fail for nginx
	assert.NoError(t, err)
	assert.Equal(t, 2, len(sbomResults)) // SBOM should succeed for both
	assert.Equal(t, 1, len(cveResults))  // Only redis should have a CVE scan

	// Validate CVE scan for redis
	assert.Contains(t, cveResults["67890"], `"CVE-2021-67890"`)
}
