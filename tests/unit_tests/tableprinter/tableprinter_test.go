package tableprinter

import (
	"AutomaticCVEResolver/services/tableprinter"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"testing"
	"time"
)

// Helper function to load CVE data from a file
func loadCVEDataFromFile(filename string) ([]tableprinter.CVEInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var cveList []tableprinter.CVEInfo
	err = json.Unmarshal(data, &cveList)
	if err != nil {
		return nil, err
	}

	// Ensure that dates are parsed correctly
	for i, cve := range cveList {
		cveList[i].Date, err = time.Parse("2006-01-02 15:04:05 -0700 MST", cve.Date.String())
		if err != nil {
			return nil, err
		}
	}

	return cveList, nil
}

// Test for valid CVE data
func TestPrintCVEResults_Valid(t *testing.T) {
	// Load valid CVE data from file
	cveList, err := loadCVEDataFromFile("testdata/valid_cve.json")
	if err != nil {
		t.Fatalf("Failed to load valid CVE data: %v", err)
	}

	// Capture output in a buffer
	output := captureOutput(func() {
		tableprinter.PrintCVEResults("container1", cveList)
	})

	// Updated expected output for comparison
	expectedOutput := "CVE Name|        Date|  Severity|  Current Version|  Resolved Version|Path\n" +
		"  CVE-2021-12345|  2024-01-01|  Critical|            1.2.3|             1.2.4|/path/to/libxyz\n" +
		"  CVE-2021-67890|  2024-01-01|      High|            1.2.3|             1.2.5|/path/to/otherlib\n"

	// Compare the captured output with the expected output
	if output != expectedOutput {
		t.Errorf("Expected output:\n%s\nGot:\n%s", expectedOutput, output)
	}
}

// Test for invalid CVE data (testing multiple cases)
func TestPrintCVEResults_InvalidCases(t *testing.T) {
	// Test 1: Invalid Date Format
	invalidDateData := []byte(`
	[
		{
			"cve_name": "CVE-2021-12345",
			"date": "InvalidDate",  // Invalid date format
			"severity": "Critical",
			"current_version": "1.2.3",
			"resolved_version": "1.2.4",
			"path": "/path/to/libxyz"
		}
	]`)
	var cveList []tableprinter.CVEInfo
	err := json.Unmarshal(invalidDateData, &cveList)
	assert.Error(t, err, "Expected error while parsing invalid date format, but got none")

	// Test 2: Missing Severity
	missingSeverityData := []byte(`
	[
		{
			"cve_name": "CVE-2021-67890",
			"date": "2024-01-01T00:00:00Z",
			"severity": "",
			"current_version": "1.2.3",
			"resolved_version": "1.2.5",
			"path": "/path/to/otherlib"
		}
	]`)
	err = json.Unmarshal(missingSeverityData, &cveList)
	assert.Error(t, err, "Expected error while parsing missing severity, but got none")

	// Test 3: Invalid Severity Value
	invalidSeverityData := []byte(`
	[
		{
			"cve_name": "CVE-2021-98765",
			"date": "2024-01-01T00:00:00Z",
			"severity": "InvalidSeverity",
			"current_version": "2.3.4",
			"resolved_version": "2.4.0",
			"path": "/path/to/badlib"
		}
	]`)
	err = json.Unmarshal(invalidSeverityData, &cveList)
	assert.NoError(t, err, "Unexpected error while parsing invalid severity")

	// Test 4: Corrupted JSON Structure
	corruptedJSONData := []byte(`
	[
		{
			"cve_name": "CVE-2021-54321",
			"date": "2024-01-01T00:00:00Z",
			"severity": "Low",
			"current_version": "3.2.1",
			"resolved_version": "3.2.5",
			"path": "/path/to/corrupted"
		`, // Missing closing brace
	)
	err = json.Unmarshal(corruptedJSONData, &cveList)
	assert.Error(t, err, "Expected error while parsing corrupted JSON, but got none")
}

// Helper function to capture output from a function
func captureOutput(f func()) string {
	// Redirect standard output to a buffer
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	err := w.Close()
	if err != nil {
		return ""
	}
	os.Stdout = old

	// Read output from the buffer
	var buf []byte
	buf, _ = io.ReadAll(r)
	return string(buf)
}
