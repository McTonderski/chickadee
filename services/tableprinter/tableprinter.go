package tableprinter

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

// CVEInfo holds the details of a detected CVE
type CVEInfo struct {
	CVEName         string
	Date            time.Time
	Severity        string
	CurrentVersion  string
	ResolvedVersion string
	Path            string
}

// PrintCVEResults prints a table of CVE information
func PrintCVEResults(containerID string, cveList []CVEInfo) {
	// Create a tab writer for formatted output
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight|tabwriter.Debug)

	// Print the header
	fmt.Fprintln(writer, "CVE Name\tDate\tSeverity\tCurrent Version\tResolved Version\tPath")

	// Iterate over the CVE list and print each CVE's details
	for _, cve := range cveList {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\n",
			cve.CVEName,
			cve.Date.Format("2006-01-02"),
			cve.Severity,
			cve.CurrentVersion,
			cve.ResolvedVersion,
			cve.Path,
		)
	}

	// Flush the writer to ensure the table is printed
	writer.Flush()
}
