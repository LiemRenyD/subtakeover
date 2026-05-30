package report

import (
	"fmt"
	"os"

	"github.com/pterm/pterm"
	"gorm.io/gorm"

	"github.com/liemreny/subtakeover/internal/storage"
)

// Render renders scan results to terminal and optionally exports to file.
func Render(db *gorm.DB, scan *storage.Scan, format string, outputFile string) error {
	// Always show terminal table.
	PrintTerminalTable(scan)

	// Export to file if requested.
	if format == "" {
		return nil
	}

	var data []byte
	var err error
	switch format {
	case "json":
		data, err = ExportJSON(scan)
	case "csv":
		data, err = ExportCSV(scan)
	case "md", "markdown":
		data, err = ExportMarkdown(scan)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, data, 0644)
	}

	// If no output file, print to stdout.
	fmt.Println(string(data))
	return nil
}

// RenderScanByID loads a scan and renders it.
func RenderScanByID(db *gorm.DB, scanID uint, format string) error {
	scan, err := storage.GetScanByID(db, scanID)
	if err != nil {
		return fmt.Errorf("scan %d not found: %w", scanID, err)
	}
	PrintTerminalTable(scan)

	if format == "json" {
		data, _ := ExportJSON(scan)
		fmt.Println(string(data))
	} else if format == "csv" {
		data, _ := ExportCSV(scan)
		fmt.Println(string(data))
	}
	return nil
}

// RenderScanList prints a summary table of past scans using pterm.
func RenderScanList(db *gorm.DB, domain string, limit int) error {
	var scans []storage.Scan
	query := db.Model(&storage.Scan{}).Order("id DESC")
	if domain != "" {
		query = query.Where("domain = ?", domain)
	}
	if limit > 0 {
		query = query.Limit(limit)
	}
	query.Find(&scans)

	if len(scans) == 0 {
		pterm.Info.Println("No scans found.")
		return nil
	}

	tableData := pterm.TableData{
		{"ID", "Domain", "Started", "Status", "Subdomains", "Vulns"},
	}
	for _, s := range scans {
		status := s.Status
		tableData = append(tableData, []string{
			fmt.Sprintf("%d", s.ID),
			s.Domain,
			s.StartedAt.Format("2006-01-02 15:04"),
			status,
			fmt.Sprintf("%d", s.SubdomainCount),
			fmt.Sprintf("%d", s.VulnCount),
		})
	}

	return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
}
