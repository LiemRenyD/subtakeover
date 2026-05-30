package report

import (
	"fmt"
	"strconv"

	"github.com/pterm/pterm"

	"github.com/liemreny/subtakeover/internal/storage"
)

// PrintTerminalTable renders a color-coded table of findings to the terminal.
// Vulnerable subdomains are highlighted in RED for demo video impact.
func PrintTerminalTable(scan *storage.Scan) {
	fmt.Println()
	pterm.DefaultHeader.WithFullWidth().Println("Scan Report: " + scan.Domain)
	fmt.Printf("Status: %s | Subdomains: %d | Vulnerabilities: %d\n\n",
		scan.Status, scan.SubdomainCount, scan.VulnCount)

	if len(scan.Findings) == 0 {
		pterm.Info.Println("No findings to display.")
		return
	}

	tableData := pterm.TableData{
		{"Subdomain", "CNAME Chain", "Service", "Risk", "HTTP", "Status"},
	}

	for _, f := range scan.Findings {
		risk := strconv.Itoa(f.TakeoverRisk)
		httpStatus := ""
		if f.HTTPStatus > 0 {
			httpStatus = strconv.Itoa(f.HTTPStatus)
		}

		status := "SAFE"
		if f.IsVulnerable {
			status = "VULNERABLE"
		}

		cname := f.CNAMEChain
		if len(cname) > 40 {
			cname = cname[:37] + "..."
		}

		row := []string{
			f.Subdomain,
			cname,
			f.FingerprintService,
			risk,
			httpStatus,
			status,
		}
		tableData = append(tableData, row)
	}

	// Render with pterm - vulnerable rows will be styled.
	renderColorTable(tableData)
}

func renderColorTable(data pterm.TableData) {
	headerStyle := pterm.NewStyle(pterm.FgCyan, pterm.Bold)
	redStyle := pterm.NewStyle(pterm.FgRed, pterm.Bold)

	for i, row := range data {
		if i == 0 {
			// Header row.
			for j, cell := range row {
				row[j] = headerStyle.Sprint(cell)
			}
			data[i] = row
			continue
		}
		// Data row - check if last column indicates vulnerable.
		if len(row) >= 6 && row[5] == "VULNERABLE" {
			for j := range row {
				row[j] = redStyle.Sprint(row[j])
			}
			data[i] = row
		}
	}

	pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

// RenderPtermTable renders arbitrary pterm table data.
func RenderPtermTable(data pterm.TableData) {
	pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}
