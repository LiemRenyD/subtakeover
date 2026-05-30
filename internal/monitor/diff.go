package monitor

import (
	"encoding/json"
	"fmt"

	"github.com/pterm/pterm"
	"gorm.io/gorm"

	"github.com/liemreny/subtakeover/internal/storage"
)

// DiffResult holds the comparison between two scans.
type DiffResult struct {
	Domain     string
	PrevScanID uint
	CurrScanID uint
	New        []storage.Finding // newly vulnerable
	Fixed      []storage.Finding // was vulnerable, now safe
	Changed    []ChangedFinding  // CNAME or service changed
	Unchanged  int
}

// ChangedFinding is a finding whose state changed between scans.
type ChangedFinding struct {
	Subdomain   string
	PrevCNAME   string
	CurrCNAME   string
	PrevService string
	CurrService string
	PrevRisk    int
	CurrRisk    int
}

// Compare performs a diff between the latest two completed scans for a domain.
// lookback controls which Nth previous scan to compare against (default 1 = immediately previous).
func Compare(db *gorm.DB, domain string, lookback int) (*DiffResult, error) {
	// Get the N most recent completed scans.
	var scans []storage.Scan
	err := db.Where("domain = ? AND status = ?", domain, "completed").
		Order("id DESC").Limit(lookback + 1).Find(&scans).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query scans for domain %s: %w", domain, err)
	}
	if len(scans) < 2 {
		return nil, fmt.Errorf("need at least 2 completed scans for domain %s (found %d)", domain, len(scans))
	}

	// curr = most recent; prev = lookback-th previous scan.
	curr := &scans[0]
	prevIdx := lookback
	if prevIdx >= len(scans) {
		prevIdx = len(scans) - 1
	}
	prev := &scans[prevIdx]

	// Preload findings for both.
	db.Preload("Findings").First(curr, curr.ID)
	db.Preload("Findings").First(prev, prev.ID)

	result := &DiffResult{
		Domain:     domain,
		PrevScanID: prev.ID,
		CurrScanID: curr.ID,
	}

	// Index previous findings by subdomain.
	prevMap := make(map[string]storage.Finding)
	for _, f := range prev.Findings {
		prevMap[f.Subdomain] = f
	}

	// Build current finding index for the second pass.
	currSet := make(map[string]bool)
	for _, cf := range curr.Findings {
		currSet[cf.Subdomain] = true

		pf, existed := prevMap[cf.Subdomain]

		if !existed {
			// New subdomain.
			if cf.IsVulnerable {
				result.New = append(result.New, cf)
			} else {
				result.Unchanged++
			}
			continue
		}

		// Existed in previous scan.
		if cf.IsVulnerable && !pf.IsVulnerable {
			result.New = append(result.New, cf)
		} else if !cf.IsVulnerable && pf.IsVulnerable {
			result.Fixed = append(result.Fixed, cf)
		} else if cf.IsVulnerable && pf.IsVulnerable {
			// Both vulnerable — check if CNAME or service changed.
			if cf.CNAMEChain != pf.CNAMEChain || cf.FingerprintService != pf.FingerprintService {
				result.Changed = append(result.Changed, ChangedFinding{
					Subdomain:   cf.Subdomain,
					PrevCNAME:   shortCNAME(pf.CNAMEChain),
					CurrCNAME:   shortCNAME(cf.CNAMEChain),
					PrevService: pf.FingerprintService,
					CurrService: cf.FingerprintService,
					PrevRisk:    pf.TakeoverRisk,
					CurrRisk:    cf.TakeoverRisk,
				})
			}
		} else {
			result.Unchanged++
		}
	}

	// Count previously vulnerable subdomains that disappeared.
	for _, pf := range prev.Findings {
		if pf.IsVulnerable && !currSet[pf.Subdomain] {
			result.Fixed = append(result.Fixed, pf)
		}
	}

	return result, nil
}

func shortCNAME(cnameJSON string) string {
	var arr []string
	json.Unmarshal([]byte(cnameJSON), &arr)
	if len(arr) == 0 {
		return "—"
	}
	return arr[len(arr)-1]
}

// PrintDiff renders the diff as a color-coded pterm table.
// GREEN for newly discovered vulnerable subdomains.
// RED for fixed/removed vulnerabilities.
// YELLOW for changed states.
func PrintDiff(result *DiffResult) {
	fmt.Println()
	pterm.DefaultHeader.WithFullWidth().Printf("Monitor Diff: %s", result.Domain)
	fmt.Printf("Scan #%d → Scan #%d | New: %d | Fixed: %d | Changed: %d | Unchanged: %d\n\n",
		result.PrevScanID, result.CurrScanID,
		len(result.New), len(result.Fixed), len(result.Changed), result.Unchanged)

	if len(result.New) == 0 && len(result.Fixed) == 0 && len(result.Changed) == 0 {
		pterm.Success.Println("No changes detected between scans.")
		return
	}

	// New vulnerabilities — GREEN
	if len(result.New) > 0 {
		pterm.NewStyle(pterm.FgGreen, pterm.Bold).Println("▲ NEW VULNERABILITIES")
		tableData := pterm.TableData{{"Subdomain", "Service", "Risk", "CNAME"}}
		for _, f := range result.New {
			tableData = append(tableData, []string{
				f.Subdomain,
				f.FingerprintService,
				fmt.Sprintf("%d", f.TakeoverRisk),
				shortCNAME(f.CNAMEChain),
			})
		}
		renderColored(tableData, pterm.FgGreen)
		fmt.Println()
	}

	// Fixed vulnerabilities — RED
	if len(result.Fixed) > 0 {
		pterm.NewStyle(pterm.FgRed, pterm.Bold).Println("▼ FIXED / REMOVED")
		tableData := pterm.TableData{{"Subdomain", "Service", "Risk"}}
		for _, f := range result.Fixed {
			tableData = append(tableData, []string{
				f.Subdomain,
				f.FingerprintService,
				fmt.Sprintf("%d", f.TakeoverRisk),
			})
		}
		renderColored(tableData, pterm.FgRed)
		fmt.Println()
	}

	// Changed — YELLOW
	if len(result.Changed) > 0 {
		pterm.NewStyle(pterm.FgYellow, pterm.Bold).Println("◆ CHANGED STATE")
		tableData := pterm.TableData{{"Subdomain", "Prev CNAME", "Curr CNAME", "Prev Svc", "Curr Svc"}}
		for _, c := range result.Changed {
			tableData = append(tableData, []string{
				c.Subdomain,
				c.PrevCNAME,
				c.CurrCNAME,
				c.PrevService,
				c.CurrService,
			})
		}
		renderColored(tableData, pterm.FgYellow)
	}
}

func renderColored(data pterm.TableData, color pterm.Color) {
	style := pterm.NewStyle(color)
	for i, row := range data {
		if i == 0 {
			bold := pterm.NewStyle(color, pterm.Bold)
			for j := range row {
				data[i][j] = bold.Sprint(row[j])
			}
		} else {
			for j := range row {
				data[i][j] = style.Sprint(row[j])
			}
		}
	}
	pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}
