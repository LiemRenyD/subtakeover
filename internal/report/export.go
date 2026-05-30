package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/liemreny/subtakeover/internal/storage"
)

// ExportJSON exports scan findings as JSON.
func ExportJSON(scan *storage.Scan) ([]byte, error) {
	type findingExport struct {
		Subdomain          string `json:"subdomain"`
		CNAMEChain         string `json:"cname_chain"`
		FingerprintService string `json:"fingerprint_service,omitempty"`
		TakeoverRisk       int    `json:"takeover_risk"`
		IsVulnerable       bool   `json:"is_vulnerable"`
		HTTPStatus         int    `json:"http_status,omitempty"`
		HTTPBodySnippet    string `json:"http_body_snippet,omitempty"`
		ErrorMsg           string `json:"error_msg,omitempty"`
		CheckedAt          string `json:"checked_at"`
	}

	var findings []findingExport
	for _, f := range scan.Findings {
		findings = append(findings, findingExport{
			Subdomain:          f.Subdomain,
			CNAMEChain:         f.CNAMEChain,
			FingerprintService: f.FingerprintService,
			TakeoverRisk:       f.TakeoverRisk,
			IsVulnerable:       f.IsVulnerable,
			HTTPStatus:         f.HTTPStatus,
			HTTPBodySnippet:    f.HTTPBodySnippet,
			ErrorMsg:           f.ErrorMsg,
			CheckedAt:          f.CheckedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	output := map[string]interface{}{
		"scan_id":    scan.ID,
		"domain":     scan.Domain,
		"started_at": scan.StartedAt.Format("2006-01-02T15:04:05Z"),
		"sources":    scan.Sources,
		"findings":   findings,
	}

	return json.MarshalIndent(output, "", "  ")
}

// ExportCSV exports scan findings as CSV.
func ExportCSV(scan *storage.Scan) ([]byte, error) {
	var buf strings.Builder
	w := csv.NewWriter(&buf)

	if err := w.Write([]string{"subdomain", "cname_chain", "fingerprint_service", "takeover_risk", "is_vulnerable", "http_status", "error_msg"}); err != nil {
		return nil, fmt.Errorf("csv write header: %w", err)
	}

	for _, f := range scan.Findings {
		vuln := "false"
		if f.IsVulnerable {
			vuln = "true"
		}
		if err := w.Write([]string{
			f.Subdomain,
			f.CNAMEChain,
			f.FingerprintService,
			strconv.Itoa(f.TakeoverRisk),
			vuln,
			strconv.Itoa(f.HTTPStatus),
			f.ErrorMsg,
		}); err != nil {
			return nil, fmt.Errorf("csv write row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("csv flush: %w", err)
	}
	return []byte(buf.String()), nil
}
