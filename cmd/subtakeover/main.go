package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/liemreny/subtakeover/internal/config"
	"github.com/liemreny/subtakeover/internal/dns"
	"github.com/liemreny/subtakeover/internal/fingerprint"
	"github.com/liemreny/subtakeover/internal/monitor"
	"github.com/liemreny/subtakeover/internal/pipeline"
	"github.com/liemreny/subtakeover/internal/report"
	"github.com/liemreny/subtakeover/internal/server"
	"github.com/liemreny/subtakeover/internal/storage"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "subtakeover",
	Short: "Subdomain takeover vulnerability scanner",
}

// ---- scan flags ----
var (
	scanDomains     []string
	scanSources     []string
	scanWordlist    string
	scanConcurrency int
	scanRisk        int
	scanOutput      string
	scanOutputFile  string
	dbPath          string
	rulesPath       string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan domains for subdomain takeover vulnerabilities",
	RunE: runScan,
}

// ---- history flags ----
var (
	histDomain     string
	histScanID     uint
	histFormat     string
	histLimit      int
	histVulnsOnly  bool
	histOutputFile string
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Query past scan results",
	RunE: runHistory,
}

// ---- monitor flags ----
var (
	monitorDomain   string
	monitorLookback int
)

// ---- serve flags ----
var (
	servePort   int
	serveNoOpen bool
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Compare latest scans and show diff",
	RunE: runMonitor,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the web dashboard",
	RunE: runServe,
}

func init() {
	// scan flags
	scanCmd.Flags().StringSliceVarP(&scanDomains, "domain", "d", nil, "target domain (required, repeatable)")
	scanCmd.Flags().StringSliceVar(&scanSources, "source", []string{"certspotter"}, "enumeration sources (certspotter,brute)")
	scanCmd.Flags().StringVarP(&scanWordlist, "wordlist", "w", "", "wordlist path for brute-force")
	scanCmd.Flags().IntVarP(&scanConcurrency, "concurrency", "c", 50, "max DNS worker count")
	scanCmd.Flags().IntVarP(&scanRisk, "risk-threshold", "r", 50, "takeover risk threshold (0-100)")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "export format: json, csv, md")
	scanCmd.Flags().StringVarP(&scanOutputFile, "output-file", "f", "", "export file path")
	scanCmd.Flags().StringVar(&dbPath, "db", "subtakeover.db", "SQLite database path")
	scanCmd.Flags().StringVar(&rulesPath, "rules", "internal/fingerprint/rules.json", "fingerprint rules file path")
	scanCmd.MarkFlagRequired("domain")

	// history flags
	historyCmd.Flags().StringVar(&histDomain, "domain", "", "filter by domain")
	historyCmd.Flags().UintVarP(&histScanID, "scan-id", "s", 0, "show findings for a specific scan ID")
	historyCmd.Flags().StringVarP(&histFormat, "format", "o", "table", "output format: table, json, csv, md")
	historyCmd.Flags().StringVarP(&histOutputFile, "output-file", "f", "", "export file path (for json/csv/md)")
	historyCmd.Flags().IntVarP(&histLimit, "limit", "n", 20, "max scans to show")
	historyCmd.Flags().BoolVarP(&histVulnsOnly, "vulns-only", "v", false, "show only vulnerable findings")

	// monitor flags
	monitorCmd.Flags().StringVarP(&monitorDomain, "domain", "d", "", "target domain (required)")
	monitorCmd.Flags().IntVarP(&monitorLookback, "last", "l", 1, "compare with Nth previous scan")
	monitorCmd.MarkFlagRequired("domain")

	// serve flags
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8080, "HTTP server port")
	serveCmd.Flags().BoolVar(&serveNoOpen, "no-open", false, "don't open browser")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(monitorCmd)
	rootCmd.AddCommand(serveCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg := config.ScanConfig{
		Domains:       scanDomains,
		Sources:       scanSources,
		WordlistPath:  scanWordlist,
		Concurrency:   scanConcurrency,
		RiskThreshold: scanRisk,
	}

	// Initialize storage.
	db, err := storage.NewDB(dbPath)
	if err != nil {
		return fmt.Errorf("database init failed: %w", err)
	}

	// Initialize DNS resolver.
	resolver := dns.NewResolver("8.8.8.8:53")

	// Initialize fingerprint engine.
	rulesJSON, err := pipeline.LoadRules(rulesPath)
	if err != nil {
		return fmt.Errorf("failed to load fingerprint rules: %w", err)
	}
	matcher, err := fingerprint.NewMatcher(rulesJSON)
	if err != nil {
		return fmt.Errorf("failed to parse fingerprint rules: %w", err)
	}
	verifier := fingerprint.NewVerifier()

	// Build and run pipeline.
	pipe := pipeline.New(db, resolver, matcher, verifier, cfg)
	ctx := context.Background()
	if err := pipe.Run(ctx); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Load the scan we just created and render results.
	latest, err := storage.GetLatestScan(db, cfg.Domains[0])
	if err != nil {
		return err
	}

	// Preload findings.
	db.Preload("Findings").First(latest, latest.ID)

	// Render terminal table + optional export.
	return report.Render(db, latest, scanOutput, scanOutputFile)
}

func runHistory(cmd *cobra.Command, args []string) error {
	db, err := storage.NewDB(dbPath)
	if err != nil {
		return fmt.Errorf("database init failed: %w", err)
	}

	if histScanID > 0 {
		scan, err := storage.GetScanByID(db, histScanID)
		if err != nil {
			return err
		}

		if histVulnsOnly {
			var vulnFindings []storage.Finding
			for _, f := range scan.Findings {
				if f.IsVulnerable {
					vulnFindings = append(vulnFindings, f)
				}
			}
			scan.Findings = vulnFindings
			scan.VulnCount = len(vulnFindings)
		}

		switch histFormat {
		case "json":
			data, _ := report.ExportJSON(scan)
			writeOrPrint(data, histOutputFile)
		case "csv":
			data, _ := report.ExportCSV(scan)
			writeOrPrint(data, histOutputFile)
		case "md":
			data, _ := report.ExportMarkdown(scan)
			writeOrPrint(data, histOutputFile)
		default:
			report.PrintTerminalTable(scan)
		}
		return nil
	}

	return report.RenderScanList(db, histDomain, histLimit)
}

func writeOrPrint(data []byte, path string) {
	if path != "" {
		os.WriteFile(path, data, 0644)
		fmt.Printf("Exported to %s\n", path)
	} else {
		fmt.Println(string(data))
	}
}

func runMonitor(cmd *cobra.Command, args []string) error {
	db, err := storage.NewDB(dbPath)
	if err != nil {
		return fmt.Errorf("database init failed: %w", err)
	}

	result, err := monitor.Compare(db, monitorDomain, monitorLookback)
	if err != nil {
		return fmt.Errorf("monitor diff failed: %w", err)
	}

	monitor.PrintDiff(result)
	return nil
}

func runServe(cmd *cobra.Command, args []string) error {
	db, err := storage.NewDB(dbPath)
	if err != nil {
		return fmt.Errorf("database init failed: %w", err)
	}

	srv := server.New(db, servePort)
	return srv.Start()
}
