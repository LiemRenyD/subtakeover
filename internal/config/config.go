package config

import (
	"time"
)

// DomainResult holds all findings for one subdomain after the full pipeline.
type DomainResult struct {
	Subdomain          string   `json:"subdomain"`
	CNAMEChain         []string `json:"cname_chain"`
	ARecords           []string `json:"a_records"`
	NXDomain           bool     `json:"nxdomain"`
	IsWildcard         bool     `json:"is_wildcard"`
	FingerprintService string   `json:"fingerprint_service,omitempty"`
	TakeoverRisk       int      `json:"takeover_risk"`
	IsVulnerable       bool     `json:"is_vulnerable"`
	HTTPStatus         int      `json:"http_status,omitempty"`
	HTTPBodySnippet    string   `json:"http_body_snippet,omitempty"`
	ErrorMsg           string   `json:"error_msg,omitempty"`
	CheckedAt          time.Time `json:"checked_at"`
}

// ScanConfig holds CLI flags for the scan command.
type ScanConfig struct {
	Domains       []string
	Sources       []string
	WordlistPath  string
	Concurrency   int
	RiskThreshold int
}

// DefaultScanConfig returns a ScanConfig with safe defaults.
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		Sources:       []string{"certspotter"},
		Concurrency:   50,
		RiskThreshold: 50,
	}
}

// Rate limits and concurrency settings for the scan pipeline.
const (
	// CrtShRate is the rate limit (req/s) for crt.sh API requests.
	CrtShRate = 5
	// DNSQPS is the maximum DNS queries per second.
	DNSQPS = 100
	// HTTPProbeRate is the rate limit for HTTP verification requests.
	HTTPProbeRate = 10
	// DNSConcurrency is the maximum concurrent DNS workers.
	DNSConcurrency = 50
	// HTTPConcurrency is the maximum concurrent HTTP workers.
	HTTPConcurrency = 10
	// EnumConcurrency is the maximum concurrent enumeration workers.
	EnumConcurrency = 3

	// DNSBufferSize is the buffered channel size for DNS result passing.
	DNSBufferSize = 200
	// EnumBufferSize is the buffered channel size for enumeration output.
	EnumBufferSize = 100
	// FingerprintBufSize is the buffered channel size for fingerprint results.
	FingerprintBufSize = 50
	// BatchBufSize is the buffered channel size for batch insert batches.
	BatchBufSize = 10

	// BatchInsertSize is the number of findings per batch insert to SQLite.
	BatchInsertSize = 100
	// BodySnippetLen is the max HTTP response body bytes to capture.
	BodySnippetLen = 500
	// DNSTimeout is the DNS query timeout.
	DNSTimeout = 3 * time.Second
	// CNAMEMaxDepth is the maximum CNAME chain depth before declaring a loop.
	CNAMEMaxDepth = 5
)
