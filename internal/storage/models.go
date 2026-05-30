package storage

import (
	"time"

	"gorm.io/gorm"
)

// Scan represents one scan run.
type Scan struct {
	gorm.Model
	Domain         string     `gorm:"index;not null" json:"domain"`
	StartedAt      time.Time  `gorm:"not null" json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	SubdomainCount int        `gorm:"default:0" json:"subdomain_count"`
	VulnCount      int        `gorm:"default:0" json:"vuln_count"`
	Sources        string     `gorm:"default:'[]'" json:"sources"`
	Status         string     `gorm:"default:'running';index" json:"status"`
	Findings       []Finding  `gorm:"foreignKey:ScanID" json:"findings,omitempty"`
}

// Finding holds detailed results for one subdomain.
type Finding struct {
	gorm.Model
	ScanID             uint      `gorm:"index;not null" json:"scan_id"`
	Subdomain          string    `gorm:"not null" json:"subdomain"`
	CNAMEChain         string    `gorm:"default:'[]'" json:"cname_chain"`
	ARecords           string    `gorm:"default:'[]'" json:"a_records"`
	NXDomain           bool      `gorm:"default:false" json:"nxdomain"`
	Wildcard           bool      `gorm:"default:false" json:"wildcard"`
	FingerprintService string    `json:"fingerprint_service,omitempty"`
	TakeoverRisk       int       `gorm:"default:0" json:"takeover_risk"`
	IsVulnerable       bool      `gorm:"default:false;index" json:"is_vulnerable"`
	HTTPStatus         int       `json:"http_status,omitempty"`
	HTTPBodySnippet    string    `json:"http_body_snippet,omitempty"`
	ErrorMsg           string    `json:"error_msg,omitempty"`
	CheckedAt          time.Time `gorm:"not null" json:"checked_at"`
}
