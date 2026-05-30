package storage

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// CreateScan starts a new scan record.
func CreateScan(db *gorm.DB, domain string, sources []string) (*Scan, error) {
	srcJSON := marshalJSON(sources)
	scan := &Scan{
		Domain:    domain,
		StartedAt: time.Now(),
		Sources:   srcJSON,
		Status:    "running",
	}
	if err := db.Create(scan).Error; err != nil {
		return nil, fmt.Errorf("failed to create scan record: %w", err)
	}
	return scan, nil
}

// FinishScan marks a scan as completed.
func FinishScan(db *gorm.DB, scanID uint, subCount, vulnCount int) error {
	now := time.Now()
	if err := db.Model(&Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
		"finished_at":     &now,
		"subdomain_count": subCount,
		"vuln_count":      vulnCount,
		"status":          "completed",
	}).Error; err != nil {
		return fmt.Errorf("failed to finalize scan %d: %w", scanID, err)
	}
	return nil
}

// FailScan marks a scan as failed.
func FailScan(db *gorm.DB, scanID uint, errMsg string) error {
	now := time.Now()
	if err := db.Model(&Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
		"finished_at": &now,
		"status":      "failed",
	}).Error; err != nil {
		return fmt.Errorf("failed to mark scan %d as failed: %w", scanID, err)
	}
	return nil
}

// GetLatestScan returns the most recent completed scan for a domain.
func GetLatestScan(db *gorm.DB, domain string) (*Scan, error) {
	var scan Scan
	err := db.Where("domain = ? AND status = ?", domain, "completed").
		Order("id DESC").First(&scan).Error
	if err != nil {
		return nil, fmt.Errorf("no completed scan for domain %s: %w", domain, err)
	}
	return &scan, nil
}

// GetScanByID returns a scan by primary key.
func GetScanByID(db *gorm.DB, id uint) (*Scan, error) {
	var scan Scan
	err := db.Preload("Findings").First(&scan, id).Error
	if err != nil {
		return nil, fmt.Errorf("scan %d not found: %w", id, err)
	}
	return &scan, nil
}
