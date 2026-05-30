package storage

import (
	"encoding/json"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/liemreny/subtakeover/internal/config"
)

// marshalJSON safely marshals a value to a JSON string.
// Returns "[]" on marshal failure.
func marshalJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// DomainResultToFinding converts a pipeline result to a GORM Finding model.
func DomainResultToFinding(scanID uint, r *config.DomainResult) Finding {
	cnameJSON := marshalJSON(r.CNAMEChain)
	aJSON := marshalJSON(r.ARecords)

	return Finding{
		ScanID:             scanID,
		Subdomain:          r.Subdomain,
		CNAMEChain:         cnameJSON,
		ARecords:           aJSON,
		NXDomain:           r.NXDomain,
		Wildcard:           r.IsWildcard,
		FingerprintService: r.FingerprintService,
		TakeoverRisk:       r.TakeoverRisk,
		IsVulnerable:       r.IsVulnerable,
		HTTPStatus:         r.HTTPStatus,
		HTTPBodySnippet:    r.HTTPBodySnippet,
		ErrorMsg:           r.ErrorMsg,
		CheckedAt:          r.CheckedAt,
	}
}

// BatchInsertFindings writes findings in batches via a single goroutine.
// Call this from the batch writer goroutine. Returns total count and vuln count.
func BatchInsertFindings(db *gorm.DB, batchCh <-chan []Finding) (total int, vulns int) {
	for batch := range batchCh {
		if len(batch) == 0 {
			continue
		}
		if err := db.Clauses(clause.OnConflict{DoNothing: true}).
			CreateInBatches(batch, config.BatchInsertSize).Error; err != nil {
			continue
		}
		for _, f := range batch {
			total++
			if f.IsVulnerable {
				vulns++
			}
		}
	}
	return
}
