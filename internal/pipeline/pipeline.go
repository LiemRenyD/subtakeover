package pipeline

import (
	"context"
	"fmt"
	"os"
	"sync"

	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/liemreny/subtakeover/internal/config"
	"github.com/liemreny/subtakeover/internal/dns"
	"github.com/liemreny/subtakeover/internal/enum"
	"github.com/liemreny/subtakeover/internal/fingerprint"
	"github.com/liemreny/subtakeover/internal/storage"
)

// Pipeline orchestrates the full scan: enum -> dns -> fingerprint -> storage.
type Pipeline struct {
	db       *gorm.DB
	resolver *dns.Resolver
	matcher  *fingerprint.Matcher
	verifier *fingerprint.Verifier
	config   config.ScanConfig
}

// New creates a new scan pipeline.
func New(db *gorm.DB, resolver *dns.Resolver, matcher *fingerprint.Matcher,
	verifier *fingerprint.Verifier, cfg config.ScanConfig) *Pipeline {
	return &Pipeline{
		db:       db,
		resolver: resolver,
		matcher:  matcher,
		verifier: verifier,
		config:   cfg,
	}
}

// Run executes the full scan for all configured domains.
func (p *Pipeline) Run(ctx context.Context) error {
	for _, domain := range p.config.Domains {
		if err := p.scanDomain(ctx, domain); err != nil {
			return fmt.Errorf("scan failed for domain %s: %w", domain, err)
		}
	}
	return nil
}

func (p *Pipeline) scanDomain(ctx context.Context, domain string) error {
	// 1. Detect wildcard DNS for this domain.
	wildcardIPs, _ := dns.DetectWildcard(domain, "8.8.8.8:53")
	if len(wildcardIPs) > 0 {
		p.resolver.SetWildcards(wildcardIPs)
	}

	// 2. Create scan record.
	scan, err := storage.CreateScan(p.db, domain, p.config.Sources)
	if err != nil {
		return fmt.Errorf("failed to create scan record: %w", err)
	}

	// 3. Channels connecting the pipeline stages.
	enumCh := make(chan string, config.EnumBufferSize)
	dnsCh := make(chan *dns.Result, config.DNSBufferSize)
	fingerCh := make(chan *config.DomainResult, config.FingerprintBufSize)
	batchCh := make(chan []storage.Finding, config.BatchBufSize)

	// 4. Start enumeration.
	go func() {
		enumerator := enum.NewEnumerator()
		enumerator.Gather([]string{domain}, p.config.Sources, p.config.WordlistPath, enumCh)
	}()

	// 5. DNS workers.
	var dnsWg sync.WaitGroup
	dnsLimiter := rate.NewLimiter(rate.Limit(config.DNSQPS), config.DNSConcurrency)
	for i := 0; i < config.DNSConcurrency; i++ {
		dnsWg.Add(1)
		go func() {
			defer dnsWg.Done()
			for sub := range enumCh {
				dnsLimiter.Wait(ctx)
				result := p.resolver.Resolve(sub)
				select {
				case dnsCh <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		dnsWg.Wait()
		close(dnsCh)
	}()

	// 6. Fingerprint workers.
	var fingerWg sync.WaitGroup
	for i := 0; i < config.HTTPConcurrency; i++ {
		fingerWg.Add(1)
		go func() {
			defer fingerWg.Done()
			for dr := range dnsCh {
				result := p.fingerprintResult(dr)
				select {
				case fingerCh <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		fingerWg.Wait()
		close(fingerCh)
	}()

	// 7. Batch accumulator goroutine.
	var writeWg sync.WaitGroup
	writeWg.Add(1)
	go func() {
		defer writeWg.Done()
		var batch []storage.Finding
		for fr := range fingerCh {
			finding := storage.DomainResultToFinding(scan.ID, fr)
			batch = append(batch, finding)
			if len(batch) >= config.BatchInsertSize {
				batchCopy := make([]storage.Finding, len(batch))
				copy(batchCopy, batch)
				select {
				case batchCh <- batchCopy:
				case <-ctx.Done():
					return
				}
				batch = batch[:0]
			}
		}
		// Flush remaining.
		if len(batch) > 0 {
			select {
			case batchCh <- batch:
			case <-ctx.Done():
				return
			}
		}
		close(batchCh)
	}()

	// 8. Single-goroutine SQLite writer.
	totalWritten, vulnsWritten := storage.BatchInsertFindings(p.db, batchCh)
	writeWg.Wait()

	// 9. Finalize scan.
	storage.FinishScan(p.db, scan.ID, totalWritten, vulnsWritten)

	return nil
}

func (p *Pipeline) fingerprintResult(dr *dns.Result) *config.DomainResult {
	result := &config.DomainResult{
		Subdomain:  dr.Subdomain,
		CNAMEChain: dr.CNAMEChain,
		ARecords:   dr.ARecords,
		NXDomain:   dr.NXDomain,
	}

	if dr.Error != nil {
		result.ErrorMsg = dr.Error.Error()
		return result
	}

	rule, _ := p.matcher.Match(dr.CNAMEChain)
	if rule == nil {
		return result
	}

	vr := p.verifier.Verify(dr.Subdomain, rule)

	result.FingerprintService = vr.Service
	result.HTTPStatus = vr.HTTPStatus
	result.TakeoverRisk = vr.Confidence
	result.IsVulnerable = vr.Confidence >= p.config.RiskThreshold

	return result
}

// LoadRules reads the fingerprint rules from the given file path.
func LoadRules(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %s: %w", path, err)
	}
	return data, nil
}
