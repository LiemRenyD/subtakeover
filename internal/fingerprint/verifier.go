package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/time/rate"

	"github.com/liemreny/subtakeover/internal/config"
)

// VerifyResult holds HTTP verification output.
type VerifyResult struct {
	Service      string
	MatchedCNAME string
	RiskLevel    string
	Remediation  string
	HTTPStatus   int
	BodyMatch    bool
	Confidence   int // 0-100
}

// Verifier makes HTTP requests to confirm if a subdomain is vulnerable to takeover.
type Verifier struct {
	client  *http.Client
	limiter *rate.Limiter
}

// NewVerifier creates an HTTP verifier with the CLAUDE.md-mandated insecure client.
func NewVerifier() *Verifier {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 {
				req.Host = via[0].Host
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &Verifier{
		client:  client,
		limiter: rate.NewLimiter(rate.Limit(config.HTTPProbeRate), config.HTTPConcurrency),
	}
}

// Verify probes the subdomain via HTTPS and checks the response against
// the matched rule's HTTP fingerprints.
func (v *Verifier) Verify(subdomain string, rule *Rule) *VerifyResult {
	_ = v.limiter.Wait(context.Background())

	result := &VerifyResult{
		Service:     rule.Service,
		RiskLevel:   rule.RiskLevel,
		Remediation: rule.Remediation,
	}

	url := "https://" + subdomain
	resp, err := v.client.Get(url)
	if err != nil {
		result.Confidence = 50
		return result
	}
	defer resp.Body.Close()

	result.HTTPStatus = resp.StatusCode

	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(config.BodySnippetLen)))
	if readErr != nil && len(bodyBytes) == 0 {
		result.Confidence = 30
		return result
	}
	bodyStr := string(bodyBytes)

	for _, fp := range rule.HTTPFingerprints {
		if fp.Status == resp.StatusCode && strings.Contains(bodyStr, fp.BodyContains) {
			result.BodyMatch = true
			switch rule.RiskLevel {
			case "high":
				result.Confidence = 90
			case "medium":
				result.Confidence = 70
			case "low":
				result.Confidence = 50
			default:
				result.Confidence = 60
			}
			return result
		}
	}

	if resp.StatusCode == 404 {
		result.Confidence = 30
	} else {
		result.Confidence = 0
	}

	return result
}
