package fingerprint

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Rule defines a fingerprint rule for one cloud service.
type Rule struct {
	Service          string            `json:"service"`
	CNAMEPatterns    []string          `json:"cname_patterns"`
	HTTPFingerprints []HTTPFingerprint `json:"http_fingerprints"`
	RiskLevel        string            `json:"risk_level"`
	Remediation      string            `json:"remediation"`
}

// HTTPFingerprint is a status+body pattern to confirm takeover.
type HTTPFingerprint struct {
	Status       int    `json:"status"`
	BodyContains string `json:"body_contains"`
}

// Matcher loads rules and matches CNAME chains against them.
type Matcher struct {
	rules []Rule
}

// NewMatcher loads rules from the embedded JSON.
func NewMatcher(rulesJSON []byte) (*Matcher, error) {
	var rules []Rule
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse fingerprint rules JSON: %w", err)
	}
	return &Matcher{rules: rules}, nil
}

// Match checks each CNAME in the chain against known service patterns.
// Returns the first matching Rule and the matched CNAME, or nil if no match.
func (m *Matcher) Match(cnameChain []string) (*Rule, string) {
	for _, cname := range cnameChain {
		for i := range m.rules {
			if ruleMatchesCNAME(&m.rules[i], cname) {
				return &m.rules[i], cname
			}
		}
	}
	return nil, ""
}

func ruleMatchesCNAME(rule *Rule, cname string) bool {
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, pattern := range rule.CNAMEPatterns {
		if matchPattern(strings.ToLower(pattern), cname) {
			return true
		}
	}
	return false
}

// matchPattern matches a glob-style pattern against a hostname.
func matchPattern(pattern, target string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == target
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(target, suffix) {
			return true
		}
	}

	return false
}
