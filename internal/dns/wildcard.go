package dns

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/miekg/dns"

	"github.com/liemreny/subtakeover/internal/config"
)

// DetectWildcard probes a random subdomain to check if the domain uses wildcard DNS.
// Returns a list of IPs that resolve for the random subdomain (the wildcard IPs),
// or nil if no wildcard is detected.
func DetectWildcard(domain, server string) ([]string, error) {
	randomSub := randomHex(16) + "." + domain

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(randomSub), dns.TypeA)
	msg.RecursionDesired = true

	c := new(dns.Client)
	c.Timeout = config.DNSTimeout

	resp, _, err := c.Exchange(msg, server)
	if err != nil {
		return nil, fmt.Errorf("wildcard probe failed for %s: %w", domain, err)
	}

	if resp.Rcode == dns.RcodeNameError {
		return nil, nil // No wildcard — random sub doesn't resolve
	}

	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}

	return ips, nil
}

func randomHex(n int) string {
	b := make([]byte, n/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}
