package dns

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"

	"github.com/liemreny/subtakeover/internal/config"
)

// Result holds DNS resolution output for one subdomain.
type Result struct {
	Subdomain  string
	CNAMEChain []string
	ARecords   []string
	NXDomain   bool
	Error      error
}

// Resolver performs DNS lookups with rate limiting and CNAME chain tracking.
type Resolver struct {
	client    *dns.Client
	limiter   *rate.Limiter
	server    string
	wildcards map[string]struct{} // IPs known to be wildcard
}

// NewResolver creates a DNS resolver with the given upstream server.
func NewResolver(server string) *Resolver {
	c := new(dns.Client)
	c.Timeout = config.DNSTimeout

	return &Resolver{
		client:    c,
		limiter:   rate.NewLimiter(rate.Limit(config.DNSQPS), config.DNSConcurrency),
		server:    server,
		wildcards: make(map[string]struct{}),
	}
}

// SetWildcards sets the set of wildcard IPs to filter against.
func (r *Resolver) SetWildcards(ips []string) {
	r.wildcards = make(map[string]struct{})
	for _, ip := range ips {
		r.wildcards[ip] = struct{}{}
	}
}

// Resolve resolves a subdomain, following CNAME chains up to max depth.
func (r *Resolver) Resolve(subdomain string) *Result {
	_ = r.limiter.Wait(context.Background()) // block until token available

	result := &Result{
		Subdomain:  subdomain,
		CNAMEChain: []string{},
		ARecords:   []string{},
	}

	seen := make(map[string]bool) // CNAME loop detection
	current := dns.Fqdn(subdomain)

	for depth := 0; depth <= config.CNAMEMaxDepth; depth++ {
		if seen[current] {
			result.Error = fmt.Errorf("CNAME loop detected at %s", current)
			return result
		}
		seen[current] = true

		msg := new(dns.Msg)
		msg.SetQuestion(current, dns.TypeA)
		msg.RecursionDesired = true

		resp, _, err := r.client.Exchange(msg, r.server)
		if err != nil {
			result.Error = err
			return result
		}

		if resp.Rcode == dns.RcodeNameError {
			result.NXDomain = true
			return result
		}

		if resp.Rcode != dns.RcodeSuccess {
			result.Error = fmt.Errorf("DNS rcode %d for %s", resp.Rcode, subdomain)
			return result
		}

		// Collect A records from this response.
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ip := a.A.String()
				if !r.isWildcard(ip) {
					result.ARecords = append(result.ARecords, ip)
				}
			}
		}

		// Check for CNAME. If found, follow it.
		cname := findCNAME(resp.Answer)
		if cname == "" {
			return result // No more CNAME to follow
		}

		result.CNAMEChain = append(result.CNAMEChain, cleanTrailing(cname))
		current = dns.Fqdn(cname)
	}

	result.Error = fmt.Errorf("CNAME depth exceeded max of %d", config.CNAMEMaxDepth)
	return result
}

func (r *Resolver) isWildcard(ip string) bool {
	_, ok := r.wildcards[ip]
	return ok
}

// findCNAME returns the first CNAME target in the answer section, or empty string.
func findCNAME(answers []dns.RR) string {
	for _, ans := range answers {
		if cname, ok := ans.(*dns.CNAME); ok {
			return cname.Target
		}
	}
	return ""
}

// cleanTrailing removes the trailing dot from FQDN strings.
func cleanTrailing(s string) string {
	return strings.TrimSuffix(s, ".")
}
