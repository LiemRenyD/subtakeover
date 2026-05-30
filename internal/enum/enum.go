package enum

import (
	"strings"

	"golang.org/x/time/rate"

	"github.com/liemreny/subtakeover/internal/config"
)

// Enumerator collects subdomains from configured sources.
type Enumerator struct{}

// NewEnumerator creates a new enumerator.
func NewEnumerator() *Enumerator {
	return &Enumerator{}
}

// Gather collects subdomains for the given domains using the specified sources.
// Results are sent to the out channel. Closes the channel when done.
func (e *Enumerator) Gather(domains, sources []string, wordlistPath string, out chan<- string) {
	defer close(out)

	seen := make(map[string]bool)
	sourceSet := toSet(sources)

	for _, domain := range domains {
		if sourceSet["certspotter"] {
			limiter := rate.NewLimiter(rate.Limit(config.CrtShRate), config.EnumConcurrency)
			subs, err := fetchCrtSh(domain, limiter)
			if err == nil {
				for _, s := range subs {
					s = cleanSubdomain(s, domain)
					if s != "" && !seen[s] {
						seen[s] = true
						out <- s
					}
				}
			}
		}

		if sourceSet["brute"] && wordlistPath != "" {
			subs, err := bruteForce(domain, wordlistPath)
			if err == nil {
				for _, s := range subs {
					if !seen[s] {
						seen[s] = true
						out <- s
					}
				}
			}
		}
	}
}

func toSet(slice []string) map[string]bool {
	m := make(map[string]bool)
	for _, s := range slice {
		m[s] = true
	}
	return m
}

func cleanSubdomain(name, domain string) string {
	name = strings.TrimPrefix(name, "*.")
	if !strings.HasSuffix(name, "."+domain) && name != domain {
		return ""
	}
	return name
}
