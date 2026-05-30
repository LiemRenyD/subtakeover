package enum

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// NOTE: bruteForce uses net.LookupHost which bypasses the miekg/dns rate-limited resolver.
// Consider routing brute-force DNS lookups through dns.Resolver for consistent rate limiting.
func bruteForce(domain string, wordlistPath string) ([]string, error) {
	f, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist %s: %w", wordlistPath, err)
	}
	defer f.Close()

	var subs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}
		sub := word + "." + domain
		_, err := net.LookupHost(sub)
		if err == nil {
			subs = append(subs, sub)
		}
	}
	return subs, scanner.Err()
}
