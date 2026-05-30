package enum

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/time/rate"
)

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// crtShClient is a shared HTTP client for crt.sh requests, configured per CLAUDE.md mandates.
var crtShClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
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

func fetchCrtSh(domain string, limiter *rate.Limiter) ([]string, error) {
	_ = limiter.Wait(context.Background())

	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	resp, err := crtShClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse failed: %w", err)
	}

	seen := make(map[string]bool)
	var subdomains []string
	for _, e := range entries {
		name := e.NameValue
		if !seen[name] {
			seen[name] = true
			subdomains = append(subdomains, name)
		}
	}
	return subdomains, nil
}
