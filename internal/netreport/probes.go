package netreport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// runHTTPSProbe fetches the relay's probe path ("/ping") and times the round
// trip. It follows no redirects, matching run_https_probe
// (iroh/src/net_report/reportgen.rs:817). A non-2xx response is an error.
//
// tlsConfig, if non-nil, overrides TLS verification (used in tests with
// self-signed certs).
func runHTTPSProbe(ctx context.Context, relay netaddr.RelayURL, tlsConfig *tls.Config, proxy func(*url.URL) (*url.URL, error)) (*probeReport, error) {
	probeURL, err := joinPath(relay, relayProbePath)
	if err != nil {
		return nil, err
	}
	client := newProbeClient(tlsConfig, proxy)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("https request: %w", err)
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("https probe: unexpected status %d", resp.StatusCode)
	}
	// Drain the body (up to 8 KiB) to be polite to the server.
	drain(resp.Body, 8<<10)

	return &probeReport{probe: ProbeHTTPS, relay: relay, latency: latency}, nil
}

// checkCaptivePortal reports whether a captive portal is intercepting HTTP. It
// fetches "/generate_204" with an X-Iroh-Challenge header and requires both a
// 204 status and a matching X-Iroh-Response echo; otherwise a captive portal is
// assumed. It follows no redirects. Mirrors check_captive_portal
// (iroh/src/net_report/reportgen.rs:614).
func checkCaptivePortal(ctx context.Context, relay netaddr.RelayURL, tlsConfig *tls.Config, proxy func(*url.URL) (*url.URL, error)) (bool, error) {
	host := relay.Host()
	if host == "" {
		return false, fmt.Errorf("captive portal: %w", errMissingHost)
	}
	// The challenge is keyed on the bare hostname (no port), matching
	// reportgen.rs:614 (url.host_str()). The request, however, targets the
	// relay's actual host:port so a relay reachable on a non-default port (as
	// in tests) is honored; production relays listen on port 80 for this check.
	challenge := "ts_" + host
	authority := host
	if u := relay.URL(); u != nil && u.Host != "" {
		authority = u.Host
	}
	portalURL := "http://" + authority + captivePortalPath

	client := newProbeClient(tlsConfig, proxy)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, portalURL, nil)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set(challengeHeader, challenge)

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("captive portal request: %w", err)
	}
	defer resp.Body.Close()
	drain(resp.Body, 8<<10)

	want := "response " + challenge
	validResponse := resp.Header.Get(responseHeader) == want
	hasCaptive := resp.StatusCode != http.StatusNoContent || !validResponse
	return hasCaptive, nil
}

// errMissingHost is returned when a relay URL has no host component.
var errMissingHost = fmt.Errorf("relay url has no host")

// joinPath resolves path against the relay URL, mirroring RelayURL::join.
func joinPath(relay netaddr.RelayURL, path string) (string, error) {
	u := relay.URL()
	if u == nil {
		return "", fmt.Errorf("join: %w", errMissingHost)
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("join: %w", err)
	}
	return u.ResolveReference(ref).String(), nil
}

// newProbeClient builds an HTTP client that never follows redirects, mirroring
// the reqwest builders in reportgen.rs (redirect::Policy::none).
func newProbeClient(tlsConfig *tls.Config, proxy func(*url.URL) (*url.URL, error)) *http.Client {
	transport := &http.Transport{}
	if proxy != nil {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return proxy(req.URL)
		}
	}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// drain reads and discards up to limit bytes from r.
func drain(r interface{ Read([]byte) (int, error) }, limit int) {
	buf := make([]byte, 4096)
	read := 0
	for read < limit {
		n, err := r.Read(buf)
		read += n
		if err != nil {
			return
		}
	}
}

// lookupIPStaggered resolves host to IP addresses using the staggered retry
// schedule (dnsStaggerMs). Each delay starts a fresh lookup; the first to
// return wins and cancels the rest. It mirrors
// DnsResolver::lookup_ipv4_ipv6_staggered (iroh/src/address_lookup/dns.rs:22),
// bounded by dnsTimeout.
//
// resolver, if nil, defaults to net.DefaultResolver.
func lookupIPStaggered(ctx context.Context, resolver *net.Resolver, host string) ([]net.IPAddr, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	type result struct {
		addrs []net.IPAddr
		err   error
	}
	results := make(chan result, len(dnsStaggerMs)+1)

	// delays is the staggered schedule plus an immediate first attempt at 0ms,
	// matching how the Rust resolver fires the first call before the first
	// stagger delay.
	delays := append([]int{0}, dnsStaggerMs...)
	for _, ms := range delays {
		go func(delay time.Duration) {
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			}
			addrs, err := resolver.LookupIPAddr(ctx, host)
			select {
			case results <- result{addrs, err}:
			case <-ctx.Done():
			}
		}(time.Duration(ms) * time.Millisecond)
	}

	var lastErr error
	for range delays {
		select {
		case r := <-results:
			if r.err == nil && len(r.addrs) > 0 {
				return r.addrs, nil
			}
			if r.err != nil {
				lastErr = r.err
			}
		case <-ctx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no addresses for %s", host)
}
