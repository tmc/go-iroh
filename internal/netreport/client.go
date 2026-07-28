package netreport

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	itls "github.com/tmc/go-iroh/internal/itls/tls"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// IfStateDetails describes the host's interface capabilities, used to decide
// when enough probes have completed. It is a port of net_report's
// IfStateDetails (iroh/src/net_report/reportgen.rs:74).
type IfStateDetails struct {
	// HaveV4 reports whether the host has IPv4 connectivity.
	HaveV4 bool
	// HaveV6 reports whether the host has IPv6 connectivity.
	HaveV6 bool
}

// Client runs net_report probes against a set of relays and tracks report
// history so it can apply preferred-relay hysteresis across runs. It is a port
// of net_report::Client (iroh/src/net_report.rs:90).
//
// A Client is safe for concurrent use; GetReport serializes internally.
//
// The zero value is not usable; construct a Client with [NewClient].
type Client struct {
	relayMap *relay.Map

	// dnsResolver resolves relay hostnames for HTTPS and QAD probes. If nil,
	// net.DefaultResolver is used.
	dnsResolver *net.Resolver
	// tlsConfig overrides TLS verification for HTTPS probes (used in tests).
	tlsConfig *tls.Config
	// qadTLS supplies the QAD QUIC TLS verification policy. If nil, the relay's
	// WebPKI certificate is verified against the system roots. Tests set a
	// config with InsecureSkipVerify to trust a self-signed relay.
	qadTLS *itls.Config
	// quicConfig overrides QAD transport defaults; if nil, defaultQADConfig is
	// used.
	quicConfig *quic.Config
	// qadDialer, if non-nil, opens QAD probe connections; see WithQADDialer.
	qadDialer QADDialer
	// now returns the current time; overridable in tests for deterministic
	// hysteresis-window pruning.
	now func() time.Time

	mu       sync.Mutex
	last     *Report               // the most recent report
	prev     map[time.Time]*Report // reports within reportHistoryMaxAge
	lastFull time.Time             // when the last full report was generated
}

// NewClient returns a Client that probes the relays in relayMap.
func NewClient(relayMap *relay.Map) *Client {
	if relayMap == nil {
		relayMap = relay.NewMap()
	}
	return &Client{
		relayMap: relayMap,
		now:      time.Now,
		prev:     map[time.Time]*Report{},
	}
}

// WithDNSResolver sets the resolver used to look up relay hostnames.
func (c *Client) WithDNSResolver(r *net.Resolver) *Client {
	c.dnsResolver = r
	return c
}

// WithTLSConfig sets the TLS configuration used for HTTPS probes. It is used in
// tests to trust self-signed relay certificates.
func (c *Client) WithTLSConfig(cfg *tls.Config) *Client {
	c.tlsConfig = cfg
	return c
}

// WithQUICConfig sets the QAD QUIC transport configuration.
func (c *Client) WithQUICConfig(cfg *quic.Config) *Client {
	c.quicConfig = cfg
	return c
}

// WithQADTLSConfig sets the TLS verification policy for QAD QUIC connections.
// It is used in tests to trust a self-signed relay certificate.
func (c *Client) WithQADTLSConfig(cfg *itls.Config) *Client {
	c.qadTLS = cfg
	return c
}

// QADDialer opens the QUIC connection for one QAD probe to addr; tlsConf
// already carries the QAD ALPN and server name.
type QADDialer func(ctx context.Context, addr netip.AddrPort, tlsConf *itls.Config, cfg *quic.Config) (*quic.Conn, error)

// WithQADDialer routes QAD probes through d instead of a private per-probe
// UDP socket, so the observed address is the mapping of the dialer's own
// socket. A per-probe socket's mapping dies with it and its port is nobody's
// dial candidate; per-probe mappings also differ between relays, which makes
// MappingVariesByDest misreport symmetric NAT.
func (c *Client) WithQADDialer(d QADDialer) *Client {
	c.qadDialer = d
	return c
}

// dialQAD opens the QAD connection for a probe to addr, via the configured
// dialer or a private per-probe socket.
func (c *Client) dialQAD(ctx context.Context, addr netip.AddrPort, host string) (*qadConn, error) {
	if c.qadDialer == nil {
		return newQADClient(addr, host, c.qadTLS, c.quicConfig)
	}
	cfg := c.quicConfig
	if cfg == nil {
		cfg = defaultQADConfig()
	}
	ctx, cancel := context.WithTimeout(ctx, probesTimeout)
	defer cancel()
	conn, err := c.qadDialer(ctx, addr, qadTLSConfig(host, c.qadTLS), cfg)
	if err != nil {
		return nil, err
	}
	// ownsTransport stays false: the dialer's transport outlives the probe.
	return &qadConn{conn: conn}, nil
}

// GetReport runs a single net_report. doFull forces a full report (captive
// portal check and reset probe history); otherwise the report is full only if
// no report has been generated within [fullReportInterval]. ifState informs the
// sufficiency check.
//
// The whole call is bounded by [overallReportTimeout]; the probes within it are
// bounded by [probesTimeout].
//
// If the relay map is empty the report is empty: no probes run and
// PreferredRelay is the zero value.
func (c *Client) GetReport(ctx context.Context, ifState IfStateDetails, doFull bool) (*Report, error) {
	ctx, cancel := context.WithTimeout(ctx, overallReportTimeout)
	defer cancel()

	c.mu.Lock()
	full := doFull || c.last == nil || c.now().Sub(c.lastFull) >= fullReportInterval
	relayMap := c.relayMap
	c.mu.Unlock()

	report := &Report{Full: full}

	if !relayMap.IsEmpty() {
		c.runProbes(ctx, relayMap, report)

		// The captive-portal check runs only on full reports, and only after a
		// short delay so good QAD probes finish first
		// (iroh/src/net_report/reportgen.rs:278).
		if full {
			c.runCaptivePortal(ctx, relayMap, report)
		}
	}

	c.addReportHistoryAndSetPreferredRelay(report)

	c.mu.Lock()
	if full {
		c.lastFull = c.now()
	}
	c.mu.Unlock()

	return report, ctx.Err()
}

// runProbes runs the HTTPS and QAD probes for each relay in parallel, bounded
// by probesTimeout, and folds the results into report. QAD probes run on at
// most maxRelays relays.
func (c *Client) runProbes(ctx context.Context, relayMap *relay.Map, report *Report) {
	probeCtx, cancel := context.WithTimeout(ctx, probesTimeout)
	defer cancel()

	configs := relayMap.Configs()

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		reports []*probeReport
	)
	add := func(r *probeReport) {
		if r == nil {
			return
		}
		mu.Lock()
		reports = append(reports, r)
		mu.Unlock()
	}

	qadCount := 0
	for _, cfg := range configs {
		cfg := cfg
		// HTTPS probe for every relay.
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := runHTTPSProbe(probeCtx, cfg.URL, c.tlsConfig)
			if err == nil {
				add(r)
			}
		}()

		// QAD probes (v4 and v6) for up to maxRelays relays that enable QUIC.
		if cfg.QUIC != nil && qadCount < maxRelays {
			qadCount++
			wg.Add(2)
			go func() {
				defer wg.Done()
				add(c.runQADProbe(probeCtx, cfg, ProbeQADv4))
			}()
			go func() {
				defer wg.Done()
				add(c.runQADProbe(probeCtx, cfg, ProbeQADv6))
			}()
		}
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-probeCtx.Done():
	}

	// Fold results in a stable order so a report is deterministic given the
	// same probe outcomes.
	mu.Lock()
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].probe != reports[j].probe {
			return reports[i].probe < reports[j].probe
		}
		return reports[i].relay.Compare(reports[j].relay) < 0
	})
	for _, r := range reports {
		report.update(r)
	}
	mu.Unlock()
}

// runQADProbe resolves the relay's QUIC address for the given family, opens a
// QAD connection, records its RTT, captures any observed-address report that has
// already arrived, and gracefully closes it. If no report is available yet, the
// probe is latency-only (see the package doc).
func (c *Client) runQADProbe(ctx context.Context, cfg relay.Config, probe Probe) *probeReport {
	host := cfg.URL.Host()
	if host == "" {
		return nil
	}
	port := defaultRelayQuicPort
	if cfg.QUIC != nil && cfg.QUIC.Port != 0 {
		port = int(cfg.QUIC.Port)
	}

	addr, ok := c.resolveQADAddr(ctx, host, port, probe)
	if !ok {
		return nil
	}

	qad, err := c.dialQAD(ctx, addr, host)
	if err != nil {
		return nil
	}
	defer qad.close(qadCloseCode, qadCloseReason)

	// Read the connection RTT (iroh-relay/src/quic.rs:345) and the relay's
	// observed-address report, which observedAddr waits briefly for because it
	// is sent just after the handshake this dial already completed. It returns
	// ErrExtensionNotNegotiated when the relay does not report or none arrives
	// in time, in which case the probe is latency-only.
	latency := qad.rtt(0)
	addrPort, addrErr := qad.observedAddr(ctx)
	rep := &probeReport{probe: probe, relay: cfg.URL, latency: latency}
	if addrErr == nil {
		rep.addr = addrPort
	}
	return rep
}

// resolveQADAddr resolves host to an address of the family implied by probe and
// returns it with port. It returns ok=false if no matching address is found.
func (c *Client) resolveQADAddr(ctx context.Context, host string, port int, probe Probe) (netip.AddrPort, bool) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !addrMatchesProbe(ip, probe) {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(ip, uint16(port)), true
	}
	addrs, err := lookupIPStaggered(ctx, c.dnsResolver, host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if addrMatchesProbe(ip, probe) {
			return netip.AddrPortFrom(ip, uint16(port)), true
		}
	}
	return netip.AddrPort{}, false
}

func addrMatchesProbe(ip netip.Addr, probe Probe) bool {
	switch probe {
	case ProbeQADv4:
		return ip.Is4()
	case ProbeQADv6:
		return ip.Is6() && !ip.Is4In6()
	default:
		return false
	}
}

// runCaptivePortal runs the captive-portal check against one relay after a
// short delay, bounded by captivePortalTimeout, and records the result in
// report.CaptivePortal. iroh/src/net_report/reportgen.rs:614.
func (c *Client) runCaptivePortal(ctx context.Context, relayMap *relay.Map, report *Report) {
	select {
	case <-time.After(captivePortalDelay):
	case <-ctx.Done():
		return
	}

	urls := relayMap.URLs()
	if len(urls) == 0 {
		return
	}

	cpCtx, cancel := context.WithTimeout(ctx, captivePortalTimeout)
	defer cancel()

	has, err := checkCaptivePortal(cpCtx, urls[0], c.tlsConfig)
	if err != nil {
		return
	}
	report.CaptivePortal = boolPtr(has)
}

// addReportHistoryAndSetPreferredRelay adds r to the recent-report history,
// prunes reports older than reportHistoryMaxAge, and sets r.PreferredRelay to
// the relay with the best recent latency, applying hysteresis. It is a port of
// add_report_history_and_set_preferred_relay (iroh/src/net_report.rs:698).
func (c *Client) addReportHistoryAndSetPreferredRelay(r *Report) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var prevRelay netaddr.RelayURL
	if c.last != nil {
		prevRelay = c.last.PreferredRelay
		// Carry forward mapping-varies info when this report lacks it.
		if r.MappingVariesByDestV4 == nil {
			r.MappingVariesByDestV4 = c.last.MappingVariesByDestV4
		}
		if r.MappingVariesByDestV6 == nil {
			r.MappingVariesByDestV6 = c.last.MappingVariesByDestV6
		}
	}

	now := c.now()

	// Best recent latency per relay across the history window and this report.
	var bestRecent RelayLatencies
	for t, pr := range c.prev {
		if now.Sub(t) > reportHistoryMaxAge {
			delete(c.prev, t)
			continue
		}
		bestRecent.merge(&pr.RelayLatency)
	}
	bestRecent.merge(&r.RelayLatency)

	// Pick the currently-alive relay with the best recent latency, recording
	// the old preferred relay's current latency for the hysteresis check.
	var bestAny time.Duration
	var oldRelayCurLatency time.Duration

	// Iterate this report's relays in a deterministic order.
	relays := r.RelayLatency.relays()
	sort.Slice(relays, func(i, j int) bool { return relays[i].Compare(relays[j]) < 0 })

	havePreferred := false
	for _, url := range relays {
		cur, _ := r.RelayLatency.get(url)
		if !prevRelay.IsZero() && url.Equal(prevRelay) {
			oldRelayCurLatency = cur
		}
		best, ok := bestRecent.get(url)
		if ok && (!havePreferred || best < bestAny) {
			bestAny = best
			r.PreferredRelay = url
			havePreferred = true
		}
	}

	// Hysteresis: if we changed away from a still-responsive old relay but the
	// new one is not at least 1/3 faster, stick with the old one.
	// iroh/src/net_report.rs:760.
	if !prevRelay.IsZero() &&
		!r.PreferredRelay.Equal(prevRelay) &&
		oldRelayCurLatency != 0 &&
		bestAny > oldRelayCurLatency/3*2 {
		r.PreferredRelay = prevRelay
	}

	stored := *r
	c.prev[now] = &stored
	last := *r
	c.last = &last
}
