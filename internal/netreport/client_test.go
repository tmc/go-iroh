package netreport

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tmc/go-iroh/relay"
)

// newTestClient returns a Client with a controllable clock and no relays.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	c := NewClient(relay.NewMap())
	return c
}

// reportWith builds a Report whose only content is per-relay HTTPS latencies.
func reportWith(t *testing.T, latencies map[string]time.Duration) *Report {
	t.Helper()
	r := &Report{}
	for s, l := range latencies {
		r.RelayLatency.updateRelay(mustRelay(t, s), l, ProbeHTTPS)
	}
	return r
}

func TestPreferredRelaySelectsLowestLatency(t *testing.T) {
	c := newTestClient(t)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }

	r := reportWith(t, map[string]time.Duration{
		"https://a.example/": ms(80),
		"https://b.example/": ms(30),
		"https://c.example/": ms(50),
	})
	c.addReportHistoryAndSetPreferredRelay(r)

	if got := r.PreferredRelay.String(); got != "https://b.example/" {
		t.Errorf("PreferredRelay = %q, want b (lowest latency)", got)
	}
}

func TestPreferredRelayUsesLatencyOnlyQAD(t *testing.T) {
	c := newTestClient(t)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }

	a := mustRelay(t, "https://a.example/")
	b := mustRelay(t, "https://b.example/")
	r := &Report{}
	r.update(&probeReport{probe: ProbeQADv4, relay: a, latency: ms(20)})
	r.update(&probeReport{probe: ProbeHTTPS, relay: b, latency: ms(50)})

	c.addReportHistoryAndSetPreferredRelay(r)

	if got := r.PreferredRelay.String(); got != "https://a.example/" {
		t.Errorf("PreferredRelay = %q, want a from latency-only QAD", got)
	}
	if r.UDPv4 || r.GlobalV4.IsValid() {
		t.Fatalf("latency-only QAD set UDPv4=%v GlobalV4=%v", r.UDPv4, r.GlobalV4)
	}
}

func TestPreferredRelayHysteresis(t *testing.T) {
	// First report makes A preferred. A second report adds a slightly faster B,
	// but not 1/3 faster, so A should stick. A third report adds a much faster
	// C, so the preferred relay should switch.
	tests := []struct {
		name      string
		first     map[string]time.Duration
		second    map[string]time.Duration
		wantAfter string
	}{
		{
			name:      "marginally faster relay does not win (hysteresis holds)",
			first:     map[string]time.Duration{"https://a.example/": ms(60)},
			second:    map[string]time.Duration{"https://a.example/": ms(60), "https://b.example/": ms(50)},
			wantAfter: "https://a.example/",
		},
		{
			name:      "much faster relay wins (beats 2/3 threshold)",
			first:     map[string]time.Duration{"https://a.example/": ms(60)},
			second:    map[string]time.Duration{"https://a.example/": ms(60), "https://b.example/": ms(20)},
			wantAfter: "https://b.example/",
		},
		{
			name:      "exact 2/3 threshold wins",
			first:     map[string]time.Duration{"https://a.example/": ms(60)},
			second:    map[string]time.Duration{"https://a.example/": ms(60), "https://b.example/": ms(40)},
			wantAfter: "https://b.example/",
		},
		{
			name:      "old relay gone, switch to only candidate",
			first:     map[string]time.Duration{"https://a.example/": ms(60)},
			second:    map[string]time.Duration{"https://b.example/": ms(55)},
			wantAfter: "https://b.example/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			now := time.Unix(0, 0)
			c.now = func() time.Time { return now }

			r1 := reportWith(t, tt.first)
			c.addReportHistoryAndSetPreferredRelay(r1)

			now = now.Add(time.Second)
			r2 := reportWith(t, tt.second)
			c.addReportHistoryAndSetPreferredRelay(r2)

			if got := r2.PreferredRelay.String(); got != tt.wantAfter {
				t.Errorf("PreferredRelay after second report = %q, want %q", got, tt.wantAfter)
			}
		})
	}
}

func TestReportHistoryPrunedAfterMaxAge(t *testing.T) {
	c := newTestClient(t)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }

	// Old report establishes A as fast.
	c.addReportHistoryAndSetPreferredRelay(reportWith(t, map[string]time.Duration{
		"https://a.example/": ms(10),
	}))

	// Advance beyond MAX_AGE; the old A latency must no longer count.
	now = now.Add(reportHistoryMaxAge + time.Minute)

	// New report only has B; A should be pruned from bestRecent so B wins
	// outright (and there is no prevRelay anymore for hysteresis, since the
	// last report's preferred was A which is no longer in this report).
	r := reportWith(t, map[string]time.Duration{
		"https://b.example/": ms(40),
	})
	c.addReportHistoryAndSetPreferredRelay(r)

	if got := r.PreferredRelay.String(); got != "https://b.example/" {
		t.Errorf("PreferredRelay = %q, want b after pruning", got)
	}
	// Confirm the stale entry was removed.
	if len(c.prev) > 2 {
		t.Errorf("prev history has %d entries, expected pruning", len(c.prev))
	}
}

func TestGetReportEmptyRelayMap(t *testing.T) {
	c := newTestClient(t)
	rep, err := c.GetReport(context.Background(), IfStateDetails{HaveV4: true}, true)
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	if !rep.RelayLatency.isEmpty() {
		t.Error("expected empty relay latencies for empty map")
	}
	if !rep.PreferredRelay.IsZero() {
		t.Errorf("PreferredRelay = %q, want zero for empty map", rep.PreferredRelay)
	}
	if rep.CaptivePortal != nil {
		t.Error("captive portal should not run for empty relay map")
	}
}

func TestRunHTTPSProbe(t *testing.T) {
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path != relayProbePath {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	}))
	defer ts.Close()

	relayURL := mustRelay(t, ts.URL)
	rep, err := runHTTPSProbe(context.Background(), relayURL, insecureTLS(ts), nil)
	if err != nil {
		t.Fatalf("runHTTPSProbe: %v", err)
	}
	if rep.probe != ProbeHTTPS {
		t.Errorf("probe = %v, want HTTPS", rep.probe)
	}
	if rep.latency <= 0 {
		t.Errorf("latency = %v, want > 0", rep.latency)
	}
	if !rep.relay.Equal(relayURL) {
		t.Errorf("relay = %v, want %v", rep.relay, relayURL)
	}
	if gotPath != relayProbePath {
		t.Errorf("probe path = %q, want %q", gotPath, relayProbePath)
	}
}

func TestRunHTTPSProbeNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, err := runHTTPSProbe(context.Background(), mustRelay(t, ts.URL), insecureTLS(ts), nil)
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
}

func TestCheckCaptivePortal(t *testing.T) {
	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantCaptive bool
	}{
		{
			name: "valid 204 with matching response header is not captive",
			handler: func(w http.ResponseWriter, r *http.Request) {
				ch := r.Header.Get(challengeHeader)
				w.Header().Set(responseHeader, "response "+ch)
				w.WriteHeader(http.StatusNoContent)
			},
			wantCaptive: false,
		},
		{
			name: "wrong status is captive",
			handler: func(w http.ResponseWriter, r *http.Request) {
				ch := r.Header.Get(challengeHeader)
				w.Header().Set(responseHeader, "response "+ch)
				w.WriteHeader(http.StatusOK)
			},
			wantCaptive: true,
		},
		{
			name: "missing response header is captive",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			wantCaptive: true,
		},
		{
			name: "wrong response header is captive",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(responseHeader, "response ts_wrong")
				w.WriteHeader(http.StatusNoContent)
			},
			wantCaptive: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(captivePortalPath, tt.handler)
			ts := httptest.NewServer(mux)
			defer ts.Close()

			// checkCaptivePortal hits http://{host}/generate_204; rewrite the
			// relay url host to the test server so we control the response.
			relayURL := mustRelay(t, ts.URL)

			got, err := checkCaptivePortal(context.Background(), relayURL, nil, nil)
			if err != nil {
				t.Fatalf("checkCaptivePortal: %v", err)
			}
			if got != tt.wantCaptive {
				t.Errorf("captive = %v, want %v", got, tt.wantCaptive)
			}
		})
	}
}

func TestCheckCaptivePortalRequestShape(t *testing.T) {
	var gotPath, gotChallenge string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotChallenge = r.Header.Get(challengeHeader)
		w.Header().Set(responseHeader, "response "+gotChallenge)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	relayURL := mustRelay(t, ts.URL)
	got, err := checkCaptivePortal(context.Background(), relayURL, nil, nil)
	if err != nil {
		t.Fatalf("checkCaptivePortal: %v", err)
	}
	if got {
		t.Fatal("checkCaptivePortal = true, want false")
	}
	if gotPath != captivePortalPath {
		t.Errorf("captive portal path = %q, want %q", gotPath, captivePortalPath)
	}
	wantChallenge := "ts_" + relayURL.Host()
	if gotChallenge != wantChallenge {
		t.Errorf("%s = %q, want %q", challengeHeader, gotChallenge, wantChallenge)
	}
}

// insecureTLS returns a TLS config that trusts the httptest server's cert.
func insecureTLS(ts *httptest.Server) *tls.Config {
	if ts.TLS == nil {
		return nil
	}
	return &tls.Config{InsecureSkipVerify: true}
}
