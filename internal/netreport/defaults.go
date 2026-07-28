package netreport

import "time"

// Timeouts and intervals matching the Rust net_report defaults. Values are
// cited to the iroh source so they can be re-verified on upgrades.
const (
	// overallReportTimeout bounds a whole GetReport call.
	// iroh/src/net_report/defaults.rs:14,17 (TIMEOUT=5).
	overallReportTimeout = 5 * time.Second

	// probesTimeout bounds the entire set of HTTPS and QAD probes; it is not
	// applied per probe. iroh/src/net_report/defaults.rs:23.
	probesTimeout = 3 * time.Second

	// captivePortalDelay is how long to wait before starting the captive-portal
	// check, so good QAD probes finish first.
	// iroh/src/net_report/defaults.rs:30.
	captivePortalDelay = 200 * time.Millisecond

	// captivePortalTimeout bounds the captive-portal check.
	// iroh/src/net_report/defaults.rs:36.
	captivePortalTimeout = 2 * time.Second

	// dnsTimeout bounds a single staggered DNS lookup.
	// iroh/src/net_report/defaults.rs:38.
	dnsTimeout = 3 * time.Second

	// fullReportInterval is the minimum time between full reports; reports in
	// between are incremental. iroh/src/net_report.rs:86.
	fullReportInterval = 5 * time.Minute

	// reportHistoryMaxAge is how long a previous report contributes to relay
	// selection. iroh/src/net_report.rs:713 (MAX_AGE).
	reportHistoryMaxAge = 5 * time.Minute
)

// maxRelays is the maximum number of relays probed with QAD in one report.
// iroh/src/net_report/reportgen.rs:446 (MAX_RELAYS).
const maxRelays = 5

// dnsStaggerMs is the per-resolver retry schedule (in milliseconds) used for
// staggered DNS lookups. iroh/src/address_lookup/dns.rs:22 (DNS_STAGGERING_MS).
var dnsStaggerMs = []int{200, 300, 600, 1000, 2000, 3000}

// QAD wire and transport constants. These must match the Rust relay so QAD
// connections interoperate; iroh-relay/src/quic.rs and defaults.rs.
const (
	// alpnQAD is the ALPN advertised for QUIC Address Discovery.
	// iroh-relay/src/quic.rs:10 (ALPN_QUIC_ADDR_DISC).
	alpnQAD = "/iroh-qad/0"

	// qadCloseCode is the application error code used to close a QAD
	// connection. iroh-relay/src/quic.rs:12 (QUIC_ADDR_DISC_CLOSE_CODE = 1).
	qadCloseCode = 1

	// qadInitialRTT lowers the initial RTT estimate so a lost QAD probe times
	// out quickly. iroh-relay/src/quic.rs:293.
	qadInitialRTT = 111 * time.Millisecond

	// qadKeepAlive keeps a QAD connection alive.
	// iroh-relay/src/quic.rs:297.
	qadKeepAlive = 25 * time.Second

	// qadObservedAddrWait bounds the wait for the relay's OBSERVED_ADDRESS
	// report after the QAD handshake: one round trip normally, and a relay
	// that negotiated but never reports must not stall the probe.
	qadObservedAddrWait = time.Second
	// qadMaxIdle is the QAD connection idle timeout.
	// iroh-relay/src/quic.rs:298-300.
	qadMaxIdle = 35 * time.Second

	// defaultRelayQuicPort is the relay's default QUIC port.
	// iroh-relay/src/defaults.rs:7 (DEFAULT_RELAY_QUIC_PORT).
	defaultRelayQuicPort = 7842

	// relayProbePath is the HTTPS probe path on a relay.
	// iroh-relay/src/http.rs:15 (RELAY_PROBE_PATH).
	relayProbePath = "/ping"

	// captivePortalPath is fetched to detect a captive portal.
	// iroh/src/net_report/reportgen.rs:615.
	captivePortalPath = "/generate_204"

	// challengeHeader and responseHeader carry the captive-portal challenge and
	// its echo. iroh/src/net_report/reportgen.rs:618,626.
	challengeHeader = "X-Iroh-Challenge"
	responseHeader  = "X-Iroh-Response"
)

// qadCloseReason is the close reason string sent with a QAD connection close.
// iroh-relay/src/quic.rs:14 (QUIC_ADDR_DISC_CLOSE_REASON).
var qadCloseReason = []byte("finished")
