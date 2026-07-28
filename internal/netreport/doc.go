// Package netreport probes the local network environment to build a [Report]
// describing relay latencies and (where available) the public reflexive address
// of the host.
//
// It is a port of iroh's net_report module (iroh/src/net_report). A [Client]
// runs three kinds of probes against the configured relays:
//
//   - HTTPS probes fetch the relay's "/ping" path and time the round trip.
//   - QAD probes open a QUIC Address Discovery connection (ALPN "/iroh-qad/0",
//     QUIC port 7842) and read the connection RTT.
//   - A captive-portal check fetches "/generate_204" with an X-Iroh-Challenge
//     header and verifies the X-Iroh-Response echo, but only on full reports.
//
// From those probes the client picks a preferred relay, applying hysteresis so a
// responsive relay is not abandoned unless a new one is meaningfully faster.
//
// # Reflexive address discovery
//
// A QAD connection also learns the host's public address from the relay via the
// QUIC Address Discovery observed-address extension
// (draft-seemann-quic-address-discovery), implemented in the forked quic-go
// [github.com/tmc/go-iroh/internal/qng] (slice X3). The QAD client advertises
// the receive-only address-discovery role, and a QAD relay reports the client's
// reflexive address with OBSERVED_ADDRESS frames; the latest report is surfaced
// as [Report.GlobalV4]/[Report.GlobalV6] (and the matching UDP fields).
//
// Reports arrive after the handshake, so [qadConn.observedAddr] waits briefly
// for the first one; an immediate read would always miss. Without a report
// (not negotiated, or timed out) the probe stays latency-only.
//
// Which socket a probe rides decides what the observed address means: a
// private per-probe socket learns a mapping that dies with it.
// [Client.WithQADDialer] routes probes through the caller's transport instead,
// so the observed address is the caller's real public mapping.
package netreport
