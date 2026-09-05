# Iroh wire compatibility

go-iroh is an independent Go implementation of iroh wire v1. This matrix records observed interoperability with real, pinned Rust iroh peers; unsupported cells are not compatibility claims.

Go-client↔Go-relay pairings contain no Rust peer, so they are outside this matrix's scope; that path is covered by the standard test suite.

Generated at 2026-08-19T22:36:17Z. A pass requires a recorded Rust process and binary digest; setup errors, unsupported cells, and untested cells never count as passes.

## How to read this table

- `pass` means the implementations interoperated in the observed scenario and matched the expected verdict.
- `fail (expected)` means the scenario ran, observed a wire incompatibility, and matched the expected verdict.
- `FAIL (unexpected)` or `PASS (unexpected)` means the observation disagreed with the expected verdict.
- `unsupported` means go-iroh lacks the feature, not that the feature is broken.
- `setup-error` means the environment could not run the scenario, so it makes no compatibility claim.
- `—` means the scenario was not run for that version.

Released columns are compatibility claims against a pinned Rust release. A `-pre` column is expected-enforced evidence against a pinned upstream commit, not a claim about a shipped version. The `tip` column is a moving, advisory signal refreshed nightly and is never a committed compatibility claim. Experimental rows may change wire format to track upstream without a major go-iroh version bump.

The Rust counterpart is either an **upstream CLI**, an unmodified program shipped by upstream iroh, or a **Rust test driver**, a purpose-built peer linked to the pinned upstream libraries. CLI results have the strongest black-box provenance; test-driver results cover protocol behavior that upstream CLIs do not expose.

Matrix cells reference the **Peers** table below. Each peer entry records the Rust executable and its SHA-256 digest. The machine-readable result also records the peer process ID, so a pass cannot be emitted without evidence of a real Rust process.

## Compatibility envelope

| Surface | Tier | Upstream train | Status | Detail |
|---|---|---|---|---|
| CustomAddr endpoint tickets | experimental | 1.0 | observed-incompatible | Observed with iroh-base 1.0.3 in both directions: upstream uses the legacy enum encoding. |
| CustomAddr endpoint tickets | experimental | 1.1 (pre-release pin) | verified-interop | Measured at upstream commit 4706ec97 in both directions. Upstream moved to go-iroh's length-prefixed byte format; no go-iroh codec change is required. |

## Compatibility matrix

| Scenario | Tier | Rust counterpart | 1.0 (1.0.3) | 1.1-pre @ 4706ec9 | tip (advisory) |
|---|---|---|:---:|:---:|:---:|
| discovery/go-publish-rust-dns | stable | upstream CLI | pass [1] | — | — |
| discovery/qad-report | stable | upstream CLI | pass [2] | — | — |
| discovery/relay-urls | stable | upstream CLI | pass [3] | — | — |
| discovery/rust-publish-go-dns | stable | Rust test driver | pass [4] | — | — |
| handshake/alpn-mismatch | stable | upstream CLI | pass [2] | — | — |
| handshake/close-semantics | stable | Rust test driver | pass [4] | — | — |
| handshake/datagrams | stable | Rust test driver | pass [4] | — | — |
| handshake/go-client-rust-server | stable | upstream CLI | pass [2] | — | — |
| handshake/pq-only | stable | Rust test driver | pass [4] | — | — |
| handshake/prefer-pq | stable | Rust test driver | pass [4] | — | — |
| handshake/remote-info | stable | Rust test driver | pass [4] | — | — |
| handshake/rust-client-go-server | stable | upstream CLI | pass [2] | — | — |
| handshake/wrong-endpoint-id | stable | upstream CLI | pass [2] | — | — |
| handshake/zero-rtt | stable | Rust test driver | pass [4] | — | — |
| relay/go-client-rust-relay | stable | upstream CLI | pass [3] | — | — |
| relay/idle-timeout | stable | upstream CLI | pass [3] | — | — |
| relay/ping-pong | stable | upstream CLI | pass [3] | — | — |
| relay/rust-client-go-relay | stable | Rust test driver | pass [4] | — | — |
| relay/rust-client-rust-relay | stable | Rust test driver | pass [4] | — | — |
| relay/websocket-upgrade | stable | upstream CLI | pass [3] | — | — |
| vectors/custom-addr-ticket-go-to-rust | experimental | Rust test driver | fail (expected) [4] | pass [5] | — |
| vectors/custom-addr-ticket-rust-to-go | experimental | Rust test driver | fail (expected) [4] | pass [5] | — |
| vectors/endpoint-ticket-roundtrip | stable | Rust test driver | pass [4] | — | — |
| vectors/gossip-frame | stable | Rust test driver | pass [4] | — | — |
| vectors/keys-z32-sign | stable | Rust test driver | pass [4] | — | — |
| vectors/pkarr-txt | stable | Rust test driver | pass [4] | — | — |
| vectors/postcard-varints | stable | Rust test driver | pass [4] | — | — |

The pinned 1.1-pre column currently exercises the bidirectional CustomAddr wire-vector suite in blocking CI. Other scenarios remain untested for that train until blocking coverage is explicitly expanded at its release re-pin. The `tip` column is populated only in the nightly advisory report.

### Peers

| Ref | Rust peer | Pin | SHA-256 digest |
|---:|---|---|---|
| [1] | iroh-dns-server | 1.0 (1.0.3) | `3f09ba2a00a7ffadb264acf013062d19ed6d670b52b294e46de7f39b06e6c32e` |
| [2] | iroh-doctor | 1.0 (1.0.3) | `3aa5c46b1c3a96399eee56fd6ab329c5c1542d46ffb37c3bab21a06ebb979d0f` |
| [3] | iroh-relay | 1.0 (1.0.3) | `dc4a563cdf4197fc3187051e90124c8981e8cff8903274862434923e729d9ce8` |
| [4] | rust-driver | 1.0 (1.0.3) | `fee53c8f0bb2990c645afac72fa17c9ed1c06055ddfe9fc05714f553f1a38aeb` |
| [5] | rust-driver | 1.1-pre @ 4706ec9 | `d827681a5649072afd6277d7c8f4b01169f744b73ee435b37882090106050e8d` |

### Observed incompatibility evidence

- `vectors/custom-addr-ticket-go-to-rust` at 1.0 (1.0.3): Rust accepted 0/6 Go CustomAddr tickets.
- `vectors/custom-addr-ticket-rust-to-go` at 1.0 (1.0.3): Go accepted 0/6 Rust CustomAddr tickets.

## Scenario definitions

| Scenario | What a pass proves |
|---|---|
| discovery/go-publish-rust-dns | A Go client publishes a signed pkarr packet to the upstream Rust DNS server, and a pass proves that the server stores and returns the packet byte for byte. |
| discovery/qad-report | Go and upstream iroh-doctor probe the same network, and a pass proves that their QAD reports agree on shared reachability fields and satisfy address and latency invariants. |
| discovery/relay-urls | Go and the Rust test driver contact the same upstream relay URL, and a pass proves that both implementations resolve it, negotiate the relay protocol, and receive a pong. |
| discovery/rust-publish-go-dns | The Rust test driver publishes a signed pkarr packet to the Go DNS server, and a pass proves that the server stores and returns the packet byte for byte. |
| handshake/alpn-mismatch | A Go client offers the wrong ALPN to an upstream Rust server, and a pass proves that the incompatible handshake is rejected instead of silently connecting. |
| handshake/close-semantics | Go closes a connection to the Rust test driver with application code 42 and reason bye, and a pass proves that the Rust peer observes both values. |
| handshake/datagrams | Go and the Rust test driver exchange QUIC datagrams in both directions, and a pass proves compatible datagram framing and acknowledgement behavior. |
| handshake/go-client-rust-server | A Go client runs the doctor send, receive, and echo exchange against an upstream Rust server, and a pass proves compatible identity, ALPN, QUIC, and stream behavior. |
| handshake/pq-only | Go and Rust peers exchange data in both directions under a PQ-only policy, and a pass proves X25519MLKEM768 negotiation plus NoKxGroupsInCommon refusal of classical-only peers. |
| handshake/prefer-pq | Go and Rust peers exchange data in both directions while preferring post-quantum key exchange, and a pass proves that both negotiate X25519MLKEM768. |
| handshake/remote-info | Go and the Rust test driver exchange an authenticated stream and record peer addressing, and a pass proves that Go reports the Rust endpoint ID and a direct address. |
| handshake/rust-client-go-server | An upstream Rust client runs the doctor send, receive, and echo exchange against a Go server, and a pass proves compatible identity, ALPN, QUIC, and stream behavior. |
| handshake/wrong-endpoint-id | A Go client dials an upstream Rust server using the wrong endpoint ID, and a pass proves that peer authentication rejects the connection. |
| handshake/zero-rtt | A Go client resumes a Rust-issued TLS session and sends an early stream, and a pass proves that the Rust peer accepts the data as QUIC 0-RTT. |
| relay/go-client-rust-relay | A Go client authenticates to an upstream Rust relay and exchanges ping and pong frames, and a pass proves compatible relay protocol negotiation and framing. |
| relay/idle-timeout | A client leaves a TCP connection idle before WebSocket establishment on an upstream Rust relay, and a pass proves that the relay closes it after the expected timeout. |
| relay/ping-pong | A Go client sends an eight-byte relay ping to an upstream Rust relay, and a pass proves that the corresponding pong preserves the payload. |
| relay/rust-client-go-relay | The Rust test driver authenticates to a Go relay and exchanges ping and pong frames, and a pass proves that the Go relay accepts the upstream wire protocol. |
| relay/rust-client-rust-relay | The Rust test driver authenticates to an upstream Rust relay and exchanges ping and pong frames, and a pass proves that the pinned control path is operational. |
| relay/websocket-upgrade | A Go client performs the authenticated WebSocket upgrade against an upstream Rust relay, and a pass proves compatible HTTP upgrade and relay session setup. |
| vectors/custom-addr-ticket-go-to-rust | Rust decodes CustomAddr endpoint tickets generated by Go at lengths 0, 1, 29, 30, 31, and 255, and a pass proves Go-to-Rust compatibility across the inline-storage boundary. |
| vectors/custom-addr-ticket-rust-to-go | Go decodes CustomAddr endpoint tickets generated by Rust at lengths 0, 1, 29, 30, 31, and 255, and a pass proves Rust-to-Go compatibility across the inline-storage boundary. |
| vectors/endpoint-ticket-roundtrip | Go decodes and re-encodes endpoint tickets generated by Rust, and a pass proves a byte-identical ticket round trip. |
| vectors/gossip-frame | Go and the Rust test driver exchange framed gossip broadcasts in both directions, and a pass proves compatible topic, sender, and payload encoding. |
| vectors/keys-z32-sign | Go verifies endpoint IDs, z-base-32 encodings, signatures, and signed packets generated by Rust, and a pass proves byte-compatible key and signature representations. |
| vectors/pkarr-txt | Go verifies and parses a Rust-generated signed pkarr TXT packet, and a pass proves compatible packet signatures and TXT payload encoding. |
| vectors/postcard-varints | Go decodes postcard integer encodings generated by Rust, and a pass proves byte-compatible varint serialization at the tested boundaries. |

## Reproduce

The harness lives on the [`compat-harness`](https://github.com/tmc/go-iroh/tree/compat-harness) branch, not on main:

```sh
git checkout compat-harness
cd iroh-compat-harness
make parity
```

See the [harness README](https://github.com/tmc/go-iroh/blob/compat-harness/iroh-compat-harness/README.md) for prerequisites, the [scenario declarations](https://github.com/tmc/go-iroh/tree/compat-harness/iroh-compat-harness/scenarios) for predicted verdicts and definitions, and [results.json](https://github.com/tmc/go-iroh/blob/compat-harness/iroh-compat-harness/results/results.json) for the machine-readable report.

## Go API and wire changes

This section is written by hand and is not generated. It records changes that
the matrix above cannot show: Go API changes, which no Rust peer observes, and
wire changes whose evidence is a single matrix row rather than the whole table.
Regenerating the report preserves everything from this heading to the end of the
file.

### v0.2.0

One option added, one deprecated, one wire change, and a vendored upstream
bump. Nothing was removed and no exported signature changed.

net_report now runs by default whenever relays are configured. It measures
relay latency and reports the QAD-derived global addresses advertised as local
QNT candidates for active remotes. Previously an endpoint had to ask for it.
This is a behaviour change for an endpoint that configures relays and does not
opt out: it sends net_report probes it did not send before, and its home relay
can move away from the bootstrap pick after `Bind`.

`iroh.WithoutNetReport` was added to turn it off. Without it the home relay
stays whichever relay `Bind` picked to bootstrap with — the first in the relay
map rather than the nearest — and `Endpoint.NetReport` never reports a
measurement. `iroh.WithNetReport` is deprecated: it still compiles and still
clears the disable flag, so passing it is harmless, but it no longer enables
anything that was off.

mdns responders now answer SRV and TXT questions. A responder answered only PTR
and ANY, so a peer asking directly for an instance's SRV or TXT record got
nothing and had to re-query by PTR. Announcements already carried all three
records together, so this adds no record type that was not already on the wire;
it answers questions that were being dropped. An SRV or TXT question must name
the instance rather than the service, since both records describe one instance
and the service name does not say which.

mdns discovery now also listens and announces on the IPv6 multicast group
`ff02::fb`. Two peers that share an IPv6 link and no IPv4 link previously never
found each other. IPv6 is best effort: a host without it behaves exactly as
before. Which addresses a record carries is still independent of the link the
packet rides on, so AAAA records continue to travel over IPv4 where that is the
only link.

Path MTU discovery now runs. Setting the don't-fragment bit on UDP sockets had
been gated behind an `IROH_ENABLE_DF` environment variable, so `capabilities().DF`
was false and the MTU discoverer was never started on either side of a
connection. A dialing endpoint still appeared to widen its path, but only as a
side effect of multipath path setup arming the prober; an accepting endpoint
stayed at the initial 1243-byte payload for the life of the connection.
Endpoints now discover the real path MTU in both directions. The behaviour
change to be aware of is that datagrams too large for the path now fail with
EMSGSIZE rather than being fragmented, which is what QUIC requires and what
upstream quic-go does.

The vendored quic-go fork in `internal/qng` was updated to upstream v0.62.0.
That package is internal, so no exported API changed; the fork's own divergence
from upstream is recorded in the package's own documentation.

### v0.1.1

Two encoding changes and one struct field. Nothing was removed, and no exported
signature changed.

`u8` and `i8` now encode as one raw byte. Rust postcard writes `u8` verbatim and
`i8` as its two's complement; go-iroh varint-encoded the first and zigzagged the
second, so `uint8(200)` was `c801` where Rust gives `c8`, and `int8(-2)` was `03`
where Rust gives `fe`. Any cross-language protocol carrying an 8-bit field
diverged silently. The postcard-encoded types in this module carry their enums
as `u64`, which is why nothing caught it. A `u8` below 128 encodes identically
under both rules, so unsigned data written before this change is still readable;
`i8` is not, since zigzag and two's complement agree only on zero. Proven
against Rust output by `vectors/postcard-8bit`.

Padded varints are rejected. `ac8200` and `ac02` both decoded to 300, and `8100`
was a valid length prefix for a one-byte slice; a record identified by a digest
of its encoding therefore had more than one valid id, which defeats
deduplication and equivocation detection. Decoding now returns an overlong-varint
error for any encoding past its shortest form. **This is stricter than the
reference implementation, not matched to it:** postcard 1.1.3 accepts every one
of these encodings. See the compatibility envelope above for what that costs;
the short version is that both serializers emit only canonical forms, so no
conforming peer's traffic is affected. Measured by
`vectors/postcard-varint-strictness`, which is expected to fail because the two
implementations genuinely disagree.

`gossip.Event` gained a `Dropped` field, reporting how many events a lagging
subscriber missed. Adding a field to an exported struct breaks unkeyed composite
literals, so `gossip.Event{kind, peer, ...}` no longer compiles. Keyed literals
are unaffected. API-diff tools report this addition as compatible.

Both additions also carry an embedding hazard. A type that embeds
`gossip.Event` alongside another type providing `Dropped`, or that embeds
`iroh.Stream` alongside another providing `CloseWrite`, now has an ambiguous
selector at the point of use. `gorelease` reports neither; `apibump`
classifies both as embed-breaking.

Also added, with nothing removed: `iroh.Stream.CloseWrite`,
`iroh.ErrTLSHandshakeFailure`, `iroh.QLOGConnection`, `iroh.QLOGDir`,
`iroh.WithQLOG`, `mdns.WithLogger`, `key.UncheckedEndpointID`,
`relayserver.NewWithOptions`, `relayserver.Option`, and
`relayserver.WithClientRate`.
