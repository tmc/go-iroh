# Iroh wire compatibility

go-iroh is an independent Go implementation of iroh wire v1. This matrix records observed interoperability with real, pinned Rust iroh peers; unsupported cells are not compatibility claims.

Go-client↔Go-relay pairings contain no Rust peer, so they are outside this matrix's scope; that path is covered by the standard test suite.

Generated from commit `bb923ea14d0d39b32393c2d1099eb4252bdf25b8` at 2026-09-30T17:37:44Z. A pass requires a recorded Rust process and binary digest; setup errors, unsupported cells, and untested cells never count as passes.

## How to read this table

- `pass` means the implementations interoperated in the observed scenario and matched the expected verdict.
- `fail (expected)` means the scenario ran, observed a wire incompatibility, and matched the expected verdict.
- `FAIL (unexpected)` or `PASS (unexpected)` means the observation disagreed with the expected verdict.
- `unsupported` means go-iroh lacks the feature, not that the feature is broken.
- `setup-error` means the environment could not run the scenario, so it makes no compatibility claim.
- `—` means the scenario was not run for that version.

Released columns are compatibility claims against a pinned Rust release. A `-pre` column is expected-enforced evidence against a pinned upstream commit, not a claim about a shipped version. Experimental rows may change wire format to track upstream without a major go-iroh version bump.

The Rust counterpart is either an **upstream CLI**, a program shipped by upstream iroh and built from a pinned upstream commit, or a **Rust test driver**, a purpose-built peer linked to the pinned upstream libraries. CLI results have the strongest black-box provenance; test-driver results cover protocol behavior that upstream CLIs do not expose. Where an upstream CLI's own release does not target the pinned iroh train, or where building it required any deviation from upstream sources, that is recorded against the peer in the **Peers** table; read those notes as part of the claim.

Matrix cells reference the **Peers** table below. Each peer entry records the Rust executable and its SHA-256 digest. The machine-readable result also records the peer process ID, so a pass cannot be emitted without evidence of a real Rust process.

## Compatibility envelope

| Surface | Tier | Upstream train | Status | Detail |
|---|---|---|---|---|
| CustomAddr endpoint tickets | experimental | 1.3 (1.3.0) | verified-interop | Measured at released upstream 1.3.0 (0072d7d8), as at 1.2.0: Go accepted 6/6 Rust tickets and Rust accepted 6/6 Go tickets. Upstream moved to go-iroh's length-prefixed byte format; no go-iroh codec change is required. The superseded 1.0.3 enum encoding is kept as a frozen negative fixture in vectors/legacy_custom_addr.json, which go-iroh must keep rejecting. |
| IPv6 addresses in endpoint tickets | stable | 1.3 (1.3.0) | verified-interop | Measured at released upstream 1.3.0 (0072d7d8): Go decoded 5/5 Rust tickets holding IPv6 addresses and Rust decoded 5/5 Go tickets, re-encoding them to Go's bytes. go-iroh once wrote a flowinfo and a scope id varint after every IPv6 port (endpointticket/ticket.go, since 955f0117); iroh-tickets serializes a SocketAddrV6 through serde as (ip, port) only, and go-iroh now writes and reads that form. |
| Blob requests for hash sequence children | stable | 1.3 (1.3.0) | verified-interop | Measured at released upstream 1.2.0 (17c0612f) and 1.3.0 (0072d7d8): an iroh-blobs 0.103.0 client verified every blob a Go provider sent for sendme receive's first request, the sequence and every child's last chunk, and for two children in full as a resumed download asks. go-iroh's provider (blobs.ServeBlob) once answered only the root of a hash sequence; it now answers each entry of the request against its child's blob, with the chunk-range proofs below. |
| Partial-block blob range proofs | stable | 1.3 (1.3.0) | verified-interop | Measured at released upstream 1.2.0 and 1.3.0: Go encodes the same bytes as bao-tree 0.16.1 and decodes bao-tree's encoding for all 52 corpus ranges, including two spans in one block, the chunk at infinity, and a start past the end, which is iroh-blobs' size-proof request. go-iroh once proved whole 16 KiB chunk groups (for chunks 5..7 of a 100000-byte blob, 16584 bytes where bao-tree writes 2568); blobs.EncodeBlobChunks and DecodeBlobChunks now take bao-tree chunk ranges and descend inside a group as bao-tree does, and the provider serves through them. The byte-offset EncodeBlobRange keeps the whole-group form and is not an iroh-blobs wire format. |
| Non-canonical varints | stable | 1.3 (1.3.0) | observed-divergence | go-iroh is strictly stricter: it rejects padded varint encodings that postcard 1.1.3 accepts. No traffic produced by a conforming postcard serializer is affected, since both upstream's serializer and go-iroh's emit only canonical forms. Content relayed verbatim through gossip carries varints produced by the originating endpoint rather than the forwarding peer (gossip/discovery.go:269, docs/heads.go:77), so a non-conforming originator's own message is dropped by go-iroh while upstream accepts it, affecting only that originator. |

## Compatibility matrix

| Scenario | Tier | Rust counterpart | 1.2 (1.2.0) | 1.3 (1.3.0) |
|---|---|---|:---:|:---:|
| blobs/rust-get-per-child | stable | Rust test driver | pass [1] | pass [2] |
| blobs/rust-get-sendme | stable | Rust test driver | pass [1] | pass [2] |
| discovery/go-publish-rust-dns | stable | upstream CLI | pass [3] | pass [4] |
| discovery/qad-report | stable | upstream CLI | pass [5] | pass [6] |
| discovery/relay-urls | stable | upstream CLI | pass [7] | pass [8] |
| discovery/rust-publish-go-dns | stable | Rust test driver | pass [1] | pass [2] |
| handshake/alpn-mismatch | stable | upstream CLI | pass [5] | pass [6] |
| handshake/close-semantics | stable | Rust test driver | pass [1] | pass [2] |
| handshake/datagrams | stable | Rust test driver | pass [1] | pass [2] |
| handshake/go-client-rust-server | stable | upstream CLI | pass [5] | pass [6] |
| handshake/pq-only | stable | Rust test driver | pass [1] | pass [2] |
| handshake/prefer-pq | stable | Rust test driver | pass [1] | pass [2] |
| handshake/remote-info | stable | Rust test driver | pass [1] | pass [2] |
| handshake/rust-client-go-server | stable | upstream CLI | pass [5] | pass [6] |
| handshake/wrong-endpoint-id | stable | upstream CLI | pass [5] | pass [6] |
| handshake/zero-rtt | stable | Rust test driver | pass [1] | pass [2] |
| relay/go-client-rust-relay | stable | upstream CLI | pass [7] | pass [8] |
| relay/idle-timeout | stable | upstream CLI | pass [7] | pass [8] |
| relay/ping-pong | stable | upstream CLI | pass [7] | pass [8] |
| relay/rust-client-go-relay | stable | Rust test driver | pass [1] | pass [2] |
| relay/rust-client-rust-relay | stable | Rust test driver | pass [1] | pass [2] |
| relay/websocket-upgrade | stable | upstream CLI | pass [7] | pass [8] |
| vectors/bao-chunk-ranges | stable | Rust test driver | pass [1] | pass [2] |
| vectors/bao-range-proofs | stable | Rust test driver | pass [1] | pass [2] |
| vectors/custom-addr-ticket-go-to-rust | experimental | Rust test driver | pass [1] | pass [2] |
| vectors/custom-addr-ticket-rust-to-go | experimental | Rust test driver | pass [1] | pass [2] |
| vectors/endpoint-ticket-roundtrip | stable | Rust test driver | pass [1] | pass [2] |
| vectors/gossip-frame | stable | Rust test driver | pass [1] | pass [2] |
| vectors/ip-ticket-go-to-rust | stable | Rust test driver | pass [1] | pass [2] |
| vectors/ip-ticket-rust-to-go | stable | Rust test driver | pass [1] | pass [2] |
| vectors/keys-z32-sign | stable | Rust test driver | pass [1] | pass [2] |
| vectors/pkarr-txt | stable | Rust test driver | pass [1] | pass [2] |
| vectors/postcard-8bit | stable | Rust test driver | pass [1] | pass [2] |
| vectors/postcard-varint-strictness | stable | Rust test driver | fail (expected) [1] | fail (expected) [2] |
| vectors/postcard-varints | stable | Rust test driver | pass [1] | pass [2] |

Every scenario is measured against every released pin.

### Peers

| Ref | Rust peer | Pin | SHA-256 digest |
|---:|---|---|---|
| [1] | rust-driver | 1.2 (1.2.0) | `199200316bbe95f310fcd51e7043367f636e8627228067e5c471151e741d4511` |
| [2] | rust-driver | 1.3 (1.3.0) | `7c4450f18bff205d0915263bc1cf59c0b83ad4fc23f2d06a1595b4a2ce9cba08` |
| [3] | iroh-dns-server | 1.2 (1.2.0) | `d556534dbecad8f97d5ed701685341aedb02986a45a3f9b150ec70bad828a4c0` |
| [4] | iroh-dns-server | 1.3 (1.3.0) | `48400faf690331c103ab98cf1c12c56427b027bf8aaa0cab3af559f116d4ba53` |
| [5] | iroh-doctor (*) | 1.2 (1.2.0) | `abbdf2fd285c04dcfd3672e81e2465348d290efa1d3a7df48ada06cdfb701374` |
| [6] | iroh-doctor (*) | 1.3 (1.3.0) | `fa07ea5558a0912ed809e953db5d06d847358727064e1338cfd95588a2bb34b6` |
| [7] | iroh-relay | 1.2 (1.2.0) | `d30f708f9a0ba738f9828f096c87642351a5f47ff925646cf3ad48eedd67d5d6` |
| [8] | iroh-relay | 1.3 (1.3.0) | `5f54bdea38a948c1fb1f17e244eaddc89dc879ae5180f05317ecdb633b063841` |

* **iroh-doctor provenance.** Upstream has shipped no iroh-doctor release for the 1.2 or 1.3 train. The pin is iroh-doctor 0.101.0, whose manifest declares `iroh = "1.0.0"` and is caret-resolved up to 1.3.0, so upstream does not itself publish or test this pairing; the matrix measures it, upstream does not endorse it. Building it against 1.3.0 also needs one additive line in iroh-doctor's own manifest, declaring tokio's `rt-multi-thread` feature that its `Builder::new_multi_thread` call already requires and that the iroh 1.0.x dependency graph supplied incidentally through `hickory-net`, which iroh 1.2.0 and later no longer use. No iroh source is modified, and the feature is already present in the committed lock, so the `--locked` build resolves identically; the build gate in `images/iroh-1.3.0/Dockerfile` fails if that edit is not exactly one line.

### Observed incompatibility evidence

- `vectors/postcard-varint-strictness` at 1.2 (1.2.0): Go and Rust agreed on 3/7 canonical-varint cases: overlong-300: Go accepted=false, Rust accepted=true.
- `vectors/postcard-varint-strictness` at 1.3 (1.3.0): Go and Rust agreed on 3/7 canonical-varint cases: overlong-300: Go accepted=false, Rust accepted=true.

## Scenario definitions

| Scenario | What a pass proves |
|---|---|
| blobs/rust-get-per-child | The Rust driver's iroh-blobs 0.103.0 client asks a Go provider for the second and fourth children of the same hash sequence in full, and nothing else, as a resumed download does, and a pass proves that go-iroh answers a per-child request with exactly those blobs. |
| blobs/rust-get-sendme | The Rust driver's iroh-blobs 0.103.0 client asks a Go provider for a hash sequence of empty, 1-chunk, 16-chunk, 17-chunk, and 100000-byte blobs with sendme receive's first request, the whole sequence and the last chunk of every child, and a pass proves that go-iroh answers it with every blob iroh-blobs expects and that each verifies. |
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
| vectors/bao-chunk-ranges | Go produces and verifies bao-tree's range proofs for chunk ranges no byte range expresses: two spans in one block, the chunk at infinity, and ranges starting past the end, which iroh-blobs sends to ask for a size proof, and a pass proves go-iroh serves any range iroh-blobs can request. |
| vectors/bao-range-proofs | Go encodes range proofs for blobs of 0 to 300000 bytes and compares them to bao-tree's for whole blobs, the last chunk, chunk ranges inside, across, and past a 16-chunk block, and two spans in one block, then verifies bao-tree's encodings, and a pass proves go-iroh serves and accepts the partial-block proofs iroh-blobs does. |
| vectors/custom-addr-ticket-go-to-rust | Rust decodes CustomAddr endpoint tickets generated by Go at lengths 0, 1, 29, 30, 31, and 255, and a pass proves Go-to-Rust compatibility across the inline-storage boundary. |
| vectors/custom-addr-ticket-rust-to-go | Go decodes CustomAddr endpoint tickets generated by Rust at lengths 0, 1, 29, 30, 31, and 255, and a pass proves Rust-to-Go compatibility across the inline-storage boundary. |
| vectors/endpoint-ticket-roundtrip | Go decodes and re-encodes endpoint tickets generated by Rust, and a pass proves a byte-identical ticket round trip. |
| vectors/gossip-frame | Go and the Rust test driver exchange framed gossip broadcasts in both directions, and a pass proves compatible topic, sender, and payload encoding. |
| vectors/ip-ticket-go-to-rust | Rust decodes the same five endpoint tickets encoded by Go, and a pass proves Rust recovers the same addresses and relay and re-encodes them to Go's bytes. |
| vectors/ip-ticket-rust-to-go | Go decodes endpoint tickets generated by Rust that hold one IPv6 address, two, IPv4 and IPv6 together, IPv6 with a relay, and an IPv4-mapped IPv6 address, and a pass proves Go reads the (ip, port) form serde writes for a SocketAddrV6. |
| vectors/keys-z32-sign | Go verifies endpoint IDs, z-base-32 encodings, signatures, and signed packets generated by Rust, and a pass proves byte-compatible key and signature representations. |
| vectors/pkarr-txt | Go verifies and parses a Rust-generated signed pkarr TXT packet, and a pass proves compatible packet signatures and TXT payload encoding. |
| vectors/postcard-8bit | Go encodes u8 and i8 values and compares them to the Rust driver's output at 0, 1, 127, 128, 200, 255 and -128, -2, -1, 0, 127, and a pass proves that both write a single raw byte rather than a varint above the 128 boundary. |
| vectors/postcard-varint-strictness | Go and the Rust driver decode the same canonical and non-canonically padded varint byte strings, and the recorded verdict is that they diverge: go-iroh rejects the padded encodings that postcard 1.1.3 accepts. |
| vectors/postcard-varints | Go decodes postcard integer encodings generated by Rust, and a pass proves byte-compatible varint serialization at the tested boundaries. |

## Reproduce

```sh
cd iroh-compat-harness
make parity
```

See the [harness README](iroh-compat-harness/README.md) for prerequisites, the [scenario declarations](iroh-compat-harness/scenarios/) for predicted verdicts and definitions, and [results.json](iroh-compat-harness/results/results.json) for the machine-readable report.
## Go API and wire changes

This section is written by hand and is not generated. It records changes that
the matrix above cannot show: Go API changes, which no Rust peer observes, and
wire changes whose evidence is a single matrix row rather than the whole table.
Regenerating the report preserves everything from this heading to the end of the
file.

### v0.2.3

No removals or signature changes.

- Wire: `endpointticket` writes an IPv6 address as IP and port, as Rust
  does, and no longer adds flowinfo and a scope ID. Tickets carrying IPv6
  addresses are not readable across v0.2.2 and v0.2.3; IPv4-only tickets are
  unaffected ([#28](https://github.com/tmc/go-iroh/issues/28)).
- `iroh`: added `WithProxy`, `ProxyURL` and `ProxyFromEnvironment`.
  Relay dials and netreport probes can go through an HTTP CONNECT proxy
  ([#27](https://github.com/tmc/go-iroh/issues/27)).
- blobs: added `DownloaderOptions.StallTimeout`, `DefaultStallTimeout` and
  `ErrProviderStalled`; a download abandons a provider that stalls. Added
  `MaxRequestSize` and `ErrRequestTooLarge`; servers read at most 1 MiB of
  request.
- `Endpoint.Accept` finishes handshakes concurrently, so a slow or silent
  peer no longer holds up others.
- gossip queues sends per peer and drops a peer that stops reading. A
  subscriber re-sends its Join until it has a neighbor
  ([#35](https://github.com/tmc/go-iroh/issues/35)).
- gossip peer data, missing-message tracking, and the TLS session cache are
  bounded ([#29](https://github.com/tmc/go-iroh/issues/29)).
- docs content status checks use the sync's context
  ([#31](https://github.com/tmc/go-iroh/issues/31)).
- mdns, dnsserver, gossip discovery and the relay mapped-address table have
  bounded caches. irpc recovers handler panics per request.

### v0.2.2

No removals or signature changes.

- `docs.MemoryStore`: added `InitialMessageInNamespace` and
  `ProcessMessageInNamespace`; `InitialMessage` and `ProcessMessage` are
  deprecated. Sync and live sync are now scoped to the negotiated namespace.
- `docs.Handler.Allow`: nil still allows every peer and namespace. This will
  change in v0.3.0.
- Wire: docs sync frames are capped at 16 MiB (was 1 GiB). Entries more than
  `MaxTimestampFutureShift` in the future are rejected.
- relayserver sends departure notices only to the peers a session sent to.
- pkarr, blob, socket address cache, irpc and gossip frame lengths are now
  bounded.
- `StreamListener` keeps running when a hook rejects one peer
  ([#25](https://github.com/tmc/go-iroh/issues/25)).
- gossip answers a repeated Join or ForwardJoin, as upstream does. Closing a
  topic now forgets its neighbors.

### v0.2.1

No removals or signature changes.

- `iroh.ConnStats`: added `PTOs` and `SpuriousLosses`. This breaks unkeyed
  literals; released as a patch, as in v0.1.1.
- A wildcard-bound endpoint replies from the address each peer reached.
- `Connect` starts dial targets 250 ms apart and uses the first to succeed.
- The relay-to-direct upgrade takes tens of milliseconds, down from about 5 s.
- Loss-recovery stall fixes in `internal/qng`.
- Linux receives with `UDP_GRO`.
- `golang.org/x/crypto` is now v0.56.0. The govulncheck advisories it fixes
  were not reachable.

### v0.2.0

No removals or signature changes.

- net_report runs by default when relays are configured. Added
  `iroh.WithoutNetReport`; `iroh.WithNetReport` is deprecated and does
  nothing.
- mdns answers SRV and TXT questions and also uses IPv6 (`ff02::fb`).
- Path MTU discovery is on, so oversized datagrams fail with EMSGSIZE
  instead of being fragmented.
- `relay.Map` is safe for concurrent use and must not be copied.
- `internal/qng` is updated to quic-go v0.62.0. Single-stream message rate
  is 2.5–5% below v0.1.1; multi-stream scaling improved.

### v0.1.1

No removals or signature changes.

- Wire: `u8` and `i8` encode as one raw byte, matching Rust postcard.
  Previously stored `i8` values cannot be read.
- Wire: padded varints are rejected. This is stricter than postcard 1.1.3;
  see the compatibility envelope.
- `gossip.Event`: added `Dropped`. This breaks unkeyed literals.
- Added `iroh.Stream.CloseWrite`, `iroh.ErrTLSHandshakeFailure`,
  `iroh.QLOGConnection`, `iroh.QLOGDir`, `iroh.WithQLOG`, `mdns.WithLogger`,
  `key.UncheckedEndpointID`, `relayserver.NewWithOptions`,
  `relayserver.Option`, and `relayserver.WithClientRate`.
