# go-iroh

[![Go Reference](https://pkg.go.dev/badge/github.com/tmc/go-iroh.svg)](https://pkg.go.dev/github.com/tmc/go-iroh)
[![parity](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Ftmc%2Fgo-iroh%2Fcompat-harness%2Firoh-compat-harness%2Fresults%2Fbadge.json)](COMPATIBILITY.md)

Wire compatibility: iroh wire v1, observed against pinned Rust iroh releases by the [compatibility matrix](COMPATIBILITY.md).

`go-iroh` is a Go implementation of [iroh](https://github.com/n0-computer/iroh).
It provides peer-to-peer QUIC
endpoints identified by ed25519 public keys, with direct paths, relay fallback,
QUIC Retry, multipath, QAD observed addresses, and QNT NAT traversal support,
plus Rust-compatible ports of the iroh protocol stack: blobs, gossip, and docs.

The module is a clean-room Go port targeting wire compatibility with upstream
Rust iroh. It is not affiliated with the n0 team.

## Packages

Connectivity layer:

| Package | Purpose |
|---|---|
| `iroh` | Endpoint, Conn, Router, address lookup |
| `key` | endpoint IDs, Ed25519 keys, signatures |
| `netaddr` | endpoint addresses, transport addresses, relay URLs |
| `dns` | pkarr TXT encoding and stdlib/DoH/DoT lookupers |
| `pkarr` | pkarr signed DNS packet codec |
| `relay` | public relay maps and relay configuration |
| `relayserver` | embeddable relay server (backs `cmd/iroh-relay`) |
| `dnsserver` | embeddable DNS and pkarr server (backs `cmd/iroh-dns-server`) |
| `metrics` | small OpenMetrics registry |
| `watch` | small generic watch values |

Protocols (Rust-compatible ports):

| Package | Purpose |
|---|---|
| `blobs` | content-addressed blob tickets, identifiers, blob stores, and BAO transfer |
| `gossip` | iroh-gossip pub/sub mesh (HyParView membership, PlumTree broadcast) |
| `docs` | iroh-docs multi-writer key-value documents and range sync |
| `endpointticket` | Rust-compatible endpoint ticket codec |
| `irpc` | postcard-framed RPC helpers for iroh streams |
| `postcard` | Rust-compatible postcard wire codec (shared with sibling modules) |
| `http3` | adapts iroh connections for HTTP/3 implementations |

Commands:

| Command | Purpose |
|---|---|
| `cmd/iroh` | utility for iroh identities and addresses (keys, endpoint info) |
| `cmd/iroh-relay` | small, self-hostable relay server |
| `cmd/iroh-dns-server` | pkarr HTTP and DNS server for discovery |
| `cmd/wasmrelaytest` | browser smoke test for the js/wasm relay-only transport |

The transport internals live under `internal/`: relay protocol/client/server,
net reports, socket path management, RFC 7250 TLS, the postcard and pkarr
implementations, the gossip proto state machine, and `qng`, the quic-go fork
used for iroh/noq compatibility.

## Ecosystem

| Repository | Contents |
|---|---|
| [go-iroh-examples](https://github.com/tmc/go-iroh-examples) | 40+ runnable example programs, from hello-world dial-up to gossip meshes |
| [go-iroh-tools](https://github.com/tmc/go-iroh-tools) | command-line tools built on go-iroh |
| [go-iroh-experiments](https://github.com/tmc/go-iroh-experiments) | experimental modules layered on go-iroh |

## Install

```sh
go get github.com/tmc/go-iroh
```

This module currently declares Go 1.26 in `go.mod`.

## Use

The `iroh` package is the main entry point:

```go
ep, err := iroh.Bind(ctx, iroh.WithALPNs("example/1"))
if err != nil {
	return err
}
defer ep.Shutdown(ctx)

conn, err := ep.Connect(ctx, peerAddr, "example/1")
if err != nil {
	return err
}
defer conn.CloseWithError(0, "")
```

ALPN means Application-Layer Protocol Negotiation. It is the TLS extension that
lets peers agree which application protocol a QUIC connection will carry, such
as `"example/1"` or `"n0/iroh/transfer/example/1"`. go-iroh uses ALPN values to
route incoming connections to handlers.

The API takes ALPN values as Go strings. TLS ALPN values are byte strings on the
wire; Go strings preserve arbitrary bytes, while keeping the common printable
ASCII case simple.

See [iroh/example_test.go](./iroh/example_test.go) for runnable direct-loopback
Router and Endpoint examples.

## Wire Compatibility

Relay, pkarr, DoH, and DoT connections use standard WebPKI TLS. Direct
peer-to-peer QUIC uses TLS 1.3 Raw Public Keys (RFC 7250) with mutual endpoint
authentication. Go's standard `crypto/tls` does not support RFC 7250, so this
repository carries `internal/itls/tls` and drives it from `internal/qng`.

`internal/qng` is a quic-go v0.59.1 fork extended for the iroh/noq transport
surface: multipath, QAD observed-address reporting, QNT NAT traversal, and
pre-connection QUIC Retry admission. The fork-local READMEs document when those
forks can be removed.

## Validation

Run the local suite:

```sh
go test ./...
```

For a repeatable local check:

```sh
go test ./... -count=1
```

Run the focused wire-parser fuzz targets for one minute each:

```sh
go test -run '^$' -fuzz '^FuzzReadObserveItem$' -fuzztime 1m ./blobs
go test -run '^$' -fuzz '^FuzzUnmarshal$' -fuzztime 1m ./internal/postcard
go test -run '^$' -fuzz '^FuzzFromBytes$' -fuzztime 1m ./internal/pkarr
go test -run '^$' -fuzz '^FuzzParseRelayFrames$' -fuzztime 1m ./internal/relayproto
go test -run '^$' -fuzz '^FuzzKeyMaterialClientAuthHeader$' -fuzztime 1m ./internal/relayproto
```

For loopback stream/datagram latency and throughput, with raw TCP and UDP
baselines:

```sh
GOMAXPROCS=4 go test ./iroh -run '^$' -bench 'Benchmark(Conn|RawTCP|RawUDP)' -benchtime=5s -count=5
```

`BenchmarkRawUDPMagicQueuedPingPong` is the closest raw UDP latency baseline for
the magic-socket path: it uses the same receive queue depth, pooled receive
buffers, caller-buffer copy, and separate write queue shape as the direct IP
transport.

Live Rust interop runs through the compatibility harness in
[iroh-compat-harness](./iroh-compat-harness), which drives unmodified upstream
iroh binaries in pinned Docker images against go-iroh and renders
[COMPATIBILITY.md](COMPATIBILITY.md). It requires only Go and Docker:

```sh
cd iroh-compat-harness && make parity
```

The harness is the published claim, so it pins the Rust peer. For the
development loop there are also in-module interop tests that build a Rust peer
from a checkout you control, which is what you want when the Rust side is the
thing being changed. They are skipped unless you opt in:

```sh
IROH_RUST_REPO=../iroh go test ./internal/compat/          # source-level parity
IROH_RUST_REPO=../iroh go test -tags interop ./iroh/       # connect and echo
GO_IROH_LIVE_RUST_GOSSIP=1 go test ./gossip/               # live gossip peer
```

## Debugging

Every endpoint installs the qlog connection tracer, so setting `QLOGDIR` records
a [qlog](https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html) trace of
every QUIC connection the process opens or accepts, with no code change:

```sh
QLOGDIR=./qlog go run ./cmd/...
```

Each connection writes `<odcid>_client.sqlog` or `<odcid>_server.sqlog`, in
JSON-seq, one event per line. The two files for a single connection share the
original destination connection id, so a dial and the accept that answers it
pair up by filename. Traces carry frame metadata, loss and congestion events,
and the handshake — not payload bytes:

```sh
jq -c 'select(.name == "quic:packet_sent") | .data.frames[]' qlog/*_client.sqlog
```

`QLOGDIR` is read once per connection and applies process-wide, so a process
running several endpoints interleaves their traces in one directory, keyed only
by connection id. `iroh.WithQLOG` replaces it for one endpoint: the sink is
called once per connection and returns the `io.WriteCloser` for that trace, so
endpoints in one process can be traced separately, or somewhere other than a
file. `iroh.QLOGDir` builds a sink with the same file layout as `QLOGDIR`.

### Payload bytes

qlog stops at frame metadata. To see the bytes a stream carried, log the TLS
traffic secrets with `iroh.WithKeyLogWriter`, capture the UDP flow, and let
Wireshark decrypt it:

```go
keys, _ := os.Create("keys.txt")
ep, _ := iroh.Bind(ctx, iroh.WithKeyLogWriter(keys)) // debugging only
```

```sh
tshark -r cap.pcap -o tls.keylog_file:keys.txt -Y quic.stream_data -T fields -e quic.stream_data
```

Writing those secrets compromises the confidentiality of every connection the
endpoint makes, so this is a debugging tool, not a deployment option. Three
things stay dark:

  - Relayed traffic. Relay paths are an encrypted websocket to the relay, not
    the QUIC flow, so a capture of a relayed connection decrypts nothing.
  - 0-RTT. No early-traffic secret is written, so resumed connections' early
    data is not decryptable.
  - The reverse direction after connection-id rotation. Only the direction that
    keeps its connection id stays readable for the whole capture.

## Status

The connectivity layer is a wire-compatible iroh endpoint. The protocol packages
(`blobs`, `gossip`, `docs`) port the corresponding Rust crates, sharing the
`postcard` and `pkarr` wire codecs; `gossip` carries the full HyParView and
PlumTree state machine with a postcard discovery channel.

The normal local suite covers the public packages, qng transport extensions, and
local relay/direct behavior. Live Go↔Rust coverage — handshakes, transport
semantics, relay, discovery, and gossip against pinned upstream releases — runs
in the [compatibility harness](./iroh-compat-harness) and is summarized in
[COMPATIBILITY.md](COMPATIBILITY.md).

GOOS=js/GOARCH=wasm builds compile. Browser runtime support is limited by the
platform: the relay WebSocket client has a js-specific dial path, but direct UDP
QUIC, direct paths, and NAT traversal are not available in browser WebAssembly.

## License

go-iroh is licensed under the MIT License. See [LICENSE](./LICENSE).

The forked quic-go code under `internal/qng` retains its upstream license notice
in `internal/qng/LICENSE`.
