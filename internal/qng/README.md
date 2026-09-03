# internal/qng — quic-go on RFC 7250 TLS

`qng` ("quic-no-go-tls") is a vendored fork of [quic-go](https://github.com/quic-go/quic-go).
It started as an import rewrite from the standard library's `crypto/tls` to
`github.com/tmc/go-iroh/internal/itls/tls` (RFC 7250 raw-public-key TLS), and
now also carries the iroh/noq QUIC extension surface needed for wire
compatibility: multipath, QAD observed addresses, and QNT NAT traversal.

## Why a fork is necessary

quic-go drives TLS by calling the concrete `crypto/tls` QUIC API
(`tls.QUICClient` / `tls.QUICServer`, added in Go 1.21). There is no seam to
inject a different TLS implementation: the QUIC handshake state machine *is*
`crypto/tls`. iroh's peer-to-peer handshake authenticates with TLS 1.3 raw
public keys (RFC 7250), which `crypto/tls` does not support. So to make Go QUIC
connections wire-compatible with iroh, quic-go must be pointed at the patched TLS.

quic-go's `crypto/tls` use is woven through its `internal/` tree
(`internal/handshake`, `internal/qtls`, `internal/protocol`, `internal/qerr`) as
well as the top-level package. Go's `internal/` visibility rule means qng copies
the whole transitive package set so the `tls.Config` / `tls.ConnectionState`
types are identical across the graph.

## What the fork changes

The base regeneration is mechanical. Every copied quic-go file is rewritten with
these string substitutions:

- `"crypto/tls"` → `tls "github.com/tmc/go-iroh/internal/itls/tls"`
- `"github.com/quic-go/quic-go/..."` → `"github.com/tmc/go-iroh/internal/qng/..."`

After regeneration, go-iroh applies local additions for iroh/noq behavior. Those
additions are intentionally kept in plainly named files and tests (`multipath_*`,
`observed_addr_*`, `qnt_*`, `retry_admission_test.go`) where possible, with
small integration edits in the connection, packet, and transport-parameter paths.

## Taking a new upstream release

The fork is not a pristine copy of quic-go. Alongside the mechanical import
rewrite, go-iroh edits vendored files in place and adds files of its own, so
regenerating over the tree would discard that work. `qngregen` refuses to do it:
run with no arguments it reports the local edits and stops.

Take a new release as a merge instead. Generate the pristine tree for the
release the fork was taken from and for the new one, and merge the difference
into the working tree:

	go run ./internal/qng/cmd/qngregen -o /tmp/qng-old   # at the current pin
	go get github.com/quic-go/quic-go@<version>
	go run ./internal/qng/cmd/qngregen -o /tmp/qng-new   # at the new pin

Both trees are reproducible from the module cache at any time, so the merge base
never has to be stored. Merge `/tmp/qng-old` -> `/tmp/qng-new` onto
`internal/qng`, resolve the conflicts, and update the version string below.

Then `go build ./... && go test ./internal/qng/`, followed by the focused qng
wire tests and the root iroh interop tests. Re-review if quic-go changes how it
constructs or clones `tls.Config`, since RFC 7250 fields must survive
`Config.Clone` — see the `RawPublicKeys` line in `../itls/tls/common.go`.

## When to break this fork

Delete or shrink qng only when upstream code makes a specific part unnecessary.
Do not remove it just because quic-go has a nearby feature.

The TLS import rewrite can go away when one of these is true:

- Go `crypto/tls` supports TLS 1.3 RFC 7250 raw public keys, including QUIC
  mode, mutual authentication, and safe resumption behavior for raw-key identity;
  then upstream quic-go can use stdlib TLS directly.
- quic-go exposes a stable TLS provider seam that lets go-iroh use
  `internal/itls/tls` without rewriting quic-go imports.

The iroh/noq extension additions can go away only when upstream quic-go, or
another upstream Go QUIC backend, provides equivalent public behavior for all
active iroh requirements:

- multipath negotiation and path frame parsing/packing compatible with noq,
- QAD observed-address transport parameters and frames,
- QNT/NAT traversal address advertisement and round/event behavior,
- per-path idle and keepalive semantics matching Rust iroh/noq,
- APIs that let the socket and endpoint layers open, select, close, and observe
  paths without reaching into fork-private state.

Before removing any part of qng, prove the replacement with local qng tests,
root iroh tests, and the live Rust interop gates. A passing ordinary quic-go
path-migration test is not enough evidence for iroh/noq parity.

## Forked version

quic-go **v0.59.1**.
