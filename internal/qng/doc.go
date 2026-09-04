// Package quic is a fork of quic-go, copied into go-iroh so that it can be
// built against RFC 7250 raw-public-key TLS.
//
// The copy is mechanical: every file comes from
// github.com/quic-go/quic-go at the version recorded in README.md, with
// imports rewritten to github.com/tmc/go-iroh/internal/itls/tls and to the
// copied packages. On top of that the fork carries the changes needed for
// wire compatibility with Rust iroh, which README.md enumerates. The
// upstream copyright and license are in NOTICE and LICENSE; the cmd/qngregen
// command regenerates the copy from the module cache.
package quic
