# docs

This directory is the Go port of the [iroh-docs](https://github.com/n0-computer/iroh-docs)
sync protocol — multi-writer key-value documents with range-based set
reconciliation. It is a protocol package, not project documentation.

For project documentation, see the [main README](../README.md) and the package
reference at [pkg.go.dev/github.com/tmc/go-iroh](https://pkg.go.dev/github.com/tmc/go-iroh).

## Implementation scope

Go applications retain namespace capabilities and author secrets, register
`Handler.Allow`, and coordinate incoming admission with live sync lifecycle.
Closing `LiveSync` does not change a separately registered handler. File-store
snapshots contain signed entries; capabilities, useful peers, and download
policies belong to the application.

Sync frames are limited to 16 MiB. The pinned Rust iroh-docs 0.101.0 codec
permits frames up to 1 GiB, so a larger Rust reply can exceed Go's limit.
This limit is deliberate and does not claim acceptance of every valid Rust
frame size.

Live sync coalesces outgoing requests for each peer. It does not implement
Rust's full namespace/peer session state machine or deterministic resolution
of simultaneous incoming and outgoing syncs. Incoming admission remains an
application policy.
