//go:build qng_regenerate

// Package quic is internal/qng, a vendored fork of quic-go. This file exists
// only to keep github.com/quic-go/quic-go in the module graph; it is never
// built. See README.md.
//
// The graph edge serves two purposes. It records which quic-go release this
// fork derives from, so that anyone auditing go-iroh's dependencies sees the
// provenance in go.mod without reading this directory. It also pins the
// version that the regeneration procedure re-forks from the module cache.
package quic

import _ "github.com/quic-go/quic-go"
