module github.com/tmc/go-iroh/iroh-compat-harness

go 1.26

require github.com/tmc/go-iroh v0.0.0

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/quic-go/quic-go v0.59.1 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

replace github.com/tmc/go-iroh => ..
