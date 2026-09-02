package iroh

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/netaddr"
)

// HandshakeRejectError rejects a completed handshake with an application close
// code and reason.
type HandshakeRejectError struct {
	Code   uint64
	Reason string
}

// Error implements error.
func (e *HandshakeRejectError) Error() string {
	return fmt.Sprintf("reject handshake: code %d: %s", e.Code, e.Reason)
}

// RejectHandshake rejects a completed handshake with code and reason.
func RejectHandshake(code uint64, reason string) error {
	return &HandshakeRejectError{Code: code, Reason: reason}
}

// EndpointHooks observes and can reject an endpoint's outbound dials and its
// completed handshakes.
type EndpointHooks interface {
	// BeforeConnect runs before an outbound dial. Returning an error abandons
	// the dial and the error reaches the caller of [Endpoint.Connect]. It does
	// not run for accepted connections.
	BeforeConnect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) error

	// AfterHandshake runs once for every connection the endpoint establishes,
	// dialed and accepted alike; [Conn.Side] distinguishes them. A hook
	// installed on a server therefore fires for connections it never dialed.
	// Returning an error closes the connection; use [RejectHandshake] to pick
	// the close code and reason.
	//
	// On the ordinary paths it runs on the goroutine that is establishing the
	// connection, with that caller's context. On the 0-RTT paths
	// ([Connecting.Into0RTT] and early-data accepts) the handshake
	// completes after the connection is already in use, so AfterHandshake runs
	// on a separate goroutine with a background context: a hook that touches
	// shared state must be safe for concurrent use.
	AfterHandshake(ctx context.Context, conn *Conn) error
}

type noopHooks struct{}

func (noopHooks) BeforeConnect(context.Context, netaddr.EndpointAddr, string) error { return nil }

func (noopHooks) AfterHandshake(context.Context, *Conn) error { return nil }
