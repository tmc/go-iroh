package iroh

import (
	"context"
	"errors"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// Connecting is an in-progress outgoing connection whose handshake may not be
// complete. It is returned by [Endpoint.ConnectEarly].
//
// Await [Connecting.Connection] for the verified [Conn] (the blocking,
// fully-authenticated path that [Endpoint.Connect] returns), or call
// [Connecting.Into0RTT] to obtain a connection usable for 0-RTT early data
// before the handshake completes.
//
// A Connecting is not safe for concurrent use, and may be consumed only once:
// after Into0RTT succeeds or Connection returns, it must not be used again.
type Connecting struct {
	ep       *Endpoint
	qc       *quic.Conn
	remoteID key.EndpointID
	addr     netaddr.EndpointAddr
	alpn     string
}

// ALPN returns the application protocol negotiated for the connection.
func (c *Connecting) ALPN() string {
	if c == nil {
		return ""
	}
	return c.alpn
}

// RemoteID returns the asserted endpoint id of the peer being dialed. It is the
// dialed addr.ID; the RFC 7250 VerifyConnection check authenticates it once the
// handshake completes.
func (c *Connecting) RemoteID() key.EndpointID {
	if c == nil {
		return key.EndpointID{}
	}
	return c.remoteID
}

// Connection waits for the handshake, registers the connection with the
// endpoint, runs the AfterHandshake hooks, and returns the established [Conn].
// This is the blocking, fully-authenticated path and is exactly what
// [Endpoint.Connect] returns.
func (c *Connecting) Connection(ctx context.Context) (*Conn, error) {
	if c == nil || c.qc == nil {
		return nil, errors.New("iroh: nil connecting")
	}
	qc, err := c.qc.NextConnection(ctx)
	if err != nil {
		return nil, err
	}
	if err := context.Cause(qc.Context()); err != nil {
		return nil, err
	}
	conn, err := newConn(qc, c.remoteID, c.alpn, SideClient, c.ep.connStableID(qc))
	if err != nil {
		return nil, err
	}
	conn.pathState, conn.pathConn = c.ep.registerConn(c.remoteID, c.qc, c.addr)
	if err := c.ep.afterHandshake(ctx, conn); err != nil {
		conn.CloseWithError(0, "rejected by hook")
		return nil, err
	}
	return conn, nil
}

// Into0RTT attempts to convert the dial into a 0-RTT-capable [Conn].
//
// If the session cache held a resumable ticket for the peer, the QUIC stack
// restored the session and the returned Conn is ready for 0-RTT early data
// before the handshake completes; ok is true. Otherwise the dial fell through to
// a full handshake and ok is false; the returned Conn is a normal 1-RTT
// connection equivalent to the one [Connecting.Connection] would return, so no
// fallback round trip is needed.
//
// 0-RTT early data is sent before the peer's identity is authenticated: the Conn
// carries the dialed addr.ID as an asserted-but-not-yet-verified identity, and
// 0-RTT data is vulnerable to replay, so it must never trigger non-idempotent
// operations. The RFC 7250 VerifyConnection check and the AfterHandshake hooks
// run at handshake completion; a hook rejection closes the Conn and discards any
// early data.
//
// The server may accept the connection yet reject the 0-RTT data. Callers that
// sent early data wait on [Conn.HandshakeComplete] and then check
// [Conn.Used0RTT]: if it is false the early data was rejected and must be resent
// on the now-1-RTT connection (the QUIC stack resets the 0-RTT streams).
func (c *Connecting) Into0RTT() (conn *Conn, ok bool) {
	if c == nil || c.qc == nil {
		return nil, false
	}
	// DialEarly returns at the 0-RTT early window only when the session ticket
	// restored the transport parameters before the handshake completed. If the
	// handshake is already complete, no ticket was usable: there is no 0-RTT
	// window, so register and return the conn as a normal 1-RTT dial with
	// ok=false. The caller need not await Connection: this is already the
	// connection it would return.
	select {
	case <-c.qc.HandshakeComplete():
		out, err := c.finishVerified(context.Background())
		if err != nil {
			return nil, false
		}
		return out, false
	default:
	}

	out := mustConn(c.qc, c.remoteID, c.alpn, SideClient, c.ep.connStableID(c.qc))
	out.pathState, out.pathConn = c.ep.registerConn(c.remoteID, c.qc, c.addr)
	// Run the verify hooks at handshake completion, after early data has been
	// sent. A rejection closes the connection and discards the early data,
	// mirroring the blocking AfterHandshake path in Connection.
	go func() {
		select {
		case <-out.qc.HandshakeComplete():
		case <-out.Context().Done():
			return
		}
		if err := c.ep.afterHandshake(context.Background(), out); err != nil {
			out.CloseWithError(0, "rejected by hook")
		}
	}()
	return out, true
}

// finishVerified registers the connection and runs the AfterHandshake hooks for
// an already-completed handshake, returning the established Conn.
func (c *Connecting) finishVerified(ctx context.Context) (*Conn, error) {
	conn := mustConn(c.qc, c.remoteID, c.alpn, SideClient, c.ep.connStableID(c.qc))
	conn.pathState, conn.pathConn = c.ep.registerConn(c.remoteID, c.qc, c.addr)
	if err := c.ep.afterHandshake(ctx, conn); err != nil {
		conn.CloseWithError(0, "rejected by hook")
		return nil, err
	}
	return conn, nil
}

// Into0RTT returns a [Conn] that may receive 0-RTT early data from the peer
// before the handshake completes. The accept side is infallible: if the peer did
// not send 0-RTT data the connection simply behaves as 1-RTT.
//
// The peer's identity is not authenticated until the handshake completes. The
// returned Conn's RemoteID and ALPN are not meaningful until [Conn.RemoteID]'s
// underlying handshake finishes; wait on [Conn.HandshakeComplete] before relying
// on them. 0-RTT data is vulnerable to replay and must not drive non-idempotent
// operations until the handshake completes.
func (a *Accepting) Into0RTT() (*Conn, error) {
	if a == nil || a.qc == nil {
		return nil, errors.New("iroh: nil accepting connection")
	}
	conn := mustConn(a.qc, key.EndpointID{}, "", SideServer, a.ep.connStableID(a.qc))
	// The verified identity is not known until the handshake completes. Resolve
	// it lazily, once, from the completed handshake and register the connection
	// at the same time. resolveIdentity serializes this with reads in RemoteID,
	// ALPN, Paths, and WatchPaths.
	conn.resolve = func() (key.EndpointID, string) {
		// The verified identity is only available once the handshake completes.
		// A premature read must not cache a bad result, so wait for completion
		// (or connection close) before reading the TLS state.
		select {
		case <-a.qc.HandshakeComplete():
		case <-a.qc.Context().Done():
			return key.EndpointID{}, ""
		}
		remote, err := peerEndpointID(a.qc.ConnectionState().TLS)
		if err != nil {
			a.qc.CloseWithError(0, "bad peer certificate")
			return key.EndpointID{}, ""
		}
		alpn := a.qc.ConnectionState().TLS.NegotiatedProtocol
		conn.pathState, conn.pathConn = a.ep.registerConn(remote, a.qc, netaddr.NewEndpointAddr(remote))
		return remote, alpn
	}
	// Run the AfterHandshake hooks once the handshake completes, after any 0-RTT
	// data has arrived. A hook rejection closes the connection and discards the
	// early data.
	go func() {
		select {
		case <-a.qc.HandshakeComplete():
		case <-conn.Context().Done():
			return
		}
		conn.resolveIdentity()
		if err := a.ep.afterHandshake(context.Background(), conn); err != nil {
			conn.CloseWithError(0, "rejected by hook")
		}
	}()
	return conn, nil
}

// mustConn builds a Conn. newConn never returns an error today; this keeps the
// 0-RTT call sites free of unreachable error handling.
func mustConn(qc *quic.Conn, remoteID key.EndpointID, alpn string, side Side, stableID uint64) *Conn {
	conn, _ := newConn(qc, remoteID, alpn, side, stableID)
	return conn
}
