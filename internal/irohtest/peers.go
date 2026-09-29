package irohtest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// Within runs f with a context that expires after d and fails the test if f
// returns an error or has not returned after d. It does not rely on f
// honoring the context, so it also catches code that ignores cancellation.
// Inside a synctest bubble d is virtual time, so the bound is exact rather
// than a guess about machine speed. f must not call tb's methods.
func Within(tb testing.TB, d time.Duration, f func(ctx context.Context) error) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- f(ctx) }()
	var err error
	select {
	case err = <-done:
	case <-time.After(d):
		tb.Fatalf("irohtest: not done within %v", d)
	}
	elapsed := time.Since(start)
	if errors.Is(err, context.DeadlineExceeded) || elapsed > d {
		tb.Fatalf("irohtest: not done within %v (took %v): %v", d, elapsed, err)
	}
	if err != nil {
		tb.Fatalf("irohtest: %v", err)
	}
}

// Hooks is an [iroh.EndpointHooks] built from functions. A nil function
// allows the connection.
type Hooks struct {
	Before func(ctx context.Context, addr netaddr.EndpointAddr, alpn string) error
	After  func(ctx context.Context, conn *iroh.Conn) error
}

// BeforeConnect implements [iroh.EndpointHooks].
func (h Hooks) BeforeConnect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) error {
	if h.Before == nil {
		return nil
	}
	return h.Before(ctx, addr, alpn)
}

// AfterHandshake implements [iroh.EndpointHooks].
func (h Hooks) AfterHandshake(ctx context.Context, conn *iroh.Conn) error {
	if h.After == nil {
		return nil
	}
	return h.After(ctx, conn)
}

// RejectFrom returns hooks that reject, after the handshake, every connection
// from a peer in bad, with err (which may be a [iroh.RejectHandshake] error or
// any other).
func RejectFrom(err error, bad ...*Peer) Hooks {
	return Hooks{After: func(_ context.Context, conn *iroh.Conn) error {
		if contains(bad, conn.RemoteID()) {
			return err
		}
		return nil
	}}
}

// StallFrom returns hooks that block every connection from a peer in bad
// after its handshake until release is closed or the hook's context ends.
func StallFrom(release <-chan struct{}, bad ...*Peer) Hooks {
	return Hooks{After: func(ctx context.Context, conn *iroh.Conn) error {
		if contains(bad, conn.RemoteID()) {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return nil
	}}
}

func contains(peers []*Peer, id key.EndpointID) bool {
	for _, p := range peers {
		if p.ID().Equal(id) {
			return true
		}
	}
	return false
}

// OpenAndStall opens a bidirectional stream on conn, writes p, and then holds
// the stream open without reading or finishing it until ctx is done. It is a
// peer that sends a request and never reads the answer.
func OpenAndStall(ctx context.Context, conn *iroh.Conn, p []byte) error {
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Write(p); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// WriteForever opens a bidirectional stream on conn and writes p to it
// repeatedly, never finishing the stream, until a write fails or ctx is done.
// It is a peer whose request never ends.
func WriteForever(ctx context.Context, conn *iroh.Conn, p []byte) error {
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	for ctx.Err() == nil {
		if _, err := s.Write(p); err != nil {
			return err
		}
	}
	return nil
}
