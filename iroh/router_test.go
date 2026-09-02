package iroh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// echoHandler is a ProtocolHandler that echoes one bidirectional stream back to
// the peer and then returns.
type echoHandler struct{}

func (echoHandler) Accept(ctx context.Context, conn *Conn) error {
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(s)
	if err != nil {
		return err
	}
	if _, err := s.Write(b); err != nil {
		return err
	}
	return s.Close()
}

func TestRouterStreamListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-router-listener/0"

	server, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	ln := NewStreamListener()
	router, err := NewRouter(server, map[string]ProtocolHandler{alpn: ln.Handler()}, nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer router.Shutdown(ctx)

	var _ net.Listener = ln
	if ln.Addr() == nil {
		t.Fatal("stream listener Addr() = nil")
	}

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		pc, ok := c.(interface{ RemoteID() key.EndpointID })
		if !ok {
			done <- errors.New("accepted conn does not expose RemoteID")
			return
		}
		if !pc.RemoteID().Equal(client.ID()) {
			done <- errors.New("accepted conn has wrong RemoteID")
			return
		}
		ec, ok := c.(interface{ Used0RTT() bool })
		if !ok {
			done <- errors.New("accepted conn does not expose Used0RTT")
			return
		}
		if ec.Used0RTT() {
			done <- errors.New("accepted conn Used0RTT = true, want false")
			return
		}
		_, err = io.Copy(c, c)
		done <- err
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	c, err := client.Dial(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var buf [4]byte
	if _, err := io.ReadFull(c, buf[:]); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf[:]) != "ping" {
		t.Fatalf("echo = %q, want ping", string(buf[:]))
	}
	if err := c.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := <-done; err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestRouterStreamListenerShutdownIsQuiet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-router-listener-quiet/0"

	server, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	ln := NewStreamListener()
	router, err := NewRouter(server, map[string]ProtocolHandler{alpn: ln.Handler()}, &RouterConfig{
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	c, err := client.Dial(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	c.Close()

	if err := router.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got := logs.String(); got != "" {
		t.Fatalf("router logged during normal stream listener shutdown:\n%s", got)
	}
}

func TestRouterOwnsEndpointAcceptLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-router-owner/0"

	server, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	router, err := NewRouter(server, map[string]ProtocolHandler{alpn: echoHandler{}}, nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer router.Shutdown(ctx)

	if _, err := server.ListenStreams(); !errors.Is(err, ErrEndpointAcceptLoopInUse) {
		t.Fatalf("ListenStreams while Router active = %v, want ErrEndpointAcceptLoopInUse", err)
	}
	if _, err := server.Accept(ctx); !errors.Is(err, ErrEndpointAcceptLoopInUse) {
		t.Fatalf("Accept while Router active = %v, want ErrEndpointAcceptLoopInUse", err)
	}
	if _, err := server.AcceptIncoming(ctx); !errors.Is(err, ErrEndpointAcceptLoopInUse) {
		t.Fatalf("AcceptIncoming while Router active = %v, want ErrEndpointAcceptLoopInUse", err)
	}
	if err := server.SetALPNs([]string{"iroh-router-owner/1"}); !errors.Is(err, ErrEndpointAcceptLoopInUse) {
		t.Fatalf("SetALPNs while Router active = %v, want ErrEndpointAcceptLoopInUse", err)
	}
}

// shutdownEcho records whether Shutdown was called, exercising the optional
// ShutdownHandler hook.
type shutdownEcho struct {
	echoHandler
	mu   sync.Mutex
	done bool
}

func (h *shutdownEcho) Shutdown(ctx context.Context) {
	h.mu.Lock()
	h.done = true
	h.mu.Unlock()
}

func (h *shutdownEcho) wasShutdown() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.done
}

type blockingShutdown struct {
	started chan struct{}
	release <-chan struct{}
}

func (h blockingShutdown) Accept(context.Context, *Conn) error { return nil }

func (h blockingShutdown) Shutdown(ctx context.Context) {
	close(h.started)
	select {
	case <-h.release:
	case <-ctx.Done():
	}
}

type panicHandler struct {
	started chan struct{}
}

func (h panicHandler) Accept(context.Context, *Conn) error {
	close(h.started)
	panic("router panic test")
}

type acceptingEcho struct {
	echoHandler
	called chan string
}

func (h acceptingEcho) OnAccepting(ctx context.Context, accepting *Accepting) (*Conn, error) {
	alpn, err := accepting.ALPN(ctx)
	if err != nil {
		return nil, err
	}
	select {
	case h.called <- alpn:
	default:
	}
	return accepting.Connection(ctx)
}

// TestRouterEcho is the slice-H Router gate: two endpoints connect over a direct
// loopback path; the server registers an echo ProtocolHandler via a Router; the
// client connects and exchanges a stream echo dispatched by ALPN through the
// Router.
func TestRouterEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-router-echo/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	h := &shutdownEcho{}
	router, err := NewRouter(server, map[string]ProtocolHandler{alpn: h}, nil)
	if err != nil {
		t.Fatalf("spawn router: %v", err)
	}
	defer router.Shutdown(ctx)

	if router.Endpoint() != server {
		t.Error("Router.Endpoint did not return the server endpoint")
	}
	if router.IsShutdown() {
		t.Error("router reported shutdown before Shutdown was called")
	}

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const msg = "hello router"
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("echo = %q, want %q", got, msg)
	}

	// Shutting down the router cancels the loop, runs handler Shutdown, and
	// closes the endpoint.
	if err := router.Shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	if !router.IsShutdown() {
		t.Error("router did not report shutdown after Shutdown")
	}
	if !h.wasShutdown() {
		t.Error("handler Shutdown hook was not called")
	}
}

func TestRouterFilterRetryUsesQUICRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-router-retry/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	var retryCalls atomic.Int32
	var acceptedValidated atomic.Bool
	router, err := NewRouter(server, map[string]ProtocolHandler{alpn: echoHandler{}}, &RouterConfig{
		IncomingFilter: func(in *Incoming) IncomingFilterOutcome {
			if in.RemoteAddrValidated() {
				acceptedValidated.Store(true)
				return FilterAccept
			}
			retryCalls.Add(1)
			return FilterRetry
		},
	})
	if err != nil {
		t.Fatalf("spawn router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := s.Write([]byte("retry")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "retry" {
		t.Fatalf("echo = %q, want retry", got)
	}
	if retryCalls.Load() == 0 {
		t.Fatal("filter did not request pre-connection retry")
	}
	if !acceptedValidated.Load() {
		t.Fatal("post-retry incoming was not remote-address validated")
	}
}

// TestRouterUnsupportedALPN checks that a connection negotiating an ALPN with no
// registered handler is closed by the router (and the rest keeps working).
func TestRouterUnsupportedALPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const goodALPN = "iroh-good/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(server, map[string]ProtocolHandler{goodALPN: echoHandler{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	// The server only advertises goodALPN, so a client offering only an unknown
	// ALPN fails the handshake at the QUIC/TLS layer.
	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	if _, err := client.Connect(ctx, addr, "iroh-unknown/0"); err == nil {
		t.Error("connect with unknown ALPN unexpectedly succeeded")
	}

	// A subsequent good connection still works, proving the loop survived.
	conn, err := client.Connect(ctx, addr, goodALPN)
	if err != nil {
		t.Fatalf("good connect after bad: %v", err)
	}
	conn.CloseWithError(0, "")
}

func TestRouterHandlerPanicDoesNotStopAcceptLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const (
		panicALPN = "iroh-router-panic/0"
		echoALPN  = "iroh-router-after-panic/0"
	)

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	panicStarted := make(chan struct{})
	router, err := NewRouter(server, map[string]ProtocolHandler{
		panicALPN: panicHandler{started: panicStarted},
		echoALPN:  echoHandler{},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	panicConn, err := client.Connect(ctx, addr, panicALPN)
	if err != nil {
		t.Fatalf("panic connect: %v", err)
	}
	panicConn.CloseWithError(0, "")
	select {
	case <-panicStarted:
	case <-ctx.Done():
		t.Fatal("panic handler was not called")
	}

	conn, err := client.Connect(ctx, addr, echoALPN)
	if err != nil {
		t.Fatalf("connect after panic: %v", err)
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream after panic: %v", err)
	}
	const msg = "after panic"
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo after panic: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("echo after panic = %q, want %q", got, msg)
	}
}

func TestRouterShutdownHandlersRunConcurrently(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	h1 := blockingShutdown{started: make(chan struct{}), release: release}
	h2 := blockingShutdown{started: make(chan struct{}), release: release}
	router, err := NewRouter(server, map[string]ProtocolHandler{
		"iroh-shutdown-a/0": h1,
		"iroh-shutdown-b/0": h2,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- router.Shutdown(ctx)
	}()

	select {
	case <-h1.started:
	case <-time.After(time.Second):
		t.Fatal("first handler Shutdown was not called")
	}
	select {
	case <-h2.started:
	case <-time.After(time.Second):
		t.Fatal("second handler Shutdown was not called concurrently")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestRouterOnAccepting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-router-accepting/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	called := make(chan string, 1)
	router, err := NewRouter(server, map[string]ProtocolHandler{alpn: acceptingEcho{called: called}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("accepting")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := io.ReadAll(s); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-called:
		if got != alpn {
			t.Fatalf("OnAccepting ALPN = %q, want %q", got, alpn)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

// TestRouterALPNsWithoutHandler checks the four combinations of a bound ALPN
// set and a handler map. NewRouter replaces the endpoint's ALPN set with the
// handler keys, so an ALPN the endpoint was bound with and the router cannot
// dispatch used to be dropped silently; it is now an error.
func TestRouterALPNsWithoutHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const (
		alpnA = "iroh-router-alpn/a"
		alpnB = "iroh-router-alpn/b"
	)
	for _, tt := range []struct {
		name     string
		bound    []string
		handlers []string
		wantErr  string
	}{
		{name: "no bound alpns", handlers: []string{alpnA, alpnB}},
		{name: "identical sets", bound: []string{alpnA}, handlers: []string{alpnA}},
		{name: "router widens", bound: []string{alpnA}, handlers: []string{alpnA, alpnB}},
		{name: "bound alpn has no handler", bound: []string{alpnA, alpnB}, handlers: []string{alpnA}, wantErr: alpnB},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Option{WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0))}
			if len(tt.bound) > 0 {
				opts = append(opts, WithALPNs(tt.bound...))
			}
			ep, err := Bind(ctx, opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer ep.Shutdown(ctx)

			handlers := make(map[string]ProtocolHandler, len(tt.handlers))
			for _, a := range tt.handlers {
				handlers[a] = echoHandler{}
			}
			router, err := NewRouter(ep, handlers, nil)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewRouter: %v", err)
				}
				defer router.Shutdown(ctx)
				return
			}
			if err == nil {
				router.Shutdown(ctx)
				t.Fatal("NewRouter with an unhandled endpoint ALPN succeeded")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewRouter error = %v, want it to name %q", err, tt.wantErr)
			}
			// The endpoint keeps its own accept loop available.
			if _, err := ep.ListenStreams(); err != nil {
				t.Fatalf("ListenStreams after a rejected router: %v", err)
			}
		})
	}
}

// TestRouterAfterSetALPNs checks that the unhandled-ALPN rule reads what Bind
// was given, not what the endpoint accepts at the time. SetALPNs documents that
// it replaces the accepted set, so a router replacing it again is that
// contract, not a misconfiguration.
func TestRouterAfterSetALPNs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)
	if err := ep.SetALPNs([]string{"iroh-router-setalpns/a"}); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(ep, map[string]ProtocolHandler{"iroh-router-setalpns/b": echoHandler{}}, nil)
	if err != nil {
		t.Fatalf("NewRouter after SetALPNs: %v", err)
	}
	router.Shutdown(ctx)
}
