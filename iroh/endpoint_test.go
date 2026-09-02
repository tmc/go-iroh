package iroh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestEndpointDirectEcho is the slice-B gate: two endpoints connect over a
// direct loopback UDP address, exchange a bidi-stream echo and a datagram, and
// each observes the other's verified endpoint id.
func TestEndpointDirectEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-echo/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	type srvResult struct {
		peer key.EndpointID
		mp   bool
		err  error
	}
	done := make(chan srvResult, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		// Echo one bidi stream.
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		b, _ := io.ReadAll(s)
		s.Write(b)
		s.Close()
		// Echo one datagram.
		dg, err := conn.ReadDatagram(ctx)
		if err == nil {
			conn.SendDatagram(dg)
		}
		done <- srvResult{peer: conn.RemoteID(), mp: conn.MultipathNegotiated()}
	}()

	// The server advertises its bound loopback address.
	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())

	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if !conn.RemoteID().Equal(server.ID()) {
		t.Errorf("client saw server id %s, want %s", conn.RemoteID(), server.ID())
	}
	if conn.ALPN() != alpn {
		t.Errorf("client ALPN = %q, want %q", conn.ALPN(), alpn)
	}
	if !conn.MultipathNegotiated() {
		t.Error("client did not negotiate multipath")
	}
	if err := client.remotes.Actor(server.ID()).TriggerHolepunch(); err != nil &&
		!errors.Is(err, socket.ErrExtensionNotNegotiated) &&
		!errors.Is(err, quic.ErrNATTraversalNotEnoughAddresses) {
		t.Fatalf("TriggerHolepunch: %v", err)
	}

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const msg = "hello iroh"
	s.Write([]byte(msg))
	s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("stream echo = %q, want %q", got, msg)
	}

	// Datagram echo.
	const dmsg = "dgram"
	if err := conn.SendDatagram([]byte(dmsg)); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	dg, err := conn.ReadDatagram(ctx)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	if string(dg) != dmsg {
		t.Errorf("datagram echo = %q, want %q", dg, dmsg)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if !res.peer.Equal(client.ID()) {
		t.Errorf("server saw client id %s, want %s", res.peer, client.ID())
	}
	if !res.mp {
		t.Error("server did not negotiate multipath")
	}
	if client.transport.ConnectionIDLength != 8 {
		t.Errorf("client transport ConnectionIDLength = %d, want 8", client.transport.ConnectionIDLength)
	}
	if server.transport.ConnectionIDLength != 8 {
		t.Errorf("server transport ConnectionIDLength = %d, want 8", server.transport.ConnectionIDLength)
	}
}

func TestEndpointPeerCloseDoesNotTearDownSurvivor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const alpn = "iroh-dropout/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	survivorKey, _ := key.GenerateSecretKey()
	survivor, err := Bind(ctx, WithSecretKey(survivorKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer survivor.Shutdown(ctx)

	dropperKey, _ := key.GenerateSecretKey()
	dropper, err := Bind(ctx, WithSecretKey(dropperKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer dropper.Shutdown(ctx)

	type accepted struct {
		conn *Conn
		err  error
	}
	acceptc := make(chan accepted, 2)
	go func() {
		for range 2 {
			conn, err := server.Accept(ctx)
			acceptc <- accepted{conn: conn, err: err}
		}
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	survivorConn, err := survivor.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("survivor connect: %v", err)
	}
	defer survivorConn.CloseWithError(0, "")

	dropperConn, err := dropper.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("dropper connect: %v", err)
	}
	defer dropperConn.CloseWithError(0, "")

	serverConns := make(map[key.EndpointID]*Conn)
	for range 2 {
		res := <-acceptc
		if res.err != nil {
			t.Fatalf("accept: %v", res.err)
		}
		serverConns[res.conn.RemoteID()] = res.conn
		defer res.conn.CloseWithError(0, "")
	}
	serverSurvivor := serverConns[survivor.ID()]
	if serverSurvivor == nil {
		t.Fatalf("server did not accept survivor %s", survivor.ID())
	}
	serverDropper := serverConns[dropper.ID()]
	if serverDropper == nil {
		t.Fatalf("server did not accept dropper %s", dropper.ID())
	}

	const payloadSize = 2 << 20
	payload := bytes.Repeat([]byte("s"), payloadSize)
	serverSawDropperBytes := make(chan struct{})
	survivorServerDone := make(chan error, 1)
	dropperServerDone := make(chan error, 1)

	go func() {
		st, err := serverSurvivor.AcceptStream(ctx)
		if err != nil {
			survivorServerDone <- fmt.Errorf("accept survivor stream: %w", err)
			return
		}
		n, err := io.Copy(io.Discard, st)
		if err != nil {
			survivorServerDone <- fmt.Errorf("read survivor stream: %w", err)
			return
		}
		if n != payloadSize {
			survivorServerDone <- fmt.Errorf("read survivor stream: got %d bytes, want %d", n, payloadSize)
			return
		}
		if _, err := st.Write([]byte("ok")); err != nil {
			survivorServerDone <- fmt.Errorf("write survivor ack: %w", err)
			return
		}
		if err := st.Close(); err != nil {
			survivorServerDone <- fmt.Errorf("close survivor stream: %w", err)
			return
		}
		survivorServerDone <- nil
	}()

	go func() {
		st, err := serverDropper.AcceptStream(ctx)
		if err != nil {
			dropperServerDone <- fmt.Errorf("accept dropper stream: %w", err)
			return
		}
		buf := make([]byte, 32<<10)
		n, err := st.Read(buf)
		if n > 0 {
			close(serverSawDropperBytes)
		}
		if err != nil {
			dropperServerDone <- nil
			return
		}
		_, _ = io.Copy(io.Discard, st)
		dropperServerDone <- nil
	}()

	survivorClientDone := make(chan error, 1)
	go func() {
		st, err := survivorConn.OpenStreamSync(ctx)
		if err != nil {
			survivorClientDone <- fmt.Errorf("open survivor stream: %w", err)
			return
		}
		if _, err := st.Write(payload); err != nil {
			survivorClientDone <- fmt.Errorf("write survivor stream: %w", err)
			return
		}
		if err := st.Close(); err != nil {
			survivorClientDone <- fmt.Errorf("close survivor stream: %w", err)
			return
		}
		ack, err := io.ReadAll(st)
		if err != nil {
			survivorClientDone <- fmt.Errorf("read survivor ack: %w", err)
			return
		}
		if string(ack) != "ok" {
			survivorClientDone <- fmt.Errorf("survivor ack = %q, want ok", ack)
			return
		}
		survivorClientDone <- nil
	}()

	dropperStream, err := dropperConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open dropper stream: %v", err)
	}
	if _, err := dropperStream.Write(bytes.Repeat([]byte("d"), 128<<10)); err != nil {
		t.Fatalf("write dropper stream: %v", err)
	}
	select {
	case <-serverSawDropperBytes:
	case <-ctx.Done():
		t.Fatal("server did not observe dropper stream before timeout")
	}
	if err := dropperConn.CloseWithError(99, "dropout"); err != nil {
		t.Fatalf("dropper close: %v", err)
	}

	if err := <-survivorClientDone; err != nil {
		t.Fatal(err)
	}
	if err := <-survivorServerDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-dropperServerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Log("server dropper stream still open after peer connection close")
	}
	if err := survivorConn.Context().Err(); err != nil {
		t.Fatalf("survivor connection closed after dropper endpoint shutdown: %v", err)
	}
	if err := serverSurvivor.Context().Err(); err != nil {
		t.Fatalf("server survivor connection closed after dropper endpoint shutdown: %v", err)
	}
	if paths := survivorConn.Paths(); !selectedPathValidated(paths) {
		t.Fatalf("survivor client selected path not validated after dropper close: %+v", paths)
	}
	if paths := serverSurvivor.Paths(); !selectedPathValidated(paths) {
		t.Fatalf("survivor server selected path not validated after dropper close: %+v", paths)
	}
}

func TestEndpointDialNetConn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-dial/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	done := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		defer conn.CloseWithError(0, "")
		c, err := conn.AcceptStreamConn(ctx)
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_, err = io.Copy(c, c)
		done <- err
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	c, err := client.Dial(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	var _ net.Conn = c
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var buf [4]byte
	if _, err := io.ReadFull(c, buf[:]); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf[:]) != "ping" {
		t.Fatalf("echo = %q, want ping", string(buf[:]))
	}
	c.Close()
	if err := <-done; err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestEndpointListenNetListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-listen/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	ln, err := server.ListenStreams()
	if err != nil {
		t.Fatalf("ListenStreams: %v", err)
	}
	defer ln.Close()
	var _ net.Listener = ln
	if ln.Addr() == nil {
		t.Fatal("Listen Addr() = nil")
	}

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
			done <- fmt.Errorf("accepted conn remote id = %s, want %s", pc.RemoteID(), client.ID())
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

func TestStreamListenerClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := Bind(ctx, WithALPNs("iroh-listener-close/0"),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	ln, err := server.ListenStreams()
	if err != nil {
		t.Fatalf("ListenStreams: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
}

func TestStreamListenerCloseUnblocksAccept(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := Bind(ctx, WithALPNs("iroh-listener-close-blocked/0"),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	ln, err := server.ListenStreams()
	if err != nil {
		t.Fatalf("ListenStreams: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()

	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked Accept = %v, want net.ErrClosed", err)
		}
	case <-ctx.Done():
		t.Fatal("blocked Accept did not unblock")
	}
}

func TestStreamListenerAcceptsMultipleStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-listener-streams/0"

	server, err := Bind(ctx, WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	ln, err := server.ListenStreams()
	if err != nil {
		t.Fatalf("ListenStreams: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				errc <- err
				return
			}
			pc, ok := c.(interface{ RemoteID() key.EndpointID })
			if !ok {
				c.Close()
				errc <- errors.New("accepted conn does not expose RemoteID")
				return
			}
			if !pc.RemoteID().Equal(client.ID()) {
				c.Close()
				errc <- fmt.Errorf("accepted conn remote id = %s, want %s", pc.RemoteID(), client.ID())
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
		errc <- nil
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	for _, msg := range []string{"one", "two"} {
		c, err := conn.OpenStreamConn(ctx)
		if err != nil {
			t.Fatalf("OpenStreamConn: %v", err)
		}
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		var buf [3]byte
		if _, err := io.ReadFull(c, buf[:len(msg)]); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		if string(buf[:len(msg)]) != msg {
			t.Fatalf("echo = %q, want %q", string(buf[:len(msg)]), msg)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("Close stream: %v", err)
		}
	}

	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestStreamListenerConcurrentAccept(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-listener-concurrent-accept/0"

	server, err := Bind(ctx, WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	ln, err := server.ListenStreams()
	if err != nil {
		t.Fatalf("ListenStreams: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 2)
	errc := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			c, err := ln.Accept()
			if err != nil {
				errc <- err
				return
			}
			accepted <- c
		}()
	}

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	for i := 0; i < 2; i++ {
		c, err := conn.OpenStreamConn(ctx)
		if err != nil {
			t.Fatalf("OpenStreamConn: %v", err)
		}
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("Write: %v", err)
		}
		defer c.Close()
	}

	seen := map[net.Conn]bool{}
	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			t.Fatal(err)
		case c := <-accepted:
			defer c.Close()
			if seen[c] {
				t.Fatal("same stream returned to multiple Accept callers")
			}
			seen[c] = true
		case <-ctx.Done():
			t.Fatal("timed out waiting for concurrent Accept")
		}
	}
}

func TestStreamListenerOwnsEndpointAcceptLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := Bind(ctx, WithALPNs("iroh-listener-owner/0"),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	ln, err := server.ListenStreams()
	if err != nil {
		t.Fatalf("ListenStreams: %v", err)
	}

	if _, err := server.ListenStreams(); !errors.Is(err, ErrEndpointAcceptLoopInUse) {
		t.Fatalf("second ListenStreams = %v, want ErrEndpointAcceptLoopInUse", err)
	}
	if _, err := server.Accept(ctx); !errors.Is(err, ErrEndpointAcceptLoopInUse) {
		t.Fatalf("Accept while ListenStreams active = %v, want ErrEndpointAcceptLoopInUse", err)
	}
	if _, err := server.AcceptIncoming(ctx); !errors.Is(err, ErrEndpointAcceptLoopInUse) {
		t.Fatalf("AcceptIncoming while ListenStreams active = %v, want ErrEndpointAcceptLoopInUse", err)
	}
	if err := server.SetALPNs([]string{"iroh-listener-owner/1"}); !errors.Is(err, ErrEndpointAcceptLoopInUse) {
		t.Fatalf("SetALPNs while ListenStreams active = %v, want ErrEndpointAcceptLoopInUse", err)
	}
	if _, err := NewRouter(server, map[string]ProtocolHandler{
		"iroh-listener-owner/0": echoHandler{},
	}, nil); !errors.Is(err, ErrEndpointAcceptLoopInUse) {
		t.Fatalf("NewRouter while ListenStreams active = %v, want ErrEndpointAcceptLoopInUse", err)
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := server.SetALPNs([]string{"iroh-listener-owner/1"}); err != nil {
		t.Fatalf("SetALPNs after listener close: %v", err)
	}
}

func TestEndpointAcceptIncoming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-accept-incoming/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	done := make(chan error, 1)
	go func() {
		in, err := server.AcceptIncoming(ctx)
		if err != nil {
			done <- err
			return
		}
		if _, ok := in.RemoteAddr().(*net.UDPAddr); !ok {
			done <- errors.New("incoming remote address is not UDP")
			return
		}
		if in.RemoteAddrValidated() {
			done <- errors.New("first incoming connection remote address unexpectedly validated")
			return
		}
		accepting, err := in.Accept()
		if err != nil {
			done <- err
			return
		}
		if got, err := accepting.ALPN(ctx); err != nil || got != alpn {
			done <- fmt.Errorf("accepting ALPN = %q, %v", got, err)
			return
		}
		conn, err := accepting.Connection(ctx)
		if err != nil {
			done <- err
			return
		}
		if conn.StableID() == 0 {
			done <- errors.New("connection StableID = 0")
			return
		}
		if !conn.RemoteID().Equal(client.ID()) {
			done <- fmt.Errorf("remote id = %s, want %s", conn.RemoteID(), client.ID())
			return
		}
		done <- nil
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEndpointSourceAddressValidationRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-retry/0"

	srvKey, _ := key.GenerateSecretKey()
	var retryCalls atomic.Int32
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithSourceAddressValidation(func(net.Addr) bool {
			retryCalls.Add(1)
			return true
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	done := make(chan error, 1)
	go func() {
		in, err := server.AcceptIncoming(ctx)
		if err != nil {
			done <- err
			return
		}
		if !in.RemoteAddrValidated() {
			done <- errors.New("incoming remote address was not validated by retry")
			return
		}
		accepting, err := in.Accept()
		if err != nil {
			done <- err
			return
		}
		conn, err := accepting.Connection(ctx)
		if err != nil {
			done <- err
			return
		}
		_ = conn.CloseWithError(0, "")
		done <- nil
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")
	if retryCalls.Load() == 0 {
		t.Fatal("source-address validation callback was not called")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEndpointBinaryALPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	alpn := string([]byte{'i', 'r', 'o', 'h', '/', 0xff, 0x00, '/', '1'})

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	type srvResult struct {
		alpn string
		err  error
	}
	done := make(chan srvResult, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		done <- srvResult{alpn: conn.ALPN()}
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if conn.ALPN() != alpn {
		t.Errorf("client ALPN = % x, want % x", []byte(conn.ALPN()), []byte(alpn))
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if res.alpn != alpn {
		t.Errorf("server ALPN = % x, want % x", []byte(res.alpn), []byte(alpn))
	}
}

// TestEndpointSelfConnect checks dialing one's own id is rejected.
func TestEndpointSelfConnect(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithALPNs("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)
	_, err = ep.Connect(ctx, ep.Addr(), "x")
	if err != ErrSelfConnect {
		t.Errorf("Connect(self) err = %v, want ErrSelfConnect", err)
	}
}

// TestEndpointNoAddress checks dialing an addr with no direct IP fails clearly
// (relay dialing is not yet implemented).
func TestEndpointNoAddress(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)
	other, _ := key.GenerateSecretKey()
	_, err = ep.Connect(ctx, netaddr.NewEndpointAddr(other.Public().EndpointID()), "x")
	if err != ErrNoAddress {
		t.Errorf("Connect(no addr) err = %v, want ErrNoAddress", err)
	}
}

// TestConnectByIDUsesAddressLookup checks that a dial by endpoint ID alone
// resolves through the configured address-lookup services, that the failure
// mode without an answer is unchanged, and that a dial with an address does not
// consult them.
func TestConnectByIDUsesAddressLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-lookup-dial/0"

	newServer := func(t *testing.T) *Endpoint {
		t.Helper()
		server, err := Bind(ctx, WithALPNs(alpn), WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Shutdown(ctx) })
		go func() {
			for {
				conn, err := server.Accept(ctx)
				if err != nil {
					return
				}
				conn.CloseWithError(0, "")
			}
		}()
		return server
	}

	t.Run("bare id resolves", func(t *testing.T) {
		server := newServer(t)
		lookup := NewMemoryLookup()
		lookup.AddEndpointAddr(netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()))

		var services AddressLookupServices
		services.AddResolver(lookup)
		client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)), WithAddressLookup(&services))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Shutdown(ctx)

		conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()), alpn)
		if err != nil {
			t.Fatalf("connect by id: %v", err)
		}
		defer conn.CloseWithError(0, "")
		if !conn.RemoteID().Equal(server.ID()) {
			t.Fatalf("remote id = %s, want %s", conn.RemoteID(), server.ID())
		}
	})

	t.Run("no answer still returns ErrNoAddress", func(t *testing.T) {
		var services AddressLookupServices
		services.AddResolver(NewMemoryLookup())
		client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)), WithAddressLookup(&services))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Shutdown(ctx)

		other, _ := key.GenerateSecretKey()
		if _, err := client.Connect(ctx, netaddr.NewEndpointAddr(other.Public().EndpointID()), alpn); err != ErrNoAddress {
			t.Fatalf("connect with an empty lookup = %v, want ErrNoAddress", err)
		}
	})

	// A dial that already has an address must not wait on the lookup. The
	// per-remote state machine still consults it in the background, so the
	// resolver is not counted; it is made to block instead, which fails the
	// test by timeout if Connect starts waiting on it.
	t.Run("address present does not wait on the lookup", func(t *testing.T) {
		server := newServer(t)
		var services AddressLookupServices
		services.AddResolver(AddressResolverFunc(func(ctx context.Context, id key.EndpointID) iter.Seq2[Item, error] {
			return func(yield func(Item, error) bool) { <-ctx.Done() }
		}))
		client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)), WithAddressLookup(&services))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Shutdown(ctx)

		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		conn, err := client.Connect(dialCtx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
		if err != nil {
			t.Fatalf("connect with an address and a blocking lookup: %v", err)
		}
		conn.CloseWithError(0, "")
	})
}
