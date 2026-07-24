package iroh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestMain(m *testing.M) {
	if os.Getenv("GO_IROH_TWOPROC_SERVER") == "1" {
		runTwoProcessDirectPathServer()
		return
	}
	os.Exit(m.Run())
}

// connPair binds a server and client endpoint on loopback, dials, and returns
// the dialed (client-side) and accepted (server-side) connections. Both
// endpoints and a context are cleaned up via t.Cleanup. The accepted conn is
// returned after the server's Accept completes so both ends are usable.
func connPair(t *testing.T, alpn string) (client, server *Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	srvKey, _ := key.GenerateSecretKey()
	srvEP, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srvEP.Shutdown(context.Background()) })

	clientEP, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientEP.Shutdown(context.Background()) })

	type accepted struct {
		conn *Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := srvEP.Accept(ctx)
		done <- accepted{conn: c, err: err}
	}()

	addr := netaddr.NewEndpointAddr(srvEP.ID()).WithIP(srvEP.LocalAddr())
	client, err = clientEP.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	return client, res.conn
}

// TestConnSide verifies the dialing side reports SideClient and the accepting
// side reports SideServer.
func TestConnSide(t *testing.T) {
	client, server := connPair(t, "iroh-side/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	if client.Side() != SideClient {
		t.Errorf("client.Side() = %v, want SideClient", client.Side())
	}
	if server.Side() != SideServer {
		t.Errorf("server.Side() = %v, want SideServer", server.Side())
	}
}

func TestConnAddr(t *testing.T) {
	client, server := connPair(t, "iroh-addr/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	if client.LocalAddr() == nil {
		t.Fatal("client.LocalAddr() = nil")
	}
	if client.RemoteAddr() == nil {
		t.Fatal("client.RemoteAddr() = nil")
	}
	if server.LocalAddr() == nil {
		t.Fatal("server.LocalAddr() = nil")
	}
	if server.RemoteAddr() == nil {
		t.Fatal("server.RemoteAddr() = nil")
	}
}

func TestConnStats(t *testing.T) {
	client, server := connPair(t, "iroh-stats/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		s, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		if _, err := io.Copy(s, s); err != nil {
			done <- err
			return
		}
		done <- s.Close()
	}()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := io.ReadAll(s); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		conn *Conn
	}{
		{"client", client},
		{"server", server},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.conn.Stats()
			want := tt.conn.qc.ConnectionStats()
			if got.MinRTT != want.MinRTT {
				t.Errorf("MinRTT = %v, want %v", got.MinRTT, want.MinRTT)
			}
			if got.LatestRTT != want.LatestRTT {
				t.Errorf("LatestRTT = %v, want %v", got.LatestRTT, want.LatestRTT)
			}
			if got.SmoothedRTT != want.SmoothedRTT {
				t.Errorf("SmoothedRTT = %v, want %v", got.SmoothedRTT, want.SmoothedRTT)
			}
			if got.MeanDeviation != want.MeanDeviation {
				t.Errorf("MeanDeviation = %v, want %v", got.MeanDeviation, want.MeanDeviation)
			}
			if got.BytesSent != want.BytesSent {
				t.Errorf("BytesSent = %d, want %d", got.BytesSent, want.BytesSent)
			}
			if got.PacketsSent != want.PacketsSent {
				t.Errorf("PacketsSent = %d, want %d", got.PacketsSent, want.PacketsSent)
			}
			if got.BytesReceived != want.BytesReceived {
				t.Errorf("BytesReceived = %d, want %d", got.BytesReceived, want.BytesReceived)
			}
			if got.PacketsReceived != want.PacketsReceived {
				t.Errorf("PacketsReceived = %d, want %d", got.PacketsReceived, want.PacketsReceived)
			}
			if got.BytesLost != want.BytesLost {
				t.Errorf("BytesLost = %d, want %d", got.BytesLost, want.BytesLost)
			}
			if got.PacketsLost != want.PacketsLost {
				t.Errorf("PacketsLost = %d, want %d", got.PacketsLost, want.PacketsLost)
			}
			if got.BytesSent == 0 {
				t.Error("BytesSent = 0, want traffic recorded")
			}
			if got.BytesReceived == 0 {
				t.Error("BytesReceived = 0, want traffic recorded")
			}
		})
	}
}

func TestConnPaths(t *testing.T) {
	client, server := connPair(t, "iroh-paths/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	tests := []struct {
		name string
		conn *Conn
	}{
		{"client", client},
		{"server", server},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var paths []PathInfo
			deadline := time.Now().Add(2 * time.Second)
			for {
				paths = tt.conn.Paths()
				if selectedPathValidated(paths) || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if len(paths) == 0 {
				t.Fatal("Paths() returned no paths")
			}
			var selected int
			for _, p := range paths {
				if p.Selected {
					selected++
				}
				if p.Selected && !p.Validated {
					t.Errorf("selected path is not validated: %+v", p)
				}
				if p.Selected && !p.HasAddr {
					t.Errorf("selected path has no address: %+v", p)
				}
				if p.Relayed {
					t.Errorf("loopback path Relayed = true, want false: %+v", p)
				}
			}
			if selected != 1 {
				t.Fatalf("selected path count = %d, want 1; paths=%+v", selected, paths)
			}
		})
	}
}

func selectedPathValidated(paths []PathInfo) bool {
	for _, p := range paths {
		if p.Selected {
			return p.Validated
		}
	}
	return false
}

func TestPathInfosFromSocketCarriesCongestionStats(t *testing.T) {
	paths := pathInfosFromSocket([]socket.PathInfo{{
		ID:                  7,
		Validated:           true,
		RTT:                 5 * time.Millisecond,
		HasRTT:              true,
		BytesInFlight:       123,
		HasBytesInFlight:    true,
		BytesSent:           234,
		HasBytesSent:        true,
		BytesReceived:       345,
		HasBytesReceived:    true,
		CongestionWindow:    456,
		HasCongestionWindow: true,
		LostPackets:         7,
		LostBytes:           890,
		HasLoss:             true,
	}})
	if len(paths) != 1 {
		t.Fatalf("paths len = %d, want 1", len(paths))
	}
	p := paths[0]
	if p.BytesInFlight != 123 || !p.HasBytesInFlight {
		t.Fatalf("BytesInFlight = %d, HasBytesInFlight = %v; want 123, true", p.BytesInFlight, p.HasBytesInFlight)
	}
	if p.BytesSent != 234 || !p.HasBytesSent {
		t.Fatalf("BytesSent = %d, HasBytesSent = %v; want 234, true", p.BytesSent, p.HasBytesSent)
	}
	if p.BytesReceived != 345 || !p.HasBytesReceived {
		t.Fatalf("BytesReceived = %d, HasBytesReceived = %v; want 345, true", p.BytesReceived, p.HasBytesReceived)
	}
	if p.CongestionWindow != 456 || !p.HasCongestionWindow {
		t.Fatalf("CongestionWindow = %d, HasCongestionWindow = %v; want 456, true", p.CongestionWindow, p.HasCongestionWindow)
	}
	if p.LostPackets != 7 || p.LostBytes != 890 || !p.HasLoss {
		t.Fatalf("loss = %d/%d, HasLoss = %v; want 7/890, true", p.LostPackets, p.LostBytes, p.HasLoss)
	}

	paths = pathInfosFromSocket([]socket.PathInfo{{ID: 8, Validated: true}})
	if len(paths) != 1 {
		t.Fatalf("guarded paths len = %d, want 1", len(paths))
	}
	if paths[0].HasBytesInFlight || paths[0].BytesInFlight != 0 {
		t.Fatalf("guarded BytesInFlight = %d, HasBytesInFlight = %v; want zero, false", paths[0].BytesInFlight, paths[0].HasBytesInFlight)
	}
	if paths[0].HasBytesSent || paths[0].BytesSent != 0 {
		t.Fatalf("guarded BytesSent = %d, HasBytesSent = %v; want zero, false", paths[0].BytesSent, paths[0].HasBytesSent)
	}
	if paths[0].HasBytesReceived || paths[0].BytesReceived != 0 {
		t.Fatalf("guarded BytesReceived = %d, HasBytesReceived = %v; want zero, false", paths[0].BytesReceived, paths[0].HasBytesReceived)
	}
	if paths[0].HasCongestionWindow || paths[0].CongestionWindow != 0 {
		t.Fatalf("guarded CongestionWindow = %d, HasCongestionWindow = %v; want zero, false", paths[0].CongestionWindow, paths[0].HasCongestionWindow)
	}
	if paths[0].HasLoss || paths[0].LostPackets != 0 || paths[0].LostBytes != 0 {
		t.Fatalf("guarded loss = %d/%d, HasLoss = %v; want zero, false", paths[0].LostPackets, paths[0].LostBytes, paths[0].HasLoss)
	}
}

func TestConnWatchPaths(t *testing.T) {
	client, server := connPair(t, "iroh-watch-paths/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	watch, err := client.WatchPaths(ctx)
	if err != nil {
		t.Fatalf("WatchPaths: %v", err)
	}
	select {
	case paths, ok := <-watch:
		if !ok {
			t.Fatal("WatchPaths closed before initial snapshot")
		}
		var selected bool
		for _, p := range paths {
			selected = selected || p.Selected
		}
		if !selected {
			t.Fatalf("initial WatchPaths snapshot has no selected path: %+v", paths)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestConnTicketIPSeedsDirectPath(t *testing.T) {
	ip := localNonLoopbackIPv4(t)
	if !ip.IsValid() {
		t.Skip("no non-loopback IPv4 address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-ticket-ip-direct-path/0"
	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	accepted := make(chan *Conn, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- conn
	}()

	serverAddr := server.LocalAddr()
	conn, err := connectWithRetry(ctx, client, netaddr.NewEndpointAddr(server.ID()).WithIP(serverAddr), alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")
	select {
	case peer := <-accepted:
		defer peer.CloseWithError(0, "")
	case err := <-errc:
		t.Fatalf("accept: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		for _, p := range conn.Paths() {
			if p.Validated && p.HasAddr && !p.Relayed {
				if p.Addr == (netaddr.IPAddr{Addr: serverAddr}) {
					t.Logf("validated direct path to ticket IP %v: %+v", serverAddr, p)
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("validated direct path to ticket IP %v not found; paths=%+v", serverAddr, conn.Paths())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConnTicketIPSeedsDirectPathTwoProcess(t *testing.T) {
	ip := localNonLoopbackIPv4(t)
	if !ip.IsValid() {
		t.Skip("no non-loopback IPv4 address")
	}
	bind := netip.AddrPortFrom(ip, 0)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"GO_IROH_TWOPROC_SERVER=1",
		"GO_IROH_TWOPROC_BIND="+bind.String(),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	var idStr string
	var serverAddr netip.AddrPort
	scan := bufio.NewScanner(stdout)
	deadline := time.After(5 * time.Second)
	for idStr == "" || !serverAddr.IsValid() {
		linec := make(chan string, 1)
		errc := make(chan error, 1)
		go func() {
			if scan.Scan() {
				linec <- scan.Text()
				return
			}
			errc <- scan.Err()
		}()
		select {
		case line := <-linec:
			switch {
			case strings.HasPrefix(line, "SERVER_ID="):
				idStr = strings.TrimPrefix(line, "SERVER_ID=")
			case strings.HasPrefix(line, "SERVER_LOCAL="):
				addr, err := netip.ParseAddrPort(strings.TrimPrefix(line, "SERVER_LOCAL="))
				if err != nil {
					t.Fatalf("parse server local: %v", err)
				}
				serverAddr = addr
			}
		case err := <-errc:
			t.Fatalf("server exited before coordinates: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for server coordinates")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := Bind(ctx, WithBindAddr(bind))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)
	serverID, err := key.ParseEndpointID(idStr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := connectWithRetry(ctx, client, netaddr.NewEndpointAddr(serverID).WithIP(serverAddr), "iroh-ticket-ip-direct-path/2proc")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")
	waitDirectPath(t, conn, serverAddr, 3*time.Second)
}

func runTwoProcessDirectPathServer() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bind, err := netip.ParseAddrPort(os.Getenv("GO_IROH_TWOPROC_BIND"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse bind: %v\n", err)
		os.Exit(2)
	}
	sk, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(sk), WithALPNs("iroh-ticket-ip-direct-path/2proc"), WithBindAddr(bind))
	if err != nil {
		fmt.Fprintf(os.Stderr, "bind: %v\n", err)
		os.Exit(2)
	}
	defer server.Shutdown(ctx)
	fmt.Printf("SERVER_ID=%s\n", server.ID())
	fmt.Printf("SERVER_LOCAL=%s\n", server.LocalAddr())
	os.Stdout.Sync()
	conn, err := server.Accept(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "accept: %v\n", err)
		os.Exit(2)
	}
	defer conn.CloseWithError(0, "")
	<-ctx.Done()
}

func waitDirectPath(t *testing.T, conn *Conn, want netip.AddrPort, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, p := range conn.Paths() {
			if p.Validated && p.HasAddr && !p.Relayed && p.Addr == (netaddr.IPAddr{Addr: want}) {
				t.Logf("validated direct path to ticket IP %v: %+v", want, p)
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("validated direct path to ticket IP %v not found; paths=%+v", want, conn.Paths())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func connectWithRetry(ctx context.Context, ep *Endpoint, addr netaddr.EndpointAddr, alpn string) (*Conn, error) {
	var last error
	for ctx.Err() == nil {
		conn, err := ep.Connect(ctx, addr, alpn)
		if err == nil {
			return conn, nil
		}
		last = err
		t := time.NewTimer(100 * time.Millisecond)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
		}
	}
	if last != nil {
		return nil, last
	}
	return nil, context.Cause(ctx)
}

func localNonLoopbackIPv4(t *testing.T) netip.Addr {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr()
			if ip.Is4() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	return netip.Addr{}
}

func TestStreamConn(t *testing.T) {
	client, server := connPair(t, "iroh-stream-conn/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		c, err := server.AcceptStreamConn(ctx)
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		if c.LocalAddr() == nil || c.RemoteAddr() == nil {
			done <- errors.New("stream conn missing addresses")
			return
		}
		var _ net.Conn = c
		b, err := io.ReadAll(c)
		if err != nil {
			done <- err
			return
		}
		if string(b) != "hello" {
			done <- fmt.Errorf("read %q, want hello", string(b))
			return
		}
		done <- nil
	}()

	c, err := client.OpenStreamConn(ctx)
	if err != nil {
		t.Fatalf("OpenStreamConn: %v", err)
	}
	if c.LocalAddr() == nil || c.RemoteAddr() == nil {
		t.Fatal("stream conn missing addresses")
	}
	var _ net.Conn = c
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStreamConnCloseReturnsCredit(t *testing.T) {
	client, server := connPair(t, "iroh-stream-conn-credit/0")
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		for i := 0; i < 150; i++ {
			c, err := server.AcceptStreamConn(ctx)
			if err != nil {
				done <- fmt.Errorf("accept stream %d: %w", i, err)
				return
			}
			if err := c.Close(); err != nil {
				done <- fmt.Errorf("close stream %d: %w", i, err)
				return
			}
		}
		done <- nil
	}()

	for i := 0; i < 150; i++ {
		c, err := client.OpenStreamConn(ctx)
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("close stream %d: %v", i, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSideString(t *testing.T) {
	tests := []struct {
		side Side
		want string
	}{
		{SideClient, "client"},
		{SideServer, "server"},
		{Side(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.side.String(); got != tt.want {
			t.Errorf("Side(%d).String() = %q, want %q", tt.side, got, tt.want)
		}
	}
}

// TestConnCloseWithError closes a connection with an application code and
// verifies that both sides observe the same application code.
func TestConnCloseWithError(t *testing.T) {
	client, server := connPair(t, "iroh-close/0")

	// While open, none of the close observers report a close.
	select {
	case <-client.Context().Done():
		t.Fatal("Context() fired while the connection was open")
	default:
	}
	if err := client.Context().Err(); err != nil {
		t.Fatalf("Context().Err() = %v while open, want nil", err)
	}

	const code = 42
	if err := client.CloseWithError(code, "bye"); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}

	// The local side observes the close.
	select {
	case <-client.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Context() did not fire after local Close")
	}
	var appErr *quic.ApplicationError
	if err := context.Cause(client.Context()); !errors.As(err, &appErr) {
		t.Fatalf("context cause = %v, want *quic.ApplicationError", err)
	} else if uint64(appErr.ErrorCode) != code {
		t.Errorf("local close code = %d, want %d", appErr.ErrorCode, code)
	}
	publicErr, ok := AsApplicationError(context.Cause(client.Context()))
	if !ok {
		t.Fatalf("AsApplicationError returned false")
	}
	if publicErr.Code != code || publicErr.Reason != "bye" || publicErr.Remote {
		t.Fatalf("AsApplicationError = %+v, want code %d reason bye remote false", publicErr, code)
	}

	// The peer observes the close carrying the same application code.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := server.AcceptStream(ctx)
	var peerErr *quic.ApplicationError
	if !errors.As(err, &peerErr) {
		t.Fatalf("peer AcceptStream err = %v, want *quic.ApplicationError", err)
	}
	if uint64(peerErr.ErrorCode) != code {
		t.Errorf("peer observed code %d, want %d", peerErr.ErrorCode, code)
	}
	if !peerErr.Remote {
		t.Error("peer's ApplicationError.Remote = false, want true (peer-initiated)")
	}
	publicPeerErr, ok := AsApplicationError(err)
	if !ok {
		t.Fatalf("AsApplicationError(peer err) returned false")
	}
	if publicPeerErr.Code != code || publicPeerErr.Reason != "bye" || !publicPeerErr.Remote {
		t.Fatalf("AsApplicationError(peer err) = %+v, want code %d reason bye remote true", publicPeerErr, code)
	}

	select {
	case <-server.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("peer Context() did not fire after remote close")
	}
}

// TestConnPeerInitiatedClose verifies that CloseWithError on one side is
// observed on the other side's context cause.
func TestConnPeerInitiatedClose(t *testing.T) {
	client, server := connPair(t, "iroh-peerclose/0")
	defer client.CloseWithError(0, "")

	const code = 7
	if err := server.CloseWithError(code, "server done"); err != nil {
		t.Fatalf("server CloseWithError: %v", err)
	}

	select {
	case <-client.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client Context() did not fire after peer close")
	}
	var appErr *quic.ApplicationError
	if err := context.Cause(client.Context()); !errors.As(err, &appErr) {
		t.Fatalf("client context cause = %v, want *quic.ApplicationError", err)
	} else if uint64(appErr.ErrorCode) != code {
		t.Errorf("client observed code %d, want %d", appErr.ErrorCode, code)
	}
}

// TestConnUniStream exercises OpenUniStream/AcceptUniStream end to end.
func TestConnUniStream(t *testing.T) {
	client, server := connPair(t, "iroh-uni/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const msg = "uni hello"
	type result struct {
		data []byte
		err  error
	}
	got := make(chan result, 1)
	go func() {
		rs, err := server.AcceptUniStream(ctx)
		if err != nil {
			got <- result{err: err}
			return
		}
		b, err := io.ReadAll(rs)
		got <- result{data: b, err: err}
	}()

	ss, err := client.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	if _, err := ss.Write([]byte(msg)); err != nil {
		t.Fatalf("write uni: %v", err)
	}
	ss.Close()

	res := <-got
	if res.err != nil {
		t.Fatalf("read uni: %v", res.err)
	}
	if string(res.data) != msg {
		t.Errorf("uni stream = %q, want %q", res.data, msg)
	}
}

func TestConnMaxDatagramSize(t *testing.T) {
	client, server := connPair(t, "iroh-max-datagram/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	maxSize, ok := client.MaxDatagramSize()
	if !ok {
		t.Fatal("client.MaxDatagramSize ok = false, want true")
	}
	if maxSize <= 0 {
		t.Fatalf("client.MaxDatagramSize = %d, want positive", maxSize)
	}

	if err := client.SendDatagram(make([]byte, 1<<16)); err == nil {
		t.Fatal("SendDatagram over max size succeeded")
	} else {
		var tooLarge *quic.DatagramTooLargeError
		if !errors.As(err, &tooLarge) {
			t.Fatalf("SendDatagram over max size error = %T, want *quic.DatagramTooLargeError", err)
		}
		if tooLarge.MaxDatagramPayloadSize <= 0 {
			t.Fatalf("too large max = %d, want positive", tooLarge.MaxDatagramPayloadSize)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := make([]byte, min(maxSize, 64))
	for i := range msg {
		msg[i] = byte(i)
	}
	if err := client.SendDatagram(msg); err != nil {
		t.Fatalf("SendDatagram within max size: %v", err)
	}
	got, err := server.ReadDatagram(ctx)
	if err != nil {
		t.Fatalf("server ReadDatagram: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("server datagram = %x, want %x", got, msg)
	}
}

func clientStableIDCount(e *Endpoint) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.stableIDs)
}

// ExampleConn_Stats prints whether a loopback connection has recorded traffic.
func ExampleConn_Stats() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-stats-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Shutdown(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Shutdown(ctx)

	go server.Accept(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer conn.CloseWithError(0, "")

	stats := conn.Stats()
	fmt.Println(stats.BytesSent > 0)
	// Output:
	// true
}

// ExampleConn_Paths prints whether a loopback connection has a selected path.
func ExampleConn_Paths() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-paths-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Shutdown(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Shutdown(ctx)

	go server.Accept(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer conn.CloseWithError(0, "")

	for _, path := range conn.Paths() {
		if path.Selected {
			fmt.Println(path.HasAddr, path.Relayed)
			break
		}
	}
	// Output:
	// true false
}

// ExampleConn_WatchPaths prints whether the initial path snapshot is usable.
func ExampleConn_WatchPaths() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-watch-paths-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Shutdown(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Shutdown(ctx)

	go server.Accept(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer conn.CloseWithError(0, "")

	watch, err := conn.WatchPaths(ctx)
	if err != nil {
		fmt.Println("watch:", err)
		return
	}
	paths := <-watch
	fmt.Println(len(paths) > 0)
	// Output:
	// true
}

// ExampleConn_CloseWithError closes a loopback connection with an application
// code and reads it back from the connection context cause.
func ExampleConn_CloseWithError() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-close-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Shutdown(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Shutdown(ctx)

	go server.Accept(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}

	conn.CloseWithError(42, "done")
	<-conn.Context().Done()

	var appErr *quic.ApplicationError
	if errors.As(context.Cause(conn.Context()), &appErr) {
		fmt.Println("close code:", appErr.ErrorCode)
	}
	// Output:
	// close code: 42
}

func ExampleAsApplicationError() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-application-error-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Shutdown(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Shutdown(ctx)

	accepted := make(chan *Conn, 1)
	go func() {
		conn, _ := server.Accept(ctx)
		accepted <- conn
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer conn.CloseWithError(0, "")

	peer := <-accepted
	peer.CloseWithError(7, "done")
	<-conn.Context().Done()

	appErr, ok := AsApplicationError(context.Cause(conn.Context()))
	fmt.Println(ok, appErr.Code, appErr.Reason, appErr.Remote)
	// Output:
	// true 7 done true
}
