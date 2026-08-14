package iroh_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// TestEndpointAddrOmitsUnspecified checks that the address an endpoint
// advertises never includes the unspecified bind address.
//
// Binding without WithBindAddr leaves the socket on [::]:port, which means
// "every interface on this host" and is not something a peer can dial.
func TestEndpointAddrOmitsUnspecified(t *testing.T) {
	ctx := t.Context()

	ep := bindForAddrTest(t, ctx)
	if !ep.LocalAddr().Addr().IsUnspecified() {
		t.Skipf("bound to %s, want an unspecified address for this test", ep.LocalAddr())
	}

	for _, addr := range ep.Addr().IPAddrs() {
		if addr.Addr().IsUnspecified() {
			t.Errorf("Addr() advertises the unspecified address %s; peers cannot dial it", addr)
		}
	}
	for _, addr := range ep.WatchAddr().Current().IPAddrs() {
		if addr.Addr().IsUnspecified() {
			t.Errorf("WatchAddr() reports the unspecified address %s; peers cannot dial it", addr)
		}
	}
}

// TestConnectToAddrWithExternalAddr connects to an endpoint the way an
// application does: by dialing what Endpoint.Addr reports, which is what an
// endpoint ticket carries.
//
// An application that wants peers to reach it directly pins its interface
// address with AddExternalAddr, which also offers that address as a QNT NAT
// traversal candidate. When Addr also carried the unspecified bind address, the
// resulting PATH_RESPONSE arrived from a source the connection did not
// recognize and closed it with
//
//	PROTOCOL_VIOLATION (local): unexpected PATH_RESPONSE frame
func TestConnectToAddrWithExternalAddr(t *testing.T) {
	const alpn = "iroh/external-addr-test/1"

	ctx := t.Context()
	local := routableInterfaceAddr(t)

	server := bindForAddrTest(t, ctx, alpn)
	client := bindForAddrTest(t, ctx)

	server.AddExternalAddr(netip.AddrPortFrom(local, server.LocalAddr().Port()))
	client.AddExternalAddr(netip.AddrPortFrom(local, client.LocalAddr().Port()))

	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		alpn: iroh.ProtocolHandlerFunc(echoEveryStream),
	}, nil)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	defer router.Shutdown(context.Background())

	conn, err := client.Connect(ctx, server.Addr(), alpn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// NAT traversal probing runs shortly after the handshake, so exercise the
	// connection across that window rather than only at the start.
	for i := range 10 {
		if err := echoRoundTrip(ctx, conn); err != nil {
			t.Fatalf("round trip %d of 10: %v (connection: %v)", i+1, err, context.Cause(conn.Context()))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func echoEveryStream(ctx context.Context, conn *iroh.Conn) error {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return nil
		}
		go func() {
			io.Copy(stream, stream)
			stream.Close()
		}()
	}
}

func echoRoundTrip(ctx context.Context, conn *iroh.Conn) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	if _, err := stream.Write([]byte("ping")); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	// Close the send side so the echo handler's io.Copy finishes.
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close write: %w", err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(got) != "ping" {
		return fmt.Errorf("echoed %q, want %q", got, "ping")
	}
	return nil
}

func bindForAddrTest(t *testing.T, ctx context.Context, alpns ...string) *iroh.Endpoint {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}
	opts := []iroh.Option{iroh.WithSecretKey(sk)}
	if len(alpns) > 0 {
		opts = append(opts, iroh.WithALPNs(alpns...))
	}
	ep, err := iroh.Bind(ctx, opts...)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { ep.Shutdown(context.Background()) })
	return ep
}

// routableInterfaceAddr returns an IPv4 address of one of this machine's
// interfaces, skipping loopback and link-local, which are not usable NAT
// traversal candidates.
func routableInterfaceAddr(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			if ip = ip.Unmap(); ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	t.Skip("no routable interface address on this machine")
	return netip.Addr{}
}
