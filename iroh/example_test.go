package iroh_test

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// ExampleQLOGDir installs a per-endpoint qlog sink. The same sink can be
// passed to several endpoints when their traces belong in one directory.
func ExampleQLOGDir() {
	dir, err := os.MkdirTemp("", "iroh-qlog-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	sink := iroh.QLOGDir(dir)
	w := sink(context.Background(), iroh.QLOGConnection{
		ConnectionID: "0102",
		Client:       true,
	})
	if w == nil {
		panic("create qlog")
	}
	if _, err := io.WriteString(w, "trace"); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		panic(err)
	}
	fmt.Println(entries[0].Name())
	// Output: 0102_client.sqlog
}

// ExampleEndpoint_Online binds an endpoint that uses the n0 staging relays and
// waits until it has a connected home relay before dialing.
func ExampleEndpoint_Online() {
	ctx := context.Background()

	ep, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeStaging()))
	if err != nil {
		fmt.Println("bind:", err)
		return
	}
	defer ep.Shutdown(ctx)

	// Block until a home relay connection is established (or ctx is done).
	if err := ep.Online(ctx); err != nil {
		fmt.Println("online:", err)
		return
	}

	// ep.Addr() now includes the home relay URL, so peers can reach this
	// endpoint over the relay.
	fmt.Println(len(ep.Addr().RelayURLs()) >= 0)
}

// ExampleEndpoint_HomeRelayStatus observes the home relay connection status.
func ExampleEndpoint_HomeRelayStatus() {
	ctx := context.Background()

	ep, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeDefault()))
	if err != nil {
		fmt.Println("bind:", err)
		return
	}
	defer ep.Shutdown(ctx)

	status := ep.HomeRelayStatus().Current()
	if status != nil && status.IsConnected() {
		fmt.Println("connected to", status.URL)
	}
}

// ExampleEndpoint_RemoteInfo prints whether a direct loopback peer has an
// active known address.
func ExampleEndpoint_RemoteInfo() {
	ctx := context.Background()
	const alpn = "iroh/remote-info/1"

	server, err := iroh.Bind(ctx,
		iroh.WithALPNs(alpn),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		fmt.Println("bind server:", err)
		return
	}
	defer server.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		fmt.Println("bind client:", err)
		return
	}
	defer client.Shutdown(ctx)

	accepted := make(chan *iroh.Conn, 1)
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
	defer (<-accepted).CloseWithError(0, "")

	info, ok := client.RemoteInfo(server.ID())
	fmt.Println(ok, info.ID == server.ID(), len(info.Addrs) > 0)
	// Output:
	// true true true
}

// ExampleEndpoint_Connect_addressLookup dials a peer using only its endpoint
// ID after an address lookup service supplies its transport address.
func ExampleEndpoint_Connect_addressLookup() {
	ctx := context.Background()
	const alpn = "iroh/address-lookup/1"

	server, err := iroh.Bind(ctx,
		iroh.WithALPNs(alpn),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		panic(err)
	}
	defer server.Shutdown(ctx)

	lookup := iroh.NewMemoryLookup()
	lookup.AddEndpointAddr(netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()))
	var services iroh.AddressLookupServices
	services.AddResolver(lookup)
	client, err := iroh.Bind(ctx,
		iroh.WithAddressLookup(&services),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		panic(err)
	}
	defer client.Shutdown(ctx)

	accepted := make(chan *iroh.Conn, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()), alpn)
	if err != nil {
		panic(err)
	}
	defer conn.CloseWithError(0, "")
	if server := <-accepted; server != nil {
		defer server.CloseWithError(0, "")
	}
	fmt.Println(conn.RemoteID() == server.ID())
	// Output: true
}

func echo(ctx context.Context, conn *iroh.Conn) error {
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	if _, err := io.Copy(s, s); err != nil {
		return err
	}
	return s.Close()
}

// ExampleRouter runs an echo protocol over a direct loopback connection: a
// server registers the echo handler via a Router, and a client connects, sends
// a message on a stream, and reads the echo back.
func ExampleRouter() {
	ctx := context.Background()
	const alpn = "iroh/echo/1"

	srvKey, _ := key.GenerateSecretKey()
	server, err := iroh.Bind(ctx, iroh.WithSecretKey(srvKey),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		fmt.Println("bind server:", err)
		return
	}

	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		alpn: iroh.ProtocolHandlerFunc(echo),
	}, nil)
	if err != nil {
		fmt.Println("router:", err)
		return
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		fmt.Println("bind client:", err)
		return
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer conn.CloseWithError(0, "")

	s, _ := conn.OpenStreamSync(ctx)
	s.Write([]byte("hello"))
	// CloseWrite tells the server that the request is complete while leaving
	// the read side open for its response.
	s.CloseWrite()
	got, _ := io.ReadAll(s)
	fmt.Printf("%s\n", got)
	// Output: hello
}
