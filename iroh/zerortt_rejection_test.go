package iroh

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestEndpointConnectFallsBackAfter0RTTRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const alpn = "iroh-0rtt-rejection/0"

	serverKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	client, err := Bind(
		ctx,
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(context.Background())

	bindServer := func() *Endpoint {
		server, err := Bind(
			ctx,
			WithSecretKey(serverKey),
			WithALPNs(alpn),
			WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		)
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	type acceptResult struct {
		conn *Conn
		err  error
	}
	accept := func(server *Endpoint) <-chan acceptResult {
		result := make(chan acceptResult, 1)
		go func() {
			conn, err := server.Accept(ctx)
			result <- acceptResult{conn: conn, err: err}
		}()
		return result
	}

	server := bindServer()
	accepted := accept(server)
	clientConn, err := client.Connect(
		ctx,
		netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()),
		alpn,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverResult := <-accepted
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	defer serverResult.conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for client.sessionCache.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if client.sessionCache.Len() == 0 {
		t.Fatal("client did not cache a TLS session")
	}
	if err := clientConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serverResult.conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	server = bindServer()
	defer server.Shutdown(context.Background())
	accepted = accept(server)
	clientConn, err = client.Connect(
		ctx,
		netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()),
		alpn,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverResult = <-accepted
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	defer serverResult.conn.Close()

	serverStream, err := serverResult.conn.OpenStreamConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer serverStream.Close()
	if _, err := serverStream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := serverStream.Close(); err != nil {
		t.Fatal(err)
	}
	clientStream, err := clientConn.AcceptStreamConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientStream.Close()
	payload, err := io.ReadAll(clientStream)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "ping" {
		t.Fatalf("payload = %q, want ping", payload)
	}
}
