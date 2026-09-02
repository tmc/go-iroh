package iroh

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestKeyExchangePolicyNegotiation(t *testing.T) {
	tests := []struct {
		name   string
		policy KeyExchangePolicy
		group  string
	}{
		{name: "classical", policy: KeyExchangeClassical, group: "X25519"},
		{name: "prefer pq", policy: KeyExchangePreferPQ, group: "X25519MLKEM768"},
		{name: "pq only", policy: KeyExchangePQOnly, group: "X25519MLKEM768"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server, err := Bind(ctx, WithALPNs("iroh-kx-test/0"), WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), WithKeyExchangePolicy(tt.policy))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Shutdown(context.Background())
			client, err := Bind(ctx, WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), WithKeyExchangePolicy(tt.policy))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Shutdown(context.Background())

			accepted := make(chan *Conn, 1)
			acceptErr := make(chan error, 1)
			go func() {
				conn, err := server.Accept(ctx)
				if err != nil {
					acceptErr <- err
					return
				}
				accepted <- conn
			}()
			addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
			conn, err := client.Connect(ctx, addr, "iroh-kx-test/0")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if got := conn.KeyExchangeGroup(); got != tt.group {
				t.Fatalf("client group = %q, want %q", got, tt.group)
			}
			select {
			case peer := <-accepted:
				defer peer.Close()
				if got := peer.KeyExchangeGroup(); got != tt.group {
					t.Fatalf("server group = %q, want %q", got, tt.group)
				}
			case err := <-acceptErr:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

// TestKeyExchangeMismatchIsReported checks that a dial refused for want of a
// common key-exchange group is reported as ErrTLSHandshakeFailure, in both
// directions: the alert reaches the dialer whether its own policy or the
// server's is the narrower one.
func TestKeyExchangeMismatchIsReported(t *testing.T) {
	tests := []struct {
		name           string
		server, client KeyExchangePolicy
	}{
		{name: "pq only server", server: KeyExchangePQOnly, client: KeyExchangeClassical},
		{name: "pq only client", server: KeyExchangeClassical, client: KeyExchangePQOnly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server, err := Bind(ctx, WithALPNs("iroh-kx-test/0"), WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), WithKeyExchangePolicy(tt.server))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Shutdown(context.Background())
			client, err := Bind(ctx, WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), WithKeyExchangePolicy(tt.client))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Shutdown(context.Background())
			addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
			_, err = client.Connect(ctx, addr, "iroh-kx-test/0")
			if err == nil {
				t.Fatal("connected despite incompatible key exchange policies")
			}
			if !errors.Is(err, ErrTLSHandshakeFailure) {
				t.Errorf("Connect error = %v, want one matching ErrTLSHandshakeFailure", err)
			}
		})
	}
}

// TestKeyExchangeMatchIsNotHandshakeFailure guards against ErrTLSHandshakeFailure
// being attached to failures that are not TLS alerts.
func TestKeyExchangeMatchIsNotHandshakeFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	client, err := Bind(ctx, WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), WithKeyExchangePolicy(KeyExchangePQOnly))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(context.Background())
	// Nothing is listening, so the dial times out rather than being refused.
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	dead := netaddr.NewEndpointAddr(sk.Public().EndpointID()).WithIP(netip.MustParseAddrPort("127.0.0.1:1"))
	if _, err := client.Connect(ctx, dead, "iroh-kx-test/0"); err == nil {
		t.Fatal("dial to a dead address succeeded")
	} else if errors.Is(err, ErrTLSHandshakeFailure) {
		t.Errorf("Connect error = %v, want no ErrTLSHandshakeFailure match", err)
	}
}

func TestWithKeyExchangePolicyRejectsInvalidValue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Bind(ctx, WithKeyExchangePolicy(KeyExchangePolicy(255))); err == nil {
		t.Fatal("Bind accepted invalid key exchange policy")
	}
}
