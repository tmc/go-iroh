package docs_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/docs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestSyncLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	namespace := docs.NewNamespaceSecret(repeat32(0xb2))
	author := docs.NewAuthor(repeat32(0xa1))
	serverEntry := signedEntry(namespace, author, "server", "server-data", 1)
	clientEntry := signedEntry(namespace, author, "client", "client-data", 1)

	serverStore := docs.NewMemoryStore()
	serverStore.Put(serverEntry)
	clientStore := docs.NewMemoryStore()
	clientStore.Put(clientEntry)

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		docs.ALPN: &docs.Handler{Store: serverStore, Allow: func(ns docs.NamespaceID, _ key.EndpointID) bool { return ns == namespace.ID() }},
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	outcome, err := docs.Sync(ctx, client, addr, namespace.ID(), clientStore, nil, docs.DefaultSyncConfig())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if outcome.NumSent == 0 || outcome.NumRecv == 0 {
		t.Fatalf("outcome = %+v, want sent and received entries", outcome)
	}
	if _, ok := serverStore.GetExact(namespace.ID(), author.ID(), []byte("client"), false); !ok {
		t.Fatal("server missing client entry")
	}
	if _, ok := clientStore.GetExact(namespace.ID(), author.ID(), []byte("server"), false); !ok {
		t.Fatal("client missing server entry")
	}
}

func TestSyncReject(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	namespace := docs.NewNamespaceSecret(repeat32(0xb2))
	serverStore := docs.NewMemoryStore()

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		docs.ALPN: &docs.Handler{
			Store: serverStore,
			Allow: func(namespace docs.NamespaceID, peer key.EndpointID) bool {
				if namespace.String() == "" {
					t.Fatal("empty namespace in Allow")
				}
				if peer.String() == "" {
					t.Fatal("empty peer in Allow")
				}
				return false
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	_, err = docs.Sync(ctx, client, addr, namespace.ID(), docs.NewMemoryStore(), nil, docs.DefaultSyncConfig())
	if err == nil {
		t.Fatal("Sync succeeded, want abort error")
	}
}

func signedEntry(namespace docs.NamespaceSecret, author docs.Author, key, data string, timestamp uint64) docs.SignedEntry {
	hash := blobs.NewHash([]byte(data))
	id := docs.NewRecordIdentifier(namespace.ID(), author.ID(), []byte(key))
	return docs.NewSignedEntry(docs.NewEntry(id, docs.NewRecord(hash, uint64(len(data)), timestamp)), namespace, author)
}

func repeat32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func TestSyncConfinedToNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	shared := docs.NewNamespaceSecret(repeat32(0xb2))
	other := docs.NewNamespaceSecret(repeat32(0xb3))
	author := docs.NewAuthor(repeat32(0xa1))
	serverEntry := signedEntry(shared, author, "server", "server-data", 1)
	serverSecret := signedEntry(other, author, "server-secret", "server-secret-data", 1)
	clientSecret := signedEntry(other, author, "client-secret", "client-secret-data", 1)

	serverStore := docs.NewMemoryStore()
	serverStore.Put(serverEntry)
	serverStore.Put(serverSecret)
	clientStore := docs.NewMemoryStore()
	clientStore.Put(clientSecret)

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		docs.ALPN: &docs.Handler{
			Store: serverStore,
			Allow: func(namespace docs.NamespaceID, peer key.EndpointID) bool {
				return namespace == shared.ID()
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	if _, err := docs.Sync(ctx, client, addr, shared.ID(), clientStore, nil, docs.DefaultSyncConfig()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if _, ok := clientStore.GetExact(shared.ID(), author.ID(), []byte("server"), false); !ok {
		t.Fatal("client missing authorized namespace entry")
	}
	if _, ok := clientStore.GetExact(other.ID(), author.ID(), []byte("server-secret"), false); ok {
		t.Fatal("server disclosed an entry from an unauthorized namespace")
	}
	if _, ok := serverStore.GetExact(other.ID(), author.ID(), []byte("client-secret"), false); ok {
		t.Fatal("client disclosed an entry from another namespace")
	}
}
