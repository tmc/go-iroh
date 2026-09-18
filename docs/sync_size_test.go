package docs

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// An empty replica must be able to sync a namespace whose entries together
// exceed one frame. MaxSetSize must not be bypassed by the empty fingerprint.
func TestSyncLargeNamespaceToEmptyStore(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	source := NewMemoryStore()
	const count = 1024
	for i := range count {
		k := fmt.Sprintf("%04d/", i) + strings.Repeat("k", 16*1024)
		entry := testSignedEntry(namespace, author, k, testRecord("value", 5, 1))
		// The fixed-width prefixes are distinct. Populate the fixture directly
		// to avoid Put's quadratic prefix comparisons on these long keys.
		source.entries[string(entry.Entry.ID.bytes())] = entry
	}
	destination := NewMemoryStore()
	message := destination.InitialMessageInNamespace(namespace.ID())
	from, to := destination, source
	const maxRounds = 2*count + 2
	for round := range maxRounds {
		var frame bytes.Buffer
		if err := writeSyncFrame(&frame, syncWireMessage{Kind: syncMessageSync, Message: message}); err != nil {
			t.Fatalf("round %d: write frame with %d entries: %v", round, message.ValueCount(), err)
		}
		decoded, err := readSyncFrame(&frame)
		if err != nil {
			t.Fatalf("round %d: read frame: %v", round, err)
		}
		reply, more := to.ProcessMessageInNamespace(namespace.ID(), DefaultSyncConfig(), decoded.Message, nil, nil, nil)
		if !more {
			if got := destination.Len(); got != count {
				t.Fatalf("destination has %d entries, want %d", got, count)
			}
			for k, want := range source.entries {
				if got, ok := destination.entries[k]; !ok || !got.Equal(want) {
					t.Fatal("destination differs from source")
				}
			}
			break
		}
		message = reply
		from, to = to, from
		if round == maxRounds-1 {
			t.Fatalf("sync did not converge in %d rounds", maxRounds)
		}
	}

	// Exercise the stream path as well as the in-memory reconciliation loop.
	// The race detector makes the large stream transfer slow on a busy host.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bind := iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0))
	server, err := iroh.Bind(ctx, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{ALPN: &Handler{Store: source}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(ctx)
	client, err := iroh.Bind(ctx, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)
	got := NewMemoryStore()
	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	if _, err := Sync(ctx, client, addr, namespace.ID(), got, nil, DefaultSyncConfig()); err != nil {
		t.Fatalf("stream sync: %v", err)
	}
	if got.Len() != count {
		t.Fatalf("stream sync received %d entries, want %d", got.Len(), count)
	}
}
