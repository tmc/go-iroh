package docs

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// rustInitFrames are /iroh-sync/1 Init frames as iroh-docs 0.101.0 writes
// them: run_alice's first frame (src/net/codec.rs:105-116) for a replica
// holding the given entries, framed by SyncCodec (src/net/codec.rs:48-67).
// They were printed by a Rust program that builds the replica with
// iroh_docs::store::Store::memory, takes Replica::sync_initial_message, and
// serializes it in an enum mirroring codec.rs:77-89.
var rustInitFrames = []struct {
	name      string
	namespace byte
	entries   []string
	frame     string
}{
	{
		name:      "empty",
		namespace: 0xb3,
		frame: "000000c5005912dac020dcdaba767ceca64243e845176215c485e418e50f80205d81218a910100" +
			"4000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"0040000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"0000af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
	},
	{
		name:      "one entry",
		namespace: 0xb2,
		entries:   []string{"k"},
		frame: "000000c70055154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207010041" +
			"55154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207" +
			"bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a56b41" +
			"55154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207" +
			"bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a56b" +
			"d61fba2b8d6e4e9edd9be8a413377a7bad9ea730685b276ff14253048d05c056",
	},
}

// TestSyncOpensWithInit pins the dialer's first frame to the bytes iroh-docs
// writes. A Rust acceptor decodes only Init, Sync and Abort, so any other
// opening frame ends the sync before it starts.
func TestSyncOpensWithInit(t *testing.T) {
	for _, tt := range rustInitFrames {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			namespace := NewNamespaceSecret(repeat32(tt.namespace))
			author := NewAuthor(repeat32(0xa1))
			store := NewMemoryStore()
			for _, k := range tt.entries {
				store.Put(testSignedEntry(namespace, author, k, testRecord("same", 1, 1)))
			}

			first := make(chan []byte, 1)
			server := newSyncNode(t, ctx, iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
				s, err := conn.AcceptStream(ctx)
				if err != nil {
					return err
				}
				defer s.Close()
				frame, err := readRawFrame(s)
				first <- frame
				if err != nil {
					return err
				}
				return writeSyncFrame(s, syncWireMessage{Kind: syncMessageAbort, Reason: AbortNotFound})
			}))
			client := newSyncClient(t, ctx)
			if _, err := Sync(ctx, client, syncAddr(server), namespace.ID(), store, nil, DefaultSyncConfig()); err == nil {
				t.Fatal("Sync succeeded against an aborting peer")
			}
			var got []byte
			select {
			case got = <-first:
			case <-ctx.Done():
				t.Fatal("acceptor never read the first frame")
			}
			if want := tt.frame; hex.EncodeToString(got) != want {
				t.Fatalf("first frame = %x\nwant %s", got, want)
			}
		})
	}
}

// TestSyncCompat covers each pairing of dialer and acceptor across the
// change that made the dialer open with Init. Handler.Accept reads Init as
// v0.2.3 did, so the new dialer against it stands for the new dialer against
// an old acceptor.
func TestSyncCompat(t *testing.T) {
	tests := []struct {
		name  string
		dial  func(context.Context, *iroh.Endpoint, netaddr.EndpointAddr, NamespaceID, *MemoryStore) (SyncOutcome, error)
		equal bool
	}{
		{"init dialer, equal heads", dialSync, true},
		{"init dialer, divergent heads", dialSync, false},
		{"report dialer, equal heads", dialReportSync, true},
		{"report dialer, divergent heads", dialReportSync, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			namespace := NewNamespaceSecret(repeat32(0xb2))
			author := NewAuthor(repeat32(0xa1))
			serverEntry := testSignedEntry(namespace, author, "server", testRecord("server", 1, 2))
			clientEntry := testSignedEntry(namespace, author, "client", testRecord("client", 1, 1))
			serverStore := NewMemoryStore()
			serverStore.Put(serverEntry)
			clientStore := NewMemoryStore()
			clientStore.Put(clientEntry)
			if tt.equal {
				serverStore.Put(clientEntry)
				clientStore.Put(serverEntry)
			}

			var splits atomic.Int64
			config := DefaultSyncConfig()
			config.splitHook = func(Range) { splits.Add(1) }
			server := newSyncNode(t, ctx, &Handler{Store: serverStore, Config: config})
			client := newSyncClient(t, ctx)
			outcome, err := tt.dial(ctx, client, syncAddr(server), namespace.ID(), clientStore)
			if err != nil {
				t.Fatalf("sync: %v", err)
			}
			if tt.equal && outcome != (SyncOutcome{}) {
				t.Fatalf("outcome = %+v, want zero", outcome)
			}
			if !tt.equal && (outcome.NumSent == 0 || outcome.NumRecv == 0) {
				t.Fatalf("outcome = %+v, want range reconciliation", outcome)
			}
			if n := splits.Load(); tt.equal && n != 0 {
				t.Fatalf("range splits = %d, want 0", n)
			}
			for _, k := range []string{"server", "client"} {
				if _, ok := serverStore.GetExact(namespace.ID(), author.ID(), []byte(k), false); !ok {
					t.Fatalf("server missing %q", k)
				}
				if _, ok := clientStore.GetExact(namespace.ID(), author.ID(), []byte(k), false); !ok {
					t.Fatalf("client missing %q", k)
				}
			}
		})
	}
}

func dialSync(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, namespace NamespaceID, store *MemoryStore) (SyncOutcome, error) {
	return Sync(ctx, ep, addr, namespace, store, nil, DefaultSyncConfig())
}

// dialReportSync is the v0.2.3 Sync: it opens with a heads report and
// reconciles only when the acceptor's heads differ.
func dialReportSync(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, namespace NamespaceID, store *MemoryStore) (SyncOutcome, error) {
	conn, err := ep.Connect(ctx, addr, ALPN)
	if err != nil {
		return SyncOutcome{}, err
	}
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return SyncOutcome{}, err
	}
	defer s.Close()
	heads := store.encodeSyncHeads(namespace)
	if err := writeSyncFrame(s, syncWireMessage{Kind: syncMessageReport, Namespace: namespace, Report: liveSyncReport{
		Namespace: namespace,
		Heads:     heads,
	}}); err != nil {
		return SyncOutcome{}, err
	}
	report, err := readSyncFrame(s)
	if err != nil {
		return SyncOutcome{}, err
	}
	if report.Kind != syncMessageReport || report.Report.Namespace != namespace {
		return SyncOutcome{}, fmt.Errorf("expected sync report, got %d", report.Kind)
	}
	if bytes.Equal(report.Report.Heads, heads) {
		return SyncOutcome{}, nil
	}
	if err := writeSyncFrame(s, syncWireMessage{Kind: syncMessageInit, Namespace: namespace, Message: store.InitialMessageInNamespace(namespace)}); err != nil {
		return SyncOutcome{}, err
	}
	h := Handler{Store: store, Config: DefaultSyncConfig()}
	return h.run(ctx, s, namespace, Message{}, false)
}

func readRawFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxSyncMessageSize {
		return nil, fmt.Errorf("frame too large: %d", n)
	}
	frame := make([]byte, 4+n)
	copy(frame, hdr[:])
	_, err := io.ReadFull(r, frame[4:])
	return frame, err
}

func newSyncNode(t *testing.T, ctx context.Context, h iroh.ProtocolHandler) *iroh.Endpoint {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{ALPN: h}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	t.Cleanup(func() { router.Shutdown(context.Background()) })
	return ep
}

func newSyncClient(t *testing.T, ctx context.Context) *iroh.Endpoint {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	t.Cleanup(func() { ep.Shutdown(context.Background()) })
	return ep
}

func syncAddr(ep *iroh.Endpoint) netaddr.EndpointAddr {
	return netaddr.NewEndpointAddr(ep.ID()).WithIP(ep.LocalAddr())
}
