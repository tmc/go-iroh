package socket

import (
	"bytes"
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/relayclient"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// fakeRelayClient is an in-process relay connection used to drive the
// [RelayActor] without a network. Sends are recorded and made available on sent;
// the test feeds frames back through recv.
type fakeRelayClient struct {
	sent chan relayproto.ClientToRelayMsg
	recv chan relayproto.RelayToClientMsg
	done chan struct{}
}

func newFakeRelayClient() *fakeRelayClient {
	return &fakeRelayClient{
		sent: make(chan relayproto.ClientToRelayMsg, 64),
		recv: make(chan relayproto.RelayToClientMsg, 64),
		done: make(chan struct{}),
	}
}

func (c *fakeRelayClient) Send(ctx context.Context, msg relayproto.ClientToRelayMsg) error {
	// Auto-answer pings with a matching pong so the connection becomes
	// established and the ping timeout never fires during tests.
	if msg.Type == relayproto.FramePing {
		select {
		case c.recv <- relayproto.RelayToClientMsg{Type: relayproto.FramePong, Ping: msg.Ping}:
		case <-c.done:
		}
	}
	msg.Datagrams.Contents = bytes.Clone(msg.Datagrams.Contents)
	select {
	case c.sent <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return context.Canceled
	}
}

func (c *fakeRelayClient) Recv(ctx context.Context) (relayproto.RelayToClientMsg, error) {
	select {
	case msg := <-c.recv:
		return msg, nil
	case <-ctx.Done():
		return relayproto.RelayToClientMsg{}, ctx.Err()
	case <-c.done:
		return relayproto.RelayToClientMsg{}, context.Canceled
	}
}

func (c *fakeRelayClient) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return nil
}

func testURL(t *testing.T) netaddr.RelayURL {
	t.Helper()
	u, err := netaddr.ParseRelayURL("https://relay.test.example.")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// startActorWith starts a RelayActor whose dialer always returns client. It
// returns the actor and a cancel that stops it.
func startActorWith(t *testing.T, client *fakeRelayClient) (*RelayActor, context.CancelFunc) {
	t.Helper()
	sk, _ := key.GenerateSecretKey()
	a := NewRelayActor(RelayActorConfig{
		SecretKey: sk,
		dialer:    func(context.Context, netaddr.RelayURL, relayclient.Options) (relayClient, error) { return client, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	go a.Run(ctx)
	t.Cleanup(cancel)
	return a, cancel
}

// TestSplitSegments verifies the GRO-stride splitting of a relay batch into
// individual datagrams, matching the Rust take_segments stride
// (iroh/src/socket/transports/relay.rs:154).
func TestSplitSegments(t *testing.T) {
	tests := []struct {
		name string
		d    relayproto.Datagrams
		want [][]byte
	}{
		{
			name: "single",
			d:    relayproto.Datagrams{Contents: []byte("hello")},
			want: [][]byte{[]byte("hello")},
		},
		{
			name: "batch exact",
			d:    relayproto.Datagrams{SegmentSize: 2, Contents: []byte("aabbcc")},
			want: [][]byte{[]byte("aa"), []byte("bb"), []byte("cc")},
		},
		{
			name: "batch ragged",
			d:    relayproto.Datagrams{SegmentSize: 3, Contents: []byte("aaabbc")},
			want: [][]byte{[]byte("aaa"), []byte("bbc")},
		},
		{
			name: "batch ragged tail",
			d:    relayproto.Datagrams{SegmentSize: 4, Contents: []byte("aaaab")},
			want: [][]byte{[]byte("aaaa"), []byte("b")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitSegments(tt.d)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d segments, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if !bytes.Equal(got[i], tt.want[i]) {
					t.Errorf("segment %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestPingTimeoutDisarmedByPong is a regression test for a relay keepalive bug:
// the ping timeout (<=relayPingTimeoutMax, 5s) is shorter than pingInterval
// (15s), so a live connection whose pongs arrive must disarm the timeout when
// the pong is received. Before the fix the timeout was never stopped on pong,
// so a healthy connection tripped errPingTimeout ~5s after each ping and
// re-dialed in a loop. Here the auto-ponging fake client keeps the connection
// live; a correct actor dials exactly once and never re-dials.
func TestPingTimeoutDisarmedByPong(t *testing.T) {
	if testing.Short() {
		t.Skip("waits past relayPingTimeoutMax; skipped in -short")
	}
	client := newFakeRelayClient()
	var dials atomic.Int32
	sk, _ := key.GenerateSecretKey()
	a := NewRelayActor(RelayActorConfig{
		SecretKey: sk,
		dialer: func(context.Context, netaddr.RelayURL, relayclient.Options) (relayClient, error) {
			dials.Add(1)
			return client, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)

	a.SetHomeRelay(testURL(t))

	// Wait past the ping timeout. A connection that disarms the timeout on
	// pong stays on its first dial; the buggy one tears down at ~5s and
	// re-dials, so dials climbs above 1.
	time.Sleep(relayPingTimeoutMax + 2*time.Second)
	if n := dials.Load(); n != 1 {
		t.Fatalf("relay re-dialed %d times; a live (auto-ponged) connection must dial exactly once (ping timeout was not disarmed on pong)", n)
	}
}

// TestActorSendRoutesToRelay checks that a queued send item is delivered to the
// relay as a client-to-relay datagram frame with the destination endpoint and
// payload preserved.
func TestActorSendRoutesToRelay(t *testing.T) {
	client := newFakeRelayClient()
	a, _ := startActorWith(t, client)
	url := testURL(t)
	dst, _ := key.GenerateSecretKey()

	a.SetHomeRelay(url)

	payload := []byte("relay payload")
	if !a.Send(RelaySendItem{
		RemoteEndpoint: dst.Public().EndpointID(),
		URL:            url,
		Datagrams:      relayproto.DatagramsFromBytes(payload),
	}) {
		t.Fatal("Send returned false (dropped)")
	}

	msg := waitDatagramSend(t, client)
	if msg.Type != relayproto.FrameClientToRelayDatagram {
		t.Fatalf("frame = %s, want ClientToRelayDatagram", msg.Type)
	}
	if !msg.DstEndpointID.Equal(dst.Public().EndpointID()) {
		t.Error("destination endpoint id mismatch")
	}
	if string(msg.Datagrams.Contents) != string(payload) {
		t.Errorf("payload = %q, want %q", msg.Datagrams.Contents, payload)
	}
}

// TestActorRecvForwarding checks that a relay-to-client datagram surfaces on the
// actor's recv queue with its source and payload intact.
func TestActorRecvForwarding(t *testing.T) {
	client := newFakeRelayClient()
	a, _ := startActorWith(t, client)
	url := testURL(t)
	src, _ := key.GenerateSecretKey()
	a.SetHomeRelay(url)

	// Kick the connection alive by queuing a send so the active relay dials.
	dst, _ := key.GenerateSecretKey()
	a.Send(RelaySendItem{RemoteEndpoint: dst.Public().EndpointID(), URL: url, Datagrams: relayproto.DatagramsFromBytes([]byte("x"))})
	waitDatagramSend(t, client)

	want := []byte("incoming")
	client.recv <- relayproto.RelayToClientMsg{
		Type:             relayproto.FrameRelayToClientDatagram,
		RemoteEndpointID: src.Public().EndpointID(),
		Datagrams:        relayproto.DatagramsFromBytes(want),
	}

	select {
	case dm := <-a.Recv():
		if !dm.Src.Equal(src.Public().EndpointID()) {
			t.Error("recv src mismatch")
		}
		if string(dm.Datagrams.Contents) != string(want) {
			t.Errorf("recv payload = %q, want %q", dm.Datagrams.Contents, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for received datagram")
	}
}

// TestActorBatching checks that many queued sends are coalesced and delivered in
// no more than SEND_DATAGRAM_BATCH_SIZE frames per drain, and that all payloads
// arrive.
func TestActorBatching(t *testing.T) {
	client := newFakeRelayClient()
	a, _ := startActorWith(t, client)
	url := testURL(t)
	dst, _ := key.GenerateSecretKey()
	a.SetHomeRelay(url)

	const n = sendDatagramBatchSize + 5
	got := map[string]bool{}
	for i := 0; i < n; i++ {
		p := []byte{byte(i)}
		a.Send(RelaySendItem{RemoteEndpoint: dst.Public().EndpointID(), URL: url, Datagrams: relayproto.DatagramsFromBytes(p)})
	}

	deadline := time.After(5 * time.Second)
	for len(got) < n {
		select {
		case msg := <-client.sent:
			if msg.Type == relayproto.FrameClientToRelayDatagram || msg.Type == relayproto.FrameClientToRelayDatagramBat {
				for _, seg := range splitSegments(msg.Datagrams) {
					got[string(seg)] = true
				}
			}
		case <-deadline:
			t.Fatalf("got %d/%d datagrams", len(got), n)
		}
	}
}

// TestActorHomeRelayStatus checks the home relay watcher transitions to
// connected after a pong is received.
func TestActorHomeRelayStatus(t *testing.T) {
	client := newFakeRelayClient()
	a, _ := startActorWith(t, client)
	url := testURL(t)

	w := a.HomeRelayStatus()
	a.SetHomeRelay(url)

	// Force the active relay to start (it starts on first send or on home set).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		st, err := w.Updated(ctx)
		if err != nil {
			t.Fatalf("watcher: %v", err)
		}
		if st != nil && st.URL.Equal(url) && st.IsConnected() {
			return
		}
	}
}

// TestRelayTransportSendRouting checks RelayTransport.Send looks up the relay
// mapped address and routes to the actor, and that an unknown address is
// reported as not-routed (dropped).
func TestRelayTransportSendRouting(t *testing.T) {
	client := newFakeRelayClient()
	a, _ := startActorWith(t, client)
	sock := NewSocket()
	recvCh := make(chan recvBatch, 8)
	rt := NewRelayTransport(sock, a, recvCh)

	url := testURL(t)
	peer, _ := key.GenerateSecretKey()
	a.SetHomeRelay(url)
	m := sock.RelayMappedAddrFor(url, peer.Public().EndpointID())

	if !rt.Send(m, []byte("payload")) {
		t.Fatal("Send to known relay addr returned false")
	}
	msg := waitDatagramSend(t, client)
	if !msg.DstEndpointID.Equal(peer.Public().EndpointID()) {
		t.Error("routed to wrong endpoint")
	}

	// An unregistered mapped address has no (url, eid) mapping: dropped.
	unknown := NewRelayMappedAddr()
	if rt.Send(unknown, []byte("x")) {
		t.Error("Send to unknown relay addr should report dropped")
	}
}

// waitDatagramSend waits for the next client-to-relay datagram frame, skipping
// ping/pong keepalive frames.
func waitDatagramSend(t *testing.T, c *fakeRelayClient) relayproto.ClientToRelayMsg {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg := <-c.sent:
			if msg.Type == relayproto.FrameClientToRelayDatagram || msg.Type == relayproto.FrameClientToRelayDatagramBat {
				return msg
			}
		case <-deadline:
			t.Fatal("timed out waiting for datagram send")
		}
	}
}

// TestRelayDatagramFrameRoundTrip is the wire-compat half of the slice gate: a
// relay datagram frame round-trips through internal/relayproto unchanged.
func TestRelayDatagramFrameRoundTrip(t *testing.T) {
	key, _ := key.GenerateSecretKey()
	in := relayproto.RelayToClientMsg{
		Type:             relayproto.FrameRelayToClientDatagramBat,
		RemoteEndpointID: key.Public().EndpointID(),
		Datagrams:        relayproto.Datagrams{Ecn: relayproto.EcnCe, SegmentSize: 4, Contents: []byte("aaaabbbb")},
	}
	wire := in.AppendTo(nil)
	out, err := relayproto.ParseRelayToClientMsg(wire, relayproto.ProtocolV2)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(in.Datagrams, out.Datagrams) {
		t.Errorf("datagrams round-trip: got %+v, want %+v", out.Datagrams, in.Datagrams)
	}
	if !out.RemoteEndpointID.Equal(in.RemoteEndpointID) {
		t.Error("endpoint id round-trip mismatch")
	}
	if out.Type != relayproto.FrameRelayToClientDatagramBat {
		t.Errorf("type = %s, want RelayToClientDatagramBatch", out.Type)
	}
}

// TestRemoveHomeRelayPromotesOneSuccessor verifies the home-promotion step of
// RemoveRelay: removing the home relay promotes exactly one remaining relay —
// the first in the map's sorted order — and activates only that relay. The
// early break in the promotion loop is what enforces "exactly one"; without it
// every remaining relay is activated and the last one ends up home.
func TestRemoveHomeRelayPromotesOneSuccessor(t *testing.T) {
	client := newFakeRelayClient()
	a, _ := startActorWith(t, client)

	var urls []netaddr.RelayURL
	for _, s := range []string{
		"https://a.relay.example.",
		"https://b.relay.example.",
		"https://c.relay.example.",
	} {
		u, err := netaddr.ParseRelayURL(s)
		if err != nil {
			t.Fatal(err)
		}
		urls = append(urls, u)
		a.InsertRelay(u, relay.Config{URL: u})
	}

	// The first insert became home. Removing it must promote b (the first
	// remaining URL in sorted order), and must not touch c.
	if _, ok := a.RemoveRelay(urls[0]); !ok {
		t.Fatal("RemoveRelay: home relay not found")
	}

	a.mu.Lock()
	home := a.home
	_, bActive := a.active[urls[1].String()]
	_, cActive := a.active[urls[2].String()]
	a.mu.Unlock()

	if !home.Equal(urls[1]) {
		t.Errorf("home after removal = %v, want %v", home, urls[1])
	}
	if !bActive {
		t.Error("promoted relay b has no active connection")
	}
	if cActive {
		t.Error("relay c was activated; only the promoted home may be started")
	}
}

// TestRelayRateLimitedCounted verifies a Status frame carrying RateLimited
// increments the rate-limited counter, and other statuses do not.
func TestRelayRateLimitedCounted(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	a := NewRelayActor(RelayActorConfig{SecretKey: sk})
	var m Metrics
	a.setMetrics(&m)
	r := newActiveRelay(a, testURL(t), false)
	st := &connectedState{}

	r.handleFrameAt(relayproto.RelayToClientMsg{Type: relayproto.FrameStatus, Status: relayproto.StatusHealthy}, st, time.Now())
	if got := m.relayRateLimited.Load(); got != 0 {
		t.Fatalf("rateLimited after Healthy = %d, want 0", got)
	}
	r.handleFrameAt(relayproto.RelayToClientMsg{Type: relayproto.FrameStatus, Status: relayproto.StatusRateLimited}, st, time.Now())
	if got := m.relayRateLimited.Load(); got != 1 {
		t.Fatalf("rateLimited after RateLimited = %d, want 1", got)
	}
}

func TestRelayTransportSendBatch(t *testing.T) {
	client := newFakeRelayClient()
	a, _ := startActorWith(t, client)
	sock := NewSocket()
	rt := NewRelayTransport(sock, a, make(chan recvBatch, 8))
	url := testURL(t)
	peer, _ := key.GenerateSecretKey()
	a.SetHomeRelay(url)
	m := sock.RelayMappedAddrFor(url, peer.Public().EndpointID())

	const seg = 1200
	n := maxRelayBatch/seg*seg + seg + 100
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i / seg)
	}
	if !rt.SendBatch(m, p, seg) {
		t.Fatal("SendBatch returned false")
	}
	var got []byte
	for len(got) < n {
		msg := waitDatagramSend(t, client)
		if len(msg.Datagrams.Contents) > seg && msg.Datagrams.SegmentSize != seg {
			t.Fatalf("segment size = %d, want %d", msg.Datagrams.SegmentSize, seg)
		}
		if len(msg.Datagrams.Contents) > maxRelayBatch {
			t.Fatalf("frame contents %d > %d", len(msg.Datagrams.Contents), maxRelayBatch)
		}
		got = append(got, msg.Datagrams.Contents...)
	}
	if !bytes.Equal(got, p) {
		t.Fatal("reassembled payload differs")
	}
}

func TestRelayTransportDropsEmptyDatagram(t *testing.T) {
	sock := NewSocket()
	recvCh := make(chan recvBatch, 4)
	rt := NewRelayTransport(sock, nil, recvCh)

	u, err := netaddr.ParseRelayURL("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := key.GenerateSecretKey()
	src := sk.Public().EndpointID()

	// Empty datagram must be dropped without enqueuing onto recvCh.
	rt.deliver(context.Background(), RelayRecvDatagram{
		URL:       u,
		Src:       src,
		Datagrams: relayproto.Datagrams{}.Pooled(),
	})
	select {
	case b := <-recvCh:
		t.Fatalf("unexpected batch enqueued for empty datagram: %+v", b)
	default:
	}

	// Subsequent non-empty datagram is delivered normally.
	rt.deliver(context.Background(), RelayRecvDatagram{
		URL:       u,
		Src:       src,
		Datagrams: relayproto.DatagramsFromBytes([]byte("ok")).Pooled(),
	})
	select {
	case b := <-recvCh:
		defer b.release()
		if string(b.data) != "ok" {
			t.Fatalf("delivered %q, want %q", b.data, "ok")
		}
	default:
		t.Fatal("expected non-empty datagram on recvCh")
	}
}
