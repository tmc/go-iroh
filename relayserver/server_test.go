package relayserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/internal/relayclient"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/metrics"
	"github.com/tmc/go-iroh/netaddr"
)

func TestRelayServerForwardsDatagramAndPong(t *testing.T) {
	srv := New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	u, err := netaddr.ParseRelayURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sk1, _ := key.GenerateSecretKey()
	c1, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: sk1})
	if err != nil {
		t.Fatalf("connect c1: %v", err)
	}
	defer c1.Close()

	sk2, _ := key.GenerateSecretKey()
	c2, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: sk2})
	if err != nil {
		t.Fatalf("connect c2: %v", err)
	}
	defer c2.Close()

	var ping [8]byte
	copy(ping[:], "pingpong")
	if err := c1.Send(ctx, relayproto.ClientToRelayMsg{Type: relayproto.FramePing, Ping: ping}); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	pong, err := c1.Recv(ctx)
	if err != nil {
		t.Fatalf("recv pong: %v", err)
	}
	if pong.Type != relayproto.FramePong || pong.Ping != ping {
		t.Fatalf("pong = %+v, want ping echo", pong)
	}

	payload := []byte("hello relay")
	if err := c1.Send(ctx, relayproto.ClientToRelayMsg{
		Type:          relayproto.FrameClientToRelayDatagram,
		DstEndpointID: sk2.Public().EndpointID(),
		Datagrams:     relayproto.DatagramsFromBytes(payload),
	}); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	got, err := c2.Recv(ctx)
	if err != nil {
		t.Fatalf("recv forwarded datagram: %v", err)
	}
	if got.Type != relayproto.FrameRelayToClientDatagram {
		t.Fatalf("type = %v, want datagram", got.Type)
	}
	if !got.RemoteEndpointID.Equal(sk1.Public().EndpointID()) {
		t.Fatalf("remote id = %s, want %s", got.RemoteEndpointID, sk1.Public().EndpointID())
	}
	if string(got.Datagrams.Contents) != string(payload) {
		t.Fatalf("datagram = %q, want %q", got.Datagrams.Contents, payload)
	}

	// The forwarding counter is incremented after the datagram is queued, so
	// the reader above can observe delivery before the server has counted it.
	// Wait for the counter rather than assume the two are ordered.
	snapshot := waitForSnapshot(t, srv, func(s metrics.Snapshot) bool {
		return s["clients_accepted"] == 2 && s["pings"] == 1 && s["datagrams_forwarded"] == 1
	})
	if snapshot == nil {
		t.Fatalf("Snapshot = %+v, want clients=2 pings=1 datagrams=1", srv.Snapshot())
	}
}

// waitForSnapshot polls srv's counters until want is satisfied, returning the
// matching snapshot or nil if it never settles.
func waitForSnapshot(t *testing.T, srv *Server, want func(metrics.Snapshot) bool) metrics.Snapshot {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if s := srv.Snapshot(); want(s) {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	return nil
}

func TestRelayServerAcceptsTLSKeyMaterialAuth(t *testing.T) {
	srv := New()
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()

	u, err := netaddr.ParseRelayURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certPool := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	tlsConfig := &tls.Config{RootCAs: certPool}
	sk, _ := key.GenerateSecretKey()
	c, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: sk, TLSConfig: tlsConfig})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	var ping [8]byte
	copy(ping[:], "fastauth")
	if err := c.Send(ctx, relayproto.ClientToRelayMsg{Type: relayproto.FramePing, Ping: ping}); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	pong, err := c.Recv(ctx)
	if err != nil {
		t.Fatalf("recv pong: %v", err)
	}
	if pong.Type != relayproto.FramePong || pong.Ping != ping {
		t.Fatalf("pong = %+v, want ping echo", pong)
	}
	if got := srv.Snapshot()["clients_accepted"]; got != 1 {
		t.Fatalf("clients_accepted = %d, want 1", got)
	}
}

func TestRelayServerTimesOutAuthentication(t *testing.T) {
	srv := New()
	srv.establishTimeout = 20 * time.Millisecond
	ts := httptest.NewServer(srv)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + relayPath
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		Subprotocols: relayproto.SupportedProtocolVersions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("unauthenticated connection remained open")
	} else if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connection outlived authentication timeout: %v", err)
	}
}

func TestRelayServerLimitsPendingAuthentication(t *testing.T) {
	srv := New()
	srv.pendingAuth = make(chan struct{}, 1)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + relayPath
	options := &websocket.DialOptions{Subprotocols: relayproto.SupportedProtocolVersions()}
	first, _, err := websocket.Dial(ctx, url, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.Read(ctx); err != nil {
		t.Fatalf("read first challenge: %v", err)
	}

	second, resp, err := websocket.Dial(ctx, url, options)
	if second != nil {
		second.CloseNow()
	}
	if err == nil {
		t.Fatal("second unauthenticated connection was accepted")
	}
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		if resp == nil {
			t.Fatal("second connection has no HTTP response")
		}
		resp.Body.Close()
		t.Fatalf("second connection status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	resp.Body.Close()

	first.CloseNow()
	deadline := time.Now().Add(time.Second)
	for len(srv.pendingAuth) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(srv.pendingAuth); got != 0 {
		t.Fatalf("pending authentication count = %d, want 0", got)
	}
	third, _, err := websocket.Dial(ctx, url, options)
	if err != nil {
		t.Fatalf("connect after slot release: %v", err)
	}
	third.CloseNow()
}

func TestRelayServerReplacesSameEndpointSession(t *testing.T) {
	srv := New()
	ts := httptest.NewServer(srv)
	defer ts.Close()
	u, err := netaddr.ParseRelayURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	secret, _ := key.GenerateSecretKey()
	first, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: secret})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: secret})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	status, err := first.Recv(ctx)
	if err != nil {
		t.Fatalf("receive replacement status: %v", err)
	}
	if status.Type != relayproto.FrameStatus || status.Status != relayproto.StatusSameEndpointIDConnected {
		t.Fatalf("replacement status = %+v", status)
	}
	if _, err := first.Recv(ctx); err == nil {
		t.Fatal("replaced connection remained open")
	}

	var ping [8]byte
	copy(ping[:], "new conn")
	if err := second.Send(ctx, relayproto.ClientToRelayMsg{Type: relayproto.FramePing, Ping: ping}); err != nil {
		t.Fatalf("send on replacement connection: %v", err)
	}
	pong, err := second.Recv(ctx)
	if err != nil {
		t.Fatalf("receive on replacement connection: %v", err)
	}
	if pong.Type != relayproto.FramePong || pong.Ping != ping {
		t.Fatalf("pong = %+v, want ping echo", pong)
	}
}

func TestRelayServerOutlivesHTTPDeadlines(t *testing.T) {
	srv := New()
	ts := httptest.NewUnstartedServer(srv)
	ts.Config.ReadTimeout = 20 * time.Millisecond
	ts.Config.WriteTimeout = 20 * time.Millisecond
	ts.Start()
	defer ts.Close()

	u, err := netaddr.ParseRelayURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sk, _ := key.GenerateSecretKey()
	conn, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: sk})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)
	var ping [8]byte
	copy(ping[:], "deadline")
	if err := conn.Send(ctx, relayproto.ClientToRelayMsg{Type: relayproto.FramePing, Ping: ping}); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	msg, err := conn.Recv(ctx)
	if err != nil {
		t.Fatalf("receive pong: %v", err)
	}
	if msg.Type != relayproto.FramePong || msg.Ping != ping {
		t.Fatalf("pong = %+v, want ping echo", msg)
	}
}

func TestSessionQueueByteLimit(t *testing.T) {
	msg := relayproto.RelayToClientMsg{Type: relayproto.FrameStatus, Status: relayproto.StatusHealthy}
	n := int64(len(msg.AppendTo(nil)))
	sess := &session{
		send:           make(chan *[]byte, 2),
		maxQueuedBytes: n,
	}
	if !sess.enqueue(msg) {
		t.Fatal("first message was dropped")
	}
	if sess.enqueue(msg) {
		t.Fatal("message exceeding byte limit was queued")
	}
	if got := sess.queuedBytes.Load(); got != n {
		t.Fatalf("queued bytes = %d, want %d", got, n)
	}
	if got := len(sess.send); got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
}

func TestByteLimiterHonorsContext(t *testing.T) {
	limiter := newByteLimiter(1, 1)
	if err := limiter.wait(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.wait(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want %v", err, context.Canceled)
	}
}

func TestPingProbeReturns200(t *testing.T) {
	srv := New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /ping = %d, want %d (Rust net-report probes require it)", resp.StatusCode, http.StatusOK)
	}
}

func TestUnroutableDatagramsAreCounted(t *testing.T) {
	srv := New()
	sk1, _ := key.GenerateSecretKey()
	sk2, _ := key.GenerateSecretKey()
	src := &session{id: sk1.Public().EndpointID()}

	// sk2 never connected, so there is no session to route to.
	srv.handleClientMsg(src, relayproto.ClientToRelayMsg{
		Type:          relayproto.FrameClientToRelayDatagram,
		DstEndpointID: sk2.Public().EndpointID(),
		Datagrams:     relayproto.DatagramsFromBytes([]byte("nobody home")),
	})
	snapshot := srv.Snapshot()
	if snapshot["datagrams_dropped"] != 1 || snapshot["datagrams_forwarded"] != 0 {
		t.Fatalf("Snapshot = %+v, want dropped=1 forwarded=0", snapshot)
	}
}

func TestDroppedDatagramsAreCounted(t *testing.T) {
	srv := New()
	sk1, _ := key.GenerateSecretKey()
	sk2, _ := key.GenerateSecretKey()
	src := &session{id: sk1.Public().EndpointID()}
	dst := &session{
		id:   sk2.Public().EndpointID(),
		send: make(chan *[]byte), // unbuffered and never drained: enqueue always fails
	}
	srv.register(dst)

	srv.handleClientMsg(src, relayproto.ClientToRelayMsg{
		Type:          relayproto.FrameClientToRelayDatagram,
		DstEndpointID: dst.id,
		Datagrams:     relayproto.DatagramsFromBytes([]byte("drop me")),
	})
	snapshot := srv.Snapshot()
	if snapshot["datagrams_dropped"] != 1 || snapshot["datagrams_forwarded"] != 0 {
		t.Fatalf("Snapshot = %+v, want dropped=1 forwarded=0", snapshot)
	}
}

func TestDepartureNoticeReachesOnlyPeersSentTo(t *testing.T) {
	newSession := func(id key.EndpointID) *session {
		return &session{id: id, send: make(chan *[]byte, 4), maxQueuedBytes: 1 << 20}
	}
	secret, _ := key.GenerateSecretKey()
	sentToKey, _ := key.GenerateSecretKey()
	quietKey, _ := key.GenerateSecretKey()

	srv := New()
	leaving := newSession(secret.Public().EndpointID())
	sentTo := newSession(sentToKey.Public().EndpointID())
	quiet := newSession(quietKey.Public().EndpointID())
	srv.register(leaving)
	srv.register(sentTo)
	srv.register(quiet)

	srv.handleClientMsg(leaving, relayproto.ClientToRelayMsg{
		Type:          relayproto.FrameClientToRelayDatagram,
		DstEndpointID: sentTo.id,
		Datagrams:     relayproto.DatagramsFromBytes([]byte("hello")),
	})
	<-sentTo.send // drain the forwarded datagram
	srv.unregister(leaving)

	tests := []struct {
		name string
		sess *session
		want bool
	}{
		{"peer sent to", sentTo, true},
		{"peer never sent to", quiet, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			select {
			case b := <-tt.sess.send:
				msg, err := relayproto.ParseRelayToClientMsg(*b, relayproto.ProtocolV2)
				if err != nil {
					t.Fatalf("parse queued frame: %v", err)
				}
				if !tt.want {
					t.Fatalf("queued %v for %s, want no departure notice", msg.Type, leaving.id)
				}
				if msg.Type != relayproto.FrameEndpointGone || !msg.EndpointGone.Equal(leaving.id) {
					t.Fatalf("queued %+v, want endpoint gone for %s", msg, leaving.id)
				}
			default:
				if tt.want {
					t.Fatalf("no departure notice for %s queued", leaving.id)
				}
			}
		})
	}
}

func TestSentToTableIsBounded(t *testing.T) {
	sess := &session{}
	var id key.EndpointID
	for range maxSentTo + 1 {
		secret, _ := key.GenerateSecretKey()
		id = secret.Public().EndpointID()
		sess.noteSentTo(id)
	}
	if got := len(sess.sentTo); got != 1 {
		t.Fatalf("table size = %d, want 1 (cleared at %d)", got, maxSentTo)
	}
	if !sess.sentTo[id] {
		t.Fatalf("destination recorded after the reset is missing")
	}
}
