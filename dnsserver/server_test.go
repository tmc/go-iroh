package dnsserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"golang.org/x/net/dns/dnsmessage"
)

func TestServerPutGet(t *testing.T) {
	sk, packet := testPacket(t)
	srv := New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	keyLabel := sk.Public().EndpointID().Z32()
	req, err := http.NewRequest(http.MethodPut, ts.URL+"/pkarr/"+keyLabel, bytes.NewReader(packet.RelayPayload()))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	resp, err = ts.Client().Get(ts.URL + "/pkarr/" + keyLabel)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, packet.RelayPayload()) {
		t.Fatalf("GET status/body = %d %x, want 200 %x", resp.StatusCode, got, packet.RelayPayload())
	}
	if got := resp.Header.Get("Content-Type"); got != "application/x-pkarr-signed-packet" {
		t.Fatalf("Content-Type = %q", got)
	}

	snapshot := srv.Snapshot()
	if snapshot["http_puts"] != 1 || snapshot["http_gets"] != 1 {
		t.Fatalf("Snapshot = %+v, want one PUT and GET", snapshot)
	}
}

func TestServerPutRejectsBadPacket(t *testing.T) {
	sk, _ := testPacket(t)
	ts := httptest.NewServer(New())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPut, ts.URL+"/pkarr/"+sk.Public().EndpointID().Z32(), bytes.NewReader([]byte("bad")))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestServerPutRejectsStalePacket(t *testing.T) {
	sk, old := testPacketWithData(t, testSecretKey(t), "old")
	_, newer := testPacketWithData(t, sk, "new")
	srv := New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	keyLabel := sk.Public().EndpointID().Z32()
	putPacket(t, ts, keyLabel, newer, http.StatusNoContent)
	putPacket(t, ts, keyLabel, old, http.StatusConflict)

	resp, err := ts.Client().Get(ts.URL + "/pkarr/" + keyLabel)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newer.RelayPayload()) {
		t.Fatalf("GET body = %x, want newer packet %x", got, newer.RelayPayload())
	}
}

func TestServerPutRejectsExpiredPacket(t *testing.T) {
	sk, packet := testPacket(t)
	srv := New()
	now := time.UnixMicro(int64(packet.TimestampMicros())).Add(packetRetention + time.Microsecond)
	srv.now = func() time.Time { return now }
	ts := httptest.NewServer(srv)
	defer ts.Close()

	keyLabel := sk.Public().EndpointID().Z32()
	putPacket(t, ts, keyLabel, packet, http.StatusConflict)
	if _, ok := srv.get(keyLabel); ok {
		t.Fatal("expired packet was stored")
	}
}

func TestServerEviction(t *testing.T) {
	type op struct {
		name string // "put", "get", or "wait"
		key  int
		d    time.Duration
	}
	put := func(key int) op { return op{name: "put", key: key} }
	get := func(key int) op { return op{name: "get", key: key} }
	wait := func(d time.Duration) op { return op{name: "wait", d: d} }
	tests := []struct {
		name string
		ops  []op
		want []int // stored keys, least recently stored first
	}{
		{"under cap", []op{put(0), put(1)}, []int{0, 1}},
		{"oldest evicted first", []op{put(0), put(1), put(2), put(3), put(4)}, []int{2, 3, 4}},
		{"replace refreshes position", []op{put(0), put(1), put(2), put(0), put(3)}, []int{2, 0, 3}},
		{"replace at cap evicts nothing", []op{put(0), put(1), put(2), put(1)}, []int{0, 2, 1}},
		{"expired dropped on admit", []op{put(0), put(1), wait(30 * time.Minute), put(2), wait(30 * time.Minute), put(3)}, []int{2, 3}},
		{"expired dropped before live", []op{put(0), wait(30 * time.Minute), put(1), put(2), wait(30 * time.Minute), put(3)}, []int{1, 2, 3}},
		{"get drops expired", []op{put(0), put(1), wait(time.Hour), get(1)}, []int{0}},
		{"get keeps live", []op{put(0), put(1), wait(time.Hour - time.Second), get(0)}, []int{0, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(1, 0)
			srv := New()
			srv.maxPackets = 3
			srv.retention = time.Hour
			srv.now = func() time.Time { return now }
			var keys []string
			var packets []*dns.SignedPacket
			for i := range 5 {
				var seed [32]byte
				seed[0] = byte(i + 1)
				sk, packet := testPacketWithData(t, key.NewSecretKey(seed), "hello")
				keys = append(keys, sk.Public().EndpointID().Z32())
				packets = append(packets, packet)
			}
			for _, op := range tt.ops {
				switch op.name {
				case "put":
					if !srv.put(keys[op.key], packets[op.key].RelayPayload(), packets[op.key]) {
						t.Fatalf("put(%d) rejected", op.key)
					}
				case "get":
					srv.get(keys[op.key])
				case "wait":
					now = now.Add(op.d)
				}
			}
			var got []int
			for p := srv.order.next; p != &srv.order; p = p.next {
				got = append(got, slices.Index(keys, p.keyLabel))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("stored keys = %v, want %v", got, tt.want)
			}
			if len(srv.store) != len(got) {
				t.Errorf("len(store) = %d, want %d", len(srv.store), len(got))
			}
		})
	}
}

// TestServerFloodDisplacesRecords pins the documented global cap: one client
// publishing cap fresh keys displaces records other clients stored earlier,
// and later publishers are still admitted.
func TestServerFloodDisplacesRecords(t *testing.T) {
	srv := New()
	srv.maxPackets = 16
	put := func(t *testing.T, remote string, seed byte, n uint32) string {
		t.Helper()
		var s [32]byte
		s[0] = seed
		binary.BigEndian.PutUint32(s[1:], n)
		sk, packet := testPacketWithData(t, key.NewSecretKey(s), "hello")
		keyLabel := sk.Public().EndpointID().Z32()
		req := httptest.NewRequest(http.MethodPut, "/pkarr/"+keyLabel, bytes.NewReader(packet.RelayPayload()))
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("PUT from %s status = %d, want %d", remote, w.Code, http.StatusNoContent)
		}
		return keyLabel
	}
	before := put(t, "192.0.2.1:4000", 1, 0)
	for n := range uint32(srv.maxPackets) {
		put(t, "198.51.100.7:5000", 2, n)
	}
	after := put(t, "192.0.2.2:4000", 3, 0)
	if _, ok := srv.get(before); ok {
		t.Error("record stored before the flood survived it")
	}
	if _, ok := srv.get(after); !ok {
		t.Error("record stored after the flood was not admitted")
	}
	if len(srv.store) != srv.maxPackets {
		t.Errorf("len(store) = %d, want %d", len(srv.store), srv.maxPackets)
	}
}

// BenchmarkServerPutFull measures admitting a fresh key into a store that is
// already at its cap, so that every put evicts a record.
func BenchmarkServerPutFull(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			now := time.Unix(1, 0)
			srv := New()
			srv.maxPackets = size
			srv.now = func() time.Time { return now }
			_, packet := testPacketWithData(b, testSecretKey(b), "hello")
			payload := packet.RelayPayload()
			keys := make([]string, size+b.N)
			for i := range keys {
				keys[i] = fmt.Sprint("key", i)
			}
			for _, keyLabel := range keys[:size] {
				srv.put(keyLabel, payload, packet)
			}
			b.ResetTimer()
			for _, keyLabel := range keys[size:] {
				now = now.Add(time.Microsecond)
				srv.put(keyLabel, payload, packet)
			}
		})
	}
}

func TestServeDNSPacket(t *testing.T) {
	sk, packet := testPacket(t)
	srv := New()
	srv.storePacket(t, sk, packet)

	msg := packTXTQuery(t, dns.IrohTXTName+"."+sk.Public().EndpointID().Z32()+".example.")
	resp, err := srv.ServeDNSPacket(msg)
	if err != nil {
		t.Fatalf("ServeDNSPacket: %v", err)
	}
	txt := unpackTXTResponse(t, resp)
	if len(txt) != 1 || txt[0] != "user-data=hello" {
		t.Fatalf("TXT = %q, want user-data", txt)
	}
	if got := srv.Snapshot()["dns_queries"]; got != 1 {
		t.Fatalf("dns_queries = %d, want 1", got)
	}
}

func TestServePacketConn(t *testing.T) {
	sk, packet := testPacket(t)
	srv := New()
	srv.storePacket(t, sk, packet)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- srv.ServePacketConn(ctx, pc) }()

	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := packTXTQuery(t, dns.IrohTXTName+"."+sk.Public().EndpointID().Z32()+".example.")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	txt := unpackTXTResponse(t, buf[:n])
	if len(txt) != 1 || txt[0] != "user-data=hello" {
		t.Fatalf("TXT = %q, want user-data", txt)
	}

	cancel()
	_ = pc.Close()
	select {
	case <-errc:
	case <-time.After(2 * time.Second):
		t.Fatal("ServePacketConn did not stop")
	}
}

func testPacket(t *testing.T) (key.SecretKey, *dns.SignedPacket) {
	t.Helper()
	return testPacketWithData(t, testSecretKey(t), "hello")
}

func testSecretKey(t testing.TB) key.SecretKey {
	t.Helper()
	sk, err := key.ParseSecretKey("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia")
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func testPacketWithData(t testing.TB, sk key.SecretKey, data string) (key.SecretKey, *dns.SignedPacket) {
	t.Helper()
	userData, err := dns.NewUserData(data)
	if err != nil {
		t.Fatal(err)
	}
	info := dns.EndpointInfo{ID: sk.Public().EndpointID()}
	info.Data.SetUserData(&userData)
	packet, err := info.ToSignedPacket(sk, 30)
	if err != nil {
		t.Fatal(err)
	}
	return sk, packet
}

func (s *Server) storePacket(t *testing.T, sk key.SecretKey, packet *dns.SignedPacket) {
	t.Helper()
	keyLabel := sk.Public().EndpointID().Z32()
	if _, err := packetFromRelayPayload(keyLabel, packet.RelayPayload()); err != nil {
		t.Fatal(err)
	}
	if !s.put(keyLabel, packet.RelayPayload(), packet) {
		t.Fatal("storePacket rejected packet")
	}
}

func putPacket(t *testing.T, ts *httptest.Server, keyLabel string, packet *dns.SignedPacket, wantStatus int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, ts.URL+"/pkarr/"+keyLabel, bytes.NewReader(packet.RelayPayload()))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("PUT status = %d, want %d", resp.StatusCode, wantStatus)
	}
}

func packTXTQuery(t *testing.T, name string) []byte {
	t.Helper()
	dnsName, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsName,
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func unpackTXTResponse(t *testing.T, msg []byte) []string {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Response {
		t.Fatal("response bit not set")
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	var out []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Type != dnsmessage.TypeTXT {
			if err := p.SkipAnswer(); err != nil {
				t.Fatal(err)
			}
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, txt.TXT...)
	}
	return out
}
