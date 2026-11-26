package relayproto

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

// clientKey is SecretKey::from_bytes(&[42u8; 32]) from the Rust snapshot tests.
func clientKey(t *testing.T) key.EndpointID {
	t.Helper()
	var seed [32]byte
	for i := range seed {
		seed[i] = 42
	}
	pub := key.NewSecretKey(seed).Public()
	// The Rust snapshot's public key for [42;32].
	const wantHex = "197f6b23e16c8532c6abc838facd5ea789be0c76b29203340 39bfa8b3d368d61"
	want := strings.ReplaceAll(wantHex, " ", "")
	if pub.String() != want {
		t.Fatalf("client public key = %s, want %s", pub.String(), want)
	}
	return pub.EndpointID()
}

func hexClean(s string) []byte {
	var b strings.Builder
	for _, r := range s {
		if r != ' ' && r != '\n' && r != '\t' {
			b.WriteRune(r)
		}
	}
	out, err := hex.DecodeString(b.String())
	if err != nil {
		panic(err)
	}
	return out
}

// TestServerClientFramesSnapshot mirrors test_server_client_frames_snapshot:
// exact wire bytes for relay-to-client frames.
func TestServerClientFramesSnapshot(t *testing.T) {
	key := clientKey(t)
	cases := []struct {
		name string
		msg  RelayToClientMsg
		hex  string
	}{
		{"Health", RelayToClientMsg{Type: FrameHealth, Health: "Hello? Yes this is dog."},
			"0b 48 65 6c 6c 6f 3f 20 59 65 73 20 74 68 69 73 20 69 73 20 64 6f 67 2e"},
		{"EndpointGone", RelayToClientMsg{Type: FrameEndpointGone, EndpointGone: key},
			"08 197f6b23e16c8532c6abc838facd5ea789be0c76b2920334 039bfa8b3d368d61"},
		{"Ping", RelayToClientMsg{Type: FramePing, Ping: ping42()},
			"09 2a 2a 2a 2a 2a 2a 2a 2a"},
		{"Pong", RelayToClientMsg{Type: FramePong, Ping: ping42()},
			"0a 2a 2a 2a 2a 2a 2a 2a 2a"},
		{"DatagramBatch", RelayToClientMsg{
			Type:             FrameRelayToClientDatagramBat,
			RemoteEndpointID: key,
			Datagrams:        Datagrams{Ecn: EcnCe, SegmentSize: 6, Contents: []byte("Hello World!")},
		},
			"07 197f6b23e16c8532c6abc838facd5ea789be0c76b2920334 039bfa8b3d368d61 03 0006 48656c6c6f20576f726c6421"},
		{"DatagramSingle", RelayToClientMsg{
			Type:             FrameRelayToClientDatagram,
			RemoteEndpointID: key,
			Datagrams:        Datagrams{Ecn: EcnCe, Contents: []byte("Hello World!")},
		},
			"06 197f6b23e16c8532c6abc838facd5ea789be0c76b2920334 039bfa8b3d368d61 03 48656c6c6f20576f726c6421"},
		{"Restarting", RelayToClientMsg{
			Type:        FrameRestarting,
			ReconnectIn: 10 * time.Millisecond,
			TryFor:      20 * time.Millisecond,
		},
			"0c 00 00 00 0a 00 00 00 14"},
		{"Status", RelayToClientMsg{Type: FrameStatus, Status: StatusSameEndpointIDConnected},
			"0d 01"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.msg.AppendTo(nil)
			want := hexClean(c.hex)
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Errorf("AppendTo = %x, want %x", got, want)
			}
			if c.msg.EncodedLen() != len(got) {
				t.Errorf("EncodedLen = %d, actual = %d", c.msg.EncodedLen(), len(got))
			}
		})
	}
}

// TestClientServerFramesSnapshot mirrors test_client_server_frames_snapshot.
func TestClientServerFramesSnapshot(t *testing.T) {
	key := clientKey(t)
	cases := []struct {
		name string
		msg  ClientToRelayMsg
		hex  string
	}{
		{"Ping", ClientToRelayMsg{Type: FramePing, Ping: ping42()},
			"09 2a 2a 2a 2a 2a 2a 2a 2a"},
		{"Pong", ClientToRelayMsg{Type: FramePong, Ping: ping42()},
			"0a 2a 2a 2a 2a 2a 2a 2a 2a"},
		{"DatagramBatch", ClientToRelayMsg{
			Type:          FrameClientToRelayDatagramBat,
			DstEndpointID: key,
			Datagrams:     Datagrams{Ecn: EcnCe, SegmentSize: 6, Contents: []byte("Hello World!")},
		},
			"05 197f6b23e16c8532c6abc838facd5ea789be0c76b2920334 039bfa8b3d368d61 03 0006 48656c6c6f20576f726c6421"},
		{"DatagramSingle", ClientToRelayMsg{
			Type:          FrameClientToRelayDatagram,
			DstEndpointID: key,
			Datagrams:     Datagrams{Ecn: EcnCe, Contents: []byte("Hello World!")},
		},
			"04 197f6b23e16c8532c6abc838facd5ea789be0c76b2920334 039bfa8b3d368d61 03 48656c6c6f20576f726c6421"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.msg.AppendTo(nil)
			want := hexClean(c.hex)
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Errorf("AppendTo = %x, want %x", got, want)
			}
			if c.msg.EncodedLen() != len(got) {
				t.Errorf("EncodedLen = %d, actual = %d", c.msg.EncodedLen(), len(got))
			}
		})
	}
}

func TestRelayToClientRoundTrip(t *testing.T) {
	key := clientKey(t)
	msgs := []RelayToClientMsg{
		{Type: FrameRelayToClientDatagram, RemoteEndpointID: key, Datagrams: Datagrams{Ecn: EcnEct0, Contents: []byte("data")}},
		{Type: FrameRelayToClientDatagramBat, RemoteEndpointID: key, Datagrams: Datagrams{Ecn: EcnCe, SegmentSize: 2, Contents: []byte("data")}},
		{Type: FrameEndpointGone, EndpointGone: key},
		{Type: FramePing, Ping: ping42()},
		{Type: FrameStatus, Status: StatusSameEndpointIDConnected},
		{Type: FrameRestarting, ReconnectIn: 5 * time.Millisecond, TryFor: 9 * time.Millisecond},
	}
	for _, m := range msgs {
		encoded := m.AppendTo(nil)
		got, err := ParseRelayToClientMsg(encoded, ProtocolV2)
		if err != nil {
			t.Fatalf("%s: parse: %v", m.frameType(), err)
		}
		if got.frameType() != m.frameType() {
			t.Errorf("frame type %s != %s", got.frameType(), m.frameType())
		}
	}
}

func TestClientToRelayRoundTrip(t *testing.T) {
	key := clientKey(t)
	msgs := []ClientToRelayMsg{
		{Type: FrameClientToRelayDatagram, DstEndpointID: key, Datagrams: Datagrams{Contents: []byte("x")}},
		{Type: FrameClientToRelayDatagramBat, DstEndpointID: key, Datagrams: Datagrams{SegmentSize: 1, Contents: []byte("xy")}},
		{Type: FramePing, Ping: ping42()},
		{Type: FramePong, Ping: ping42()},
	}
	for _, m := range msgs {
		encoded := m.AppendTo(nil)
		got, err := ParseClientToRelayMsg(encoded)
		if err != nil {
			t.Fatalf("%s: parse: %v", m.frameType(), err)
		}
		if got.frameType() != m.frameType() {
			t.Errorf("frame type %s != %s", got.frameType(), m.frameType())
		}
	}
}

func TestHealthRejectedInV2(t *testing.T) {
	m := RelayToClientMsg{Type: FrameHealth, Health: "test"}
	encoded := m.AppendTo(nil)
	if _, err := ParseRelayToClientMsg(encoded, ProtocolV2); err != ErrFrameNotAllowedInVersion {
		t.Errorf("err = %v, want ErrFrameNotAllowedInVersion", err)
	}
}

func TestStatusRejectedInV1(t *testing.T) {
	m := RelayToClientMsg{Type: FrameStatus, Status: StatusSameEndpointIDConnected}
	encoded := m.AppendTo(nil)
	if _, err := ParseRelayToClientMsg(encoded, ProtocolV1); err != ErrFrameNotAllowedInVersion {
		t.Errorf("err = %v, want ErrFrameNotAllowedInVersion", err)
	}
}

func TestVarintRoundTrip(t *testing.T) {
	cases := []uint64{0, 1, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30}
	for _, v := range cases {
		enc := appendVarint(nil, v)
		if len(enc) != varintLen(v) {
			t.Errorf("varintLen(%d) = %d, encoded %d bytes", v, varintLen(v), len(enc))
		}
		got, rest, err := readVarint(enc)
		if err != nil || got != v || len(rest) != 0 {
			t.Errorf("readVarint(%x) = %d, %v; want %d", enc, got, err, v)
		}
	}
}

func TestRelayFrameTypeWireValues(t *testing.T) {
	cases := []struct {
		name string
		ft   FrameType
		want byte
	}{
		{"ServerChallenge", FrameServerChallenge, 0},
		{"ClientAuth", FrameClientAuth, 1},
		{"ServerConfirmsAuth", FrameServerConfirmsAuth, 2},
		{"ServerDeniesAuth", FrameServerDeniesAuth, 3},
		{"ClientToRelayDatagram", FrameClientToRelayDatagram, 4},
		{"ClientToRelayDatagramBatch", FrameClientToRelayDatagramBat, 5},
		{"RelayToClientDatagram", FrameRelayToClientDatagram, 6},
		{"RelayToClientDatagramBatch", FrameRelayToClientDatagramBat, 7},
		{"EndpointGone", FrameEndpointGone, 8},
		{"Ping", FramePing, 9},
		{"Pong", FramePong, 10},
		{"Health", FrameHealth, 11},
		{"Restarting", FrameRestarting, 12},
		{"Status", FrameStatus, 13},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := writeFrameType(nil, c.ft)
			if len(got) != 1 || got[0] != c.want {
				t.Fatalf("writeFrameType(%s) = %x, want %02x", c.ft, got, c.want)
			}
			ft, rest, err := readFrameType(got)
			if err != nil {
				t.Fatalf("readFrameType: %v", err)
			}
			if ft != c.ft || len(rest) != 0 {
				t.Fatalf("readFrameType(%02x) = %s, %x, want %s, empty", c.want, ft, rest, c.ft)
			}
		})
	}
}

func TestRelayEcnWireValues(t *testing.T) {
	cases := []struct {
		name string
		wire byte
		want EcnCodepoint
		ok   bool
	}{
		{"NotECT", 0, 0, false},
		{"ECT1", 1, EcnEct1, true},
		{"ECT0", 2, EcnEct0, true},
		{"CE", 3, EcnCe, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ecnFromBits(c.wire)
			if got != c.want || ok != c.ok {
				t.Fatalf("ecnFromBits(%d) = %d, %v, want %d, %v", c.wire, got, ok, c.want, c.ok)
			}
			d := Datagrams{Ecn: c.want, Contents: []byte("x")}
			if got := d.appendTo(nil)[0]; got != byte(c.want) {
				t.Fatalf("Datagrams.appendTo ECN byte = %d, want %d", got, c.want)
			}
		})
	}
}

func ping42() [8]byte {
	var p [8]byte
	for i := range p {
		p[i] = 42
	}
	return p
}

func TestParseClientToRelayFullFrameLengthLimit(t *testing.T) {
	// Total frame length (including frame-type varint) must not exceed MaxPacketSize.
	buf := make([]byte, MaxPacketSize+1)
	buf[0] = byte(FrameClientToRelayDatagram)
	if _, err := ParseClientToRelayMsg(buf); err == nil {
		t.Fatal("ParseClientToRelayMsg accepted frame exceeding MaxPacketSize")
	}
}
