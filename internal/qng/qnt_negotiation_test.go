package quic

import (
	"context"
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// TestQNTNegotiated checks the negotiation gate: n0 NAT traversal is negotiated
// only when both peers advertise the n0_nat_traversal transport parameter with a
// non-zero address limit.
func TestQNTNegotiated(t *testing.T) {
	const local = uint8(8)
	const peerLimit = uint8(16)

	tests := []struct {
		name    string
		local   *uint8
		peer    *uint8
		peerNil bool
		want    bool
	}{
		{name: "both", local: ptrTo(local), peer: ptrTo(peerLimit), want: true},
		{name: "local only", local: ptrTo(local), want: false},
		{name: "peer only", peer: ptrTo(peerLimit), want: false},
		{name: "neither", want: false},
		{name: "local zero", local: ptrTo(uint8(0)), peer: ptrTo(peerLimit), want: false},
		{name: "peer zero", local: ptrTo(local), peer: ptrTo(uint8(0)), want: false},
		{name: "peer params absent", local: ptrTo(local), peerNil: true, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{MaxRemoteNATTraversalAddresses: tc.local}
			var peer *wire.TransportParameters
			if !tc.peerNil {
				peer = &wire.TransportParameters{MaxRemoteNATTraversalAddresses: tc.peer}
			}
			c := &Conn{config: cfg}
			c.peerParams.Store(peer)
			if got := c.qntNegotiated(); got != tc.want {
				t.Fatalf("qntNegotiated() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMaxRemoteNATTraversalAddressesParam(t *testing.T) {
	if got := maxRemoteNATTraversalAddressesParam(nil); got != nil {
		t.Fatalf("nil config = %v, want nil", *got)
	}
	zero := uint8(0)
	if got := maxRemoteNATTraversalAddressesParam(&zero); got != nil {
		t.Fatalf("zero config = %v, want nil", *got)
	}
	limit := uint8(8)
	got := maxRemoteNATTraversalAddressesParam(&limit)
	if got == nil || *got != limit {
		t.Fatalf("limit config = %v, want %d", got, limit)
	}
	limit = 9
	if *got != 8 {
		t.Fatalf("returned pointer aliases config value, got %d after mutation", *got)
	}
}

func TestQNTConfigClone(t *testing.T) {
	limit := uint8(8)
	cfg := populateConfig(&Config{MaxRemoteNATTraversalAddresses: &limit})
	if cfg.MaxRemoteNATTraversalAddresses == nil {
		t.Fatal("MaxRemoteNATTraversalAddresses lost in populateConfig")
	}
	if *cfg.MaxRemoteNATTraversalAddresses != limit {
		t.Fatalf("MaxRemoteNATTraversalAddresses = %d, want %d", *cfg.MaxRemoteNATTraversalAddresses, limit)
	}
}

func TestQNTApplyTransportParametersAdmitsNegotiatedFrames(t *testing.T) {
	const limit = uint8(8)
	c := newQNTTransportParameterConn(limit, limit)
	c.applyTransportParameters()
	if !c.qntNegotiated() {
		t.Fatal("qntNegotiated() = false, want true")
	}

	added := netip.MustParseAddrPort("198.51.100.1:1001")
	reachOut := netip.MustParseAddrPort("198.51.100.2:1002")
	frames := []wire.Frame{
		&wire.AddAddressFrame{SeqNo: 1, Addr: added.Addr(), Port: added.Port()},
		&wire.ReachOutFrame{Round: 1, Addr: reachOut.Addr(), Port: reachOut.Port()},
		&wire.RemoveAddressFrame{SeqNo: 1},
	}
	for _, f := range frames {
		parsed := parseQNTFrame(t, c, f)
		switch frame := parsed.(type) {
		case *wire.AddAddressFrame:
			if err := c.handleAddAddressFrame(frame); err != nil {
				t.Fatalf("handle ADD_ADDRESS: %v", err)
			}
		case *wire.ReachOutFrame:
			if err := c.handleReachOutFrame(frame); err != nil {
				t.Fatalf("handle REACH_OUT: %v", err)
			}
		case *wire.RemoveAddressFrame:
			if err := c.handleRemoveAddressFrame(frame); err != nil {
				t.Fatalf("handle REMOVE_ADDRESS: %v", err)
			}
		default:
			t.Fatalf("parsed QNT frame = %T", parsed)
		}
	}

	if addrs, err := c.NATTraversalAddresses(); err != nil || len(addrs) != 0 {
		t.Fatalf("NATTraversalAddresses after ADD/REMOVE = %v, %v, want none, nil", addrs, err)
	}
	if probes := c.qntPendingProbeAddresses(); len(probes) != 1 || probes[0] != reachOut {
		t.Fatalf("pending probes after REACH_OUT = %v, want [%v]", probes, reachOut)
	}
}

func TestQNTApplyTransportParametersRejectsUnnegotiatedFrames(t *testing.T) {
	const local = uint8(8)
	const peer = uint8(0)
	c := newQNTTransportParameterConn(local, peer)
	c.applyTransportParameters()
	if c.qntNegotiated() {
		t.Fatal("qntNegotiated() = true, want false")
	}

	for _, ft := range []wire.FrameType{
		wire.FrameTypeAddIPv4Address,
		wire.FrameTypeAddIPv6Address,
		wire.FrameTypeReachOutAtIPv4,
		wire.FrameTypeReachOutAtIPv6,
		wire.FrameTypeRemoveAddress,
	} {
		b := quicvarint.Append(nil, uint64(ft))
		if _, _, err := c.frameParser.ParseType(b, protocol.Encryption1RTT); err == nil {
			t.Fatalf("ParseType(%#x) admitted QNT frame without negotiation", uint64(ft))
		}
	}
}

func parseQNTFrame(t *testing.T, c *Conn, f wire.Frame) wire.Frame {
	t.Helper()
	b, err := f.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("append %T: %v", f, err)
	}
	ft, n, err := c.frameParser.ParseType(b, protocol.Encryption1RTT)
	if err != nil {
		t.Fatalf("ParseType(%T): %v", f, err)
	}
	parsed, _, err := c.frameParser.ParseLessCommonFrame(ft, b[n:], protocol.Version1)
	if err != nil {
		t.Fatalf("ParseLessCommonFrame(%T): %v", f, err)
	}
	return parsed
}

func newQNTTransportParameterConn(local, peer uint8) *Conn {
	cfg := populateConfig(&Config{MaxRemoteNATTraversalAddresses: &local})
	c := &Conn{
		config:   cfg,
		rttStats: utils.NewRTTStats(),
		frameParser: *wire.NewFrameParser(
			cfg.EnableDatagrams,
			cfg.EnableStreamResetPartialDelivery,
			false,
			false,
		),
	}
	c.peerParams.Store(&wire.TransportParameters{MaxRemoteNATTraversalAddresses: &peer})
	c.connFlowController = newConnectionFlowController(
		protocol.ByteCount(cfg.InitialConnectionReceiveWindow),
		protocol.ByteCount(cfg.MaxConnectionReceiveWindow),
		nil,
		c.rttStats,
		nil,
	)
	c.streamsMap = newStreamsMap(
		context.Background(),
		c,
		func(wire.Frame) {},
		c.newFlowController,
		uint64(cfg.MaxIncomingStreams),
		uint64(cfg.MaxIncomingUniStreams),
		protocol.PerspectiveClient,
	)
	c.connIDGenerator = newConnIDGenerator(
		stubConnRunner{},
		protocol.ConnectionID{},
		nil,
		nil,
		connRunnerCallbacks{},
		func(wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 0},
	)
	return c
}

func ptrTo[T any](v T) *T {
	return &v
}
