package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

type dummyConnIDGenerator struct{}

func (d dummyConnIDGenerator) GenerateConnectionID() (protocol.ConnectionID, error) {
	return protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}), nil
}

func (d dummyConnIDGenerator) ConnectionIDLen() int {
	return 8
}

// TestAdvertiseAcceptConsistency checks that every frame type implied by our
// advertised transport parameters is accepted by the connection's frame parser.
// For example:
// - Negotiating multipath implies accepting the full multipath frame set.
// - Negotiating address discovery implies accepting OBSERVED_ADDRESS frames.
// - Negotiating NAT traversal implies accepting ADD_ADDRESS, REACH_OUT, and REMOVE_ADDRESS frames.
func TestAdvertiseAcceptConsistency(t *testing.T) {
	maxAddrs := uint8(4)
	tests := []struct {
		name          string
		perspective   protocol.Perspective
		setupConfig   func(*Config)
		peerParams    func() *wire.TransportParameters
		impliedFrames []wire.FrameType
	}{
		{
			name:        "Multipath TP implies multipath frame set",
			perspective: protocol.PerspectiveServer,
			setupConfig: func(c *Config) {
				maxPathID := uint32(4)
				c.InitialMaxPathID = &maxPathID
			},
			peerParams: func() *wire.TransportParameters {
				pid := protocol.PathID(4)
				return &wire.TransportParameters{
					InitialMaxPathID: &pid,
				}
			},
			impliedFrames: []wire.FrameType{
				wire.FrameTypePathAck,
				wire.FrameTypePathAckECN,
				wire.FrameTypePathAbandon,
				wire.FrameTypePathStatusBackup,
				wire.FrameTypePathStatusAvailable,
				wire.FrameTypePathNewConnectionID,
				wire.FrameTypePathRetireConnectionID,
				wire.FrameTypeMaxPathID,
				wire.FrameTypePathsBlocked,
				wire.FrameTypePathCIDsBlocked,
			},
		},
		{
			name:        "Address discovery implies OBSERVED_ADDRESS frames",
			perspective: protocol.PerspectiveClient,
			setupConfig: func(c *Config) {
				c.ReceiveObservedAddressReports = true
			},
			peerParams: func() *wire.TransportParameters {
				return &wire.TransportParameters{
					AddressDiscoveryRole: wire.AddressDiscoverySendOnly,
				}
			},
			impliedFrames: []wire.FrameType{
				wire.FrameTypeObservedIPv4Addr,
				wire.FrameTypeObservedIPv6Addr,
			},
		},
		{
			name:        "NAT traversal implies QNT frame set",
			perspective: protocol.PerspectiveClient,
			setupConfig: func(c *Config) {
				c.MaxRemoteNATTraversalAddresses = &maxAddrs
			},
			peerParams: func() *wire.TransportParameters {
				return &wire.TransportParameters{
					MaxRemoteNATTraversalAddresses: &maxAddrs,
				}
			},
			impliedFrames: []wire.FrameType{
				wire.FrameTypeAddIPv4Address,
				wire.FrameTypeAddIPv6Address,
				wire.FrameTypeReachOutAtIPv4,
				wire.FrameTypeReachOutAtIPv6,
				wire.FrameTypeRemoveAddress,
			},
		},
		{
			name:        "ResetStreamAt parameter implies RESET_STREAM_AT frame",
			perspective: protocol.PerspectiveClient,
			setupConfig: func(c *Config) {
				c.EnableStreamResetPartialDelivery = true
			},
			peerParams: func() *wire.TransportParameters {
				return &wire.TransportParameters{
					EnableResetStreamAt: true,
				}
			},
			impliedFrames: []wire.FrameType{
				wire.FrameTypeResetStreamAt,
			},
		},
		{
			name:        "Datagrams parameter implies DATAGRAM frames",
			perspective: protocol.PerspectiveClient,
			setupConfig: func(c *Config) {
				c.EnableDatagrams = true
			},
			peerParams: func() *wire.TransportParameters {
				return &wire.TransportParameters{
					MaxDatagramFrameSize: wire.MaxDatagramSize,
				}
			},
			impliedFrames: []wire.FrameType{
				wire.FrameTypeDatagramNoLength,
				wire.FrameTypeDatagramWithLength,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			tt.setupConfig(cfg)

			c := &Conn{
				config:          cfg,
				perspective:     tt.perspective,
				logger:          utils.DefaultLogger,
				connIDGenerator: newConnIDGenerator(nil, protocol.ConnectionID{}, nil, nil, connRunnerCallbacks{}, func(wire.Frame) {}, dummyConnIDGenerator{}),
				connIDManager:   newConnIDManager(protocol.ConnectionID{}, nil, nil, nil),
			}
			c.preSetup()

			peer := tt.peerParams()
			c.peerParams.Store(peer)
			c.applyTransportParameters()

			// Check that ParseType admits each implied frame type in 1-RTT.
			for _, ft := range tt.impliedFrames {
				var data []byte
				data = quicvarint.Append(data, uint64(ft))

				parsedType, _, err := c.frameParser.ParseType(data, protocol.Encryption1RTT)
				if err != nil {
					t.Fatalf("frame parser rejected implied frame type %#x: %v", uint64(ft), err)
				}
				if parsedType != ft {
					t.Fatalf("parsed frame type %v, want %v", parsedType, ft)
				}
			}
		})
	}
}

// TestMinAckDelayAdvertisedAcceptsAckFrequency asserts that when ACK frequency support is enabled,
// the frame parser accepts ACK_FREQUENCY and IMMEDIATE_ACK frames in 1-RTT.
func TestMinAckDelayAdvertisedAcceptsAckFrequency(t *testing.T) {
	parser := wire.NewFrameParser(true, true, true, true)
	for _, ft := range []wire.FrameType{wire.FrameTypeAckFrequency, wire.FrameTypeImmediateAck} {
		data := quicvarint.Append(nil, uint64(ft))
		parsedType, _, err := parser.ParseType(data, protocol.Encryption1RTT)
		if err != nil {
			t.Fatalf("expected parser with supportsAckFrequency to admit %#x, got %v", uint64(ft), err)
		}
		if parsedType != ft {
			t.Fatalf("parsed %v, want %v", parsedType, ft)
		}
	}
}
