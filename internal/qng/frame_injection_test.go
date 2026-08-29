package quic

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// TestFrameInjection exercises the real connection handleFrame loop with synthesized
// inbound frames, asserting correct behavior and protocol error enforcement.
func TestFrameInjection(t *testing.T) {
	now := monotime.Now()
	srcAddr := netip.MustParseAddrPort("127.0.0.1:4433")

	callbacks := connRunnerCallbacks{
		AddConnectionID:    func(protocol.ConnectionID) {},
		RemoveConnectionID: func(protocol.ConnectionID) {},
		ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
	}
	resetter := newStatelessResetter(nil)

	newTestConn := func(localMaxPathID *uint32, peerMaxPathID *protocol.PathID) *Conn {
		cfg := &Config{
			InitialMaxPathID: localMaxPathID,
		}
		c := &Conn{
			config:          cfg,
			perspective:     protocol.PerspectiveClient,
			logger:          utils.DefaultLogger,
			connIDGenerator: newConnIDGenerator(nil, protocol.ConnectionID{}, nil, resetter, callbacks, func(wire.Frame) {}, dummyConnIDGenerator{}),
			connIDManager:   newConnIDManager(protocol.ConnectionID{}, nil, nil, nil),
		}
		c.preSetup()
		if peerMaxPathID != nil {
			c.peerParams.Store(&wire.TransportParameters{
				InitialMaxPathID: peerMaxPathID,
			})
			c.applyTransportParameters()
		}
		return c
	}

	t.Run("PATH_CIDS_BLOCKED valid", func(t *testing.T) {
		maxPathID := uint32(4)
		pid := protocol.PathID(4)
		c := newTestConn(&maxPathID, &pid)

		frame := &wire.PathCIDsBlockedFrame{
			PathID:  1,
			NextSeq: 2,
		}
		_, err := c.handleFrame(frame, protocol.Encryption1RTT, protocol.ConnectionID{}, now, srcAddr)
		if err != nil {
			t.Fatalf("handleFrame(PATH_CIDS_BLOCKED): %v", err)
		}
	})

	t.Run("PATH_CIDS_BLOCKED exceeding local max path id", func(t *testing.T) {
		maxPathID := uint32(2)
		pid := protocol.PathID(4)
		c := newTestConn(&maxPathID, &pid)

		frame := &wire.PathCIDsBlockedFrame{
			PathID:  3, // > local max (2)
			NextSeq: 1,
		}
		_, err := c.handleFrame(frame, protocol.Encryption1RTT, protocol.ConnectionID{}, now, srcAddr)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		var targetErr *qerr.TransportError
		if !errors.As(err, &targetErr) || targetErr.ErrorCode != qerr.ProtocolViolation {
			t.Fatalf("expected PROTOCOL_VIOLATION, got %v", err)
		}
		if targetErr.ErrorMessage != "PATH_CIDS_BLOCKED path identifier was larger than local maximum" {
			t.Fatalf("unexpected error message: %q", targetErr.ErrorMessage)
		}
	})

	t.Run("PATHS_BLOCKED exceeding local max path id", func(t *testing.T) {
		maxPathID := uint32(2)
		pid := protocol.PathID(4)
		c := newTestConn(&maxPathID, &pid)

		frame := &wire.PathsBlockedFrame{
			MaxPathID: 3, // > local max (2)
		}
		_, err := c.handleFrame(frame, protocol.Encryption1RTT, protocol.ConnectionID{}, now, srcAddr)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		var targetErr *qerr.TransportError
		if !errors.As(err, &targetErr) || targetErr.ErrorCode != qerr.ProtocolViolation {
			t.Fatalf("expected PROTOCOL_VIOLATION, got %v", err)
		}
		if targetErr.ErrorMessage != "PATHS_BLOCKED maximum path identifier was larger than local maximum" {
			t.Fatalf("unexpected error message: %q", targetErr.ErrorMessage)
		}
	})

	t.Run("PATH_NEW_CONNECTION_ID valid", func(t *testing.T) {
		maxPathID := uint32(4)
		pid := protocol.PathID(4)
		c := newTestConn(&maxPathID, &pid)

		pathID := protocol.PathID(2)
		cid := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		frame := &wire.NewConnectionIDFrame{
			PathID:         &pathID,
			SequenceNumber: 0,
			ConnectionID:   cid,
		}
		_, err := c.handleFrame(frame, protocol.Encryption1RTT, protocol.ConnectionID{}, now, srcAddr)
		if err != nil {
			t.Fatalf("handleFrame(PATH_NEW_CONNECTION_ID): %v", err)
		}
		got, ok := c.destConnIDForPath(2)
		if !ok || got != cid {
			t.Fatalf("destConnIDForPath(2) = %v (ok=%v), want %v", got, ok, cid)
		}
	})

	t.Run("PATH_NEW_CONNECTION_ID exceeding local max path id", func(t *testing.T) {
		maxPathID := uint32(2)
		pid := protocol.PathID(4)
		c := newTestConn(&maxPathID, &pid)

		pathID := protocol.PathID(3) // > local max (2)
		cid := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		frame := &wire.NewConnectionIDFrame{
			PathID:         &pathID,
			SequenceNumber: 0,
			ConnectionID:   cid,
		}
		_, err := c.handleFrame(frame, protocol.Encryption1RTT, protocol.ConnectionID{}, now, srcAddr)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		var targetErr *qerr.TransportError
		if !errors.As(err, &targetErr) || targetErr.ErrorCode != qerr.ProtocolViolation {
			t.Fatalf("expected PROTOCOL_VIOLATION, got %v", err)
		}
		if targetErr.ErrorMessage != "PATH_NEW_CONNECTION_ID contains path_id exceeding current max" {
			t.Fatalf("unexpected error message: %q", targetErr.ErrorMessage)
		}
	})

	t.Run("PATH_NEW_CONNECTION_ID exceeding active CID limit", func(t *testing.T) {
		maxPathID := uint32(10)
		pid := protocol.PathID(10)
		c := newTestConn(&maxPathID, &pid)

		// Populate active CIDs up to MaxActiveConnectionIDs (8)
		for i := 1; i <= int(protocol.MaxActiveConnectionIDs); i++ {
			p := protocol.PathID(i)
			cid := protocol.ParseConnectionID([]byte{byte(i), 1, 1, 1})
			frame := &wire.NewConnectionIDFrame{
				PathID:         &p,
				SequenceNumber: 0,
				ConnectionID:   cid,
			}
			if _, err := c.handleFrame(frame, protocol.Encryption1RTT, protocol.ConnectionID{}, now, srcAddr); err != nil {
				t.Fatalf("handleFrame(PATH_NEW_CONNECTION_ID %d): %v", i, err)
			}
		}

		// Now add one more on a new path
		overflowPathID := protocol.PathID(protocol.MaxActiveConnectionIDs + 1)
		overflowCID := protocol.ParseConnectionID([]byte{99, 1, 1, 1})
		frame := &wire.NewConnectionIDFrame{
			PathID:         &overflowPathID,
			SequenceNumber: 0,
			ConnectionID:   overflowCID,
		}
		_, err := c.handleFrame(frame, protocol.Encryption1RTT, protocol.ConnectionID{}, now, srcAddr)
		if err == nil {
			t.Fatalf("expected CONNECTION_ID_LIMIT_ERROR, got nil")
		}
		var targetErr *qerr.TransportError
		if !errors.As(err, &targetErr) || targetErr.ErrorCode != qerr.ConnectionIDLimitError {
			t.Fatalf("expected ConnectionIDLimitError, got %v", err)
		}
	})

	t.Run("OBSERVED_ADDRESS", func(t *testing.T) {
		cfg := &Config{
			ReceiveObservedAddressReports: true,
		}
		c := &Conn{
			config:          cfg,
			perspective:     protocol.PerspectiveClient,
			logger:          utils.DefaultLogger,
			connIDGenerator: newConnIDGenerator(nil, protocol.ConnectionID{}, nil, resetter, callbacks, func(wire.Frame) {}, dummyConnIDGenerator{}),
			connIDManager:   newConnIDManager(protocol.ConnectionID{}, nil, nil, nil),
		}
		c.preSetup()
		c.peerParams.Store(&wire.TransportParameters{
			AddressDiscoveryRole: wire.AddressDiscoverySendOnly,
		})
		c.applyTransportParameters()

		observed := netip.MustParseAddrPort("192.0.2.1:1234")
		frame := &wire.ObservedAddrFrame{
			SeqNo: 1,
			Addr:  observed.Addr(),
			Port:  observed.Port(),
		}
		_, err := c.handleFrame(frame, protocol.Encryption1RTT, protocol.ConnectionID{}, now, srcAddr)
		if err != nil {
			t.Fatalf("handleFrame(OBSERVED_ADDRESS): %v", err)
		}
		got, ok := c.ObservedAddr()
		if !ok || got != observed {
			t.Fatalf("ObservedAddr() = %v (ok=%v), want %v", got, ok, observed)
		}
	})
}

// TestPath0ActiveCIDLimitEnforcesAdvertisedLimit verifies that the path-0 connIDManager
// enforces the advertised active_connection_id_limit rather than a hardcoded constant.
func TestPath0ActiveCIDLimitEnforcesAdvertisedLimit(t *testing.T) {
	initialCID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	mgr := newConnIDManager(initialCID, nil, nil, nil)
	// Set custom limit, e.g. 4
	mgr.SetMaxActiveConnIDs(4)

	// Add 3 CIDs (total active queue = 3, which is < 4)
	for i := uint64(1); i <= 3; i++ {
		err := mgr.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: i,
			ConnectionID:   protocol.ParseConnectionID([]byte{byte(i), 0, 0, 0}),
		})
		if err != nil {
			t.Fatalf("Add CID %d failed: %v", i, err)
		}
	}

	// 4th CID should exceed limit of 4 active queued CIDs
	err := mgr.Add(&wire.NewConnectionIDFrame{
		SequenceNumber: 4,
		ConnectionID:   protocol.ParseConnectionID([]byte{4, 0, 0, 0}),
	})
	if err == nil {
		t.Fatalf("expected ConnectionIDLimitError, got nil")
	}
	var targetErr *qerr.TransportError
	if !errors.As(err, &targetErr) || targetErr.ErrorCode != qerr.ConnectionIDLimitError {
		t.Fatalf("expected ConnectionIDLimitError, got %v", err)
	}
}
