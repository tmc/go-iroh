package quic

import (
	"bytes"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// These tests cover Stage 5c of the QUIC multipath port: per-path connection-ID
// issuance via PATH_NEW_CONNECTION_ID (0x3e78) on the issuer side, recording
// peer-issued path CIDs on the read side, and the send-side DCID->PathID
// resolution. Wire layouts are pinned against the authoritative noq-proto
// reference (internal/qng/n0ext/reference/frame.rs).

// stubConnRunner is a no-op connRunner used only as the map key the
// connIDGenerator stores; CID add/remove bookkeeping is observed through the
// connRunnerCallbacks passed separately to newConnIDGenerator.
type stubConnRunner struct{}

func (stubConnRunner) Add(protocol.ConnectionID, packetHandler) bool                    { return true }
func (stubConnRunner) Remove(protocol.ConnectionID)                                     {}
func (stubConnRunner) ReplaceWithClosed([]protocol.ConnectionID, []byte, time.Duration) {}
func (stubConnRunner) AddResetToken(protocol.StatelessResetToken, packetHandler)        {}
func (stubConnRunner) RemoveResetToken(protocol.StatelessResetToken)                    {}

// newTestConnIDGenerator builds a connIDGenerator that records the frames it
// queues and the CIDs it registers/removes, so tests can inspect the
// NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID it emits.
func newTestConnIDGenerator(t *testing.T) (g *connIDGenerator, frames *[]wire.Frame, added *[]protocol.ConnectionID) {
	t.Helper()
	var queued []wire.Frame
	var addedIDs []protocol.ConnectionID
	initial := protocol.ParseConnectionID([]byte{0x00, 0x11, 0x22, 0x33})
	g = newConnIDGenerator(
		stubConnRunner{},
		initial,
		nil, // client: no initialClientDestConnID
		newStatelessResetter(nil),
		connRunnerCallbacks{
			AddConnectionID:    func(id protocol.ConnectionID) { addedIDs = append(addedIDs, id) },
			RemoveConnectionID: func(protocol.ConnectionID) {},
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(f wire.Frame) { queued = append(queued, f) },
		&protocol.DefaultConnectionIDGenerator{ConnLen: 4},
	)
	return g, &queued, &addedIDs
}

// TestIssueNewConnIDStaysPlain proves the single-path issuance path is
// byte-identical: issueNewConnID never sets a PathID, so the emitted frame is a
// plain NEW_CONNECTION_ID (0x18), and its Append output carries no 0x3e78.
func TestIssueNewConnIDStaysPlain(t *testing.T) {
	g, frames, _ := newTestConnIDGenerator(t)
	if err := g.issueNewConnID(); err != nil {
		t.Fatalf("issueNewConnID: %v", err)
	}
	if len(*frames) != 1 {
		t.Fatalf("queued %d frames, want 1", len(*frames))
	}
	nc, ok := (*frames)[0].(*wire.NewConnectionIDFrame)
	if !ok {
		t.Fatalf("frame type = %T, want *wire.NewConnectionIDFrame", (*frames)[0])
	}
	if nc.PathID != nil {
		t.Fatalf("single-path NEW_CONNECTION_ID has PathID %v, want nil", *nc.PathID)
	}
	got, err := nc.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got[0] != byte(wire.FrameTypeNewConnectionID) {
		t.Fatalf("frame type byte = %#x, want %#x (plain NEW_CONNECTION_ID)", got[0], byte(wire.FrameTypeNewConnectionID))
	}
	assertNoPathNewConnID(t, got)
}

// TestIssuePathConnIDEmitsPathFrame proves the issuer side of 5c: opening a path
// emits PATH_NEW_CONNECTION_ID{PathID:1} (0x3e78) with the path's own sequence
// space (starting at 0), and the issued CID is registered so incoming packets
// to it are recognized. The connection-level highestSeq is untouched.
func TestIssuePathConnIDEmitsPathFrame(t *testing.T) {
	g, frames, added := newTestConnIDGenerator(t)

	cid1, err := g.issuePathConnID(1)
	if err != nil {
		t.Fatalf("issuePathConnID(1): %v", err)
	}
	if len(*frames) != 1 {
		t.Fatalf("queued %d frames, want 1", len(*frames))
	}
	nc, ok := (*frames)[0].(*wire.NewConnectionIDFrame)
	if !ok {
		t.Fatalf("frame type = %T, want *wire.NewConnectionIDFrame", (*frames)[0])
	}
	if nc.PathID == nil || *nc.PathID != 1 {
		t.Fatalf("PathID = %v, want 1", nc.PathID)
	}
	if nc.SequenceNumber != 0 {
		t.Fatalf("path-1 first CID sequence = %d, want 0 (independent per-path space)", nc.SequenceNumber)
	}
	if nc.ConnectionID != cid1 {
		t.Fatalf("frame CID %s != returned CID %s", nc.ConnectionID, cid1)
	}
	if g.highestSeq != 0 {
		t.Fatalf("connection-level highestSeq = %d, path issuance must not advance it", g.highestSeq)
	}
	if len(*added) != 1 || (*added)[0] != cid1 {
		t.Fatalf("issued CID not registered with the conn runner: added=%v", *added)
	}

	// A second CID for path 1 advances path 1's own sequence to 1.
	cid1b, err := g.issuePathConnID(1)
	if err != nil {
		t.Fatalf("issuePathConnID(1) #2: %v", err)
	}
	nc2 := (*frames)[1].(*wire.NewConnectionIDFrame)
	if nc2.SequenceNumber != 1 {
		t.Fatalf("path-1 second CID sequence = %d, want 1", nc2.SequenceNumber)
	}
	if cid1b == cid1 {
		t.Fatalf("path 1's two CIDs must differ")
	}

	// A different path has its own sequence space starting at 0.
	if _, err := g.issuePathConnID(2); err != nil {
		t.Fatalf("issuePathConnID(2): %v", err)
	}
	nc3 := (*frames)[2].(*wire.NewConnectionIDFrame)
	if nc3.PathID == nil || *nc3.PathID != 2 || nc3.SequenceNumber != 0 {
		t.Fatalf("path-2 first CID = {PathID:%v Seq:%d}, want {2 0}", nc3.PathID, nc3.SequenceNumber)
	}
}

// TestIssuePathConnIDZeroRejected guards risk #5: PathIDZero's CIDs flow through
// the connection-level issueNewConnID; calling issuePathConnID for it is a bug.
func TestIssuePathConnIDZeroRejected(t *testing.T) {
	g, frames, _ := newTestConnIDGenerator(t)
	if _, err := g.issuePathConnID(protocol.PathIDZero); err == nil {
		t.Fatalf("issuePathConnID(PathIDZero) should error")
	}
	if len(*frames) != 0 {
		t.Fatalf("issuePathConnID(PathIDZero) emitted %d frames, want 0", len(*frames))
	}
}

func TestRetirePathConnIDIssuesReplacement(t *testing.T) {
	g, frames, added := newTestConnIDGenerator(t)
	cid, err := g.issuePathConnID(1)
	if err != nil {
		t.Fatalf("issuePathConnID: %v", err)
	}
	if len(*frames) != 1 {
		t.Fatalf("queued frames = %d, want 1", len(*frames))
	}
	if err := g.RetirePath(1, 0, protocol.ParseConnectionID([]byte{0xff}), monotime.Now()); err != nil {
		t.Fatalf("RetirePath: %v", err)
	}
	if _, ok := g.pathSrcConnIDs[1][0]; ok {
		t.Fatalf("retired path CID %s still active", cid)
	}
	// DefaultActiveConnectionIDLimit is 2, MaxIssuedConnectionIDs is 6, so budget is 2.
	// We started with 1 CID, retired it, so RetirePath replenished path 1 back to budget (2 active CIDs).
	// Total frames queued = 1 (initial) + 2 (replenishment) = 3 frames.
	if len(*frames) != 3 {
		t.Fatalf("queued frames = %d, want 3 (1 initial + 2 replenishment to budget)", len(*frames))
	}
	nc := (*frames)[1].(*wire.NewConnectionIDFrame)
	if nc.PathID == nil || *nc.PathID != 1 || nc.SequenceNumber != 1 {
		t.Fatalf("replacement frame 1 = {PathID:%v Seq:%d}, want {1 1}", nc.PathID, nc.SequenceNumber)
	}
	nc2 := (*frames)[2].(*wire.NewConnectionIDFrame)
	if nc2.PathID == nil || *nc2.PathID != 1 || nc2.SequenceNumber != 2 {
		t.Fatalf("replacement frame 2 = {PathID:%v Seq:%d}, want {1 2}", nc2.PathID, nc2.SequenceNumber)
	}
	if len(*added) != 3 {
		t.Fatalf("registered CIDs = %d, want 3", len(*added))
	}
}

func TestHandlePathRetireConnectionIDPathZeroUsesConnIDGenerator(t *testing.T) {
	c := newMultipathConn(true)
	var queued []wire.Frame
	c.connIDGenerator = newConnIDGenerator(
		stubConnRunner{},
		protocol.ParseConnectionID([]byte{0x01, 0x02, 0x03, 0x04}),
		nil,
		newStatelessResetter(nil),
		connRunnerCallbacks{
			AddConnectionID:    func(protocol.ConnectionID) {},
			RemoveConnectionID: func(protocol.ConnectionID) {},
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(f wire.Frame) { queued = append(queued, f) },
		&protocol.DefaultConnectionIDGenerator{ConnLen: 4},
	)
	if err := c.connIDGenerator.issueNewConnID(); err != nil {
		t.Fatalf("issueNewConnID: %v", err)
	}
	pid := protocol.PathIDZero
	frame := &wire.RetireConnectionIDFrame{PathID: &pid, SequenceNumber: 1}
	if err := c.handleRetireConnectionIDFrame(frame, protocol.ParseConnectionID([]byte{0xff}), monotime.Now()); err != nil {
		t.Fatalf("handleRetireConnectionIDFrame: %v", err)
	}
	if _, ok := c.connIDGenerator.activeSrcConnIDs[1]; ok {
		t.Fatalf("connection-level CID sequence 1 still active")
	}
	if len(queued) != 2 {
		t.Fatalf("queued frames = %d, want initial CID plus replacement", len(queued))
	}
	if nc, ok := queued[1].(*wire.NewConnectionIDFrame); !ok || nc.PathID != nil || nc.SequenceNumber != 2 {
		t.Fatalf("replacement frame = %#v, want plain NEW_CONNECTION_ID seq 2", queued[1])
	}
}

// TestPathNewConnectionIDGoldenFromGenerator pins the on-wire 0x3e78 layout the
// issuer emits: frame type 0x3e78, then path_id, then sequence (frame.rs:
// 2015-2026 NewConnectionId::encode writes path_id before sequence). It mirrors
// the wire-package golden test but exercises the integration-level frame the
// connIDGenerator actually queues.
func TestPathNewConnectionIDGoldenFromGenerator(t *testing.T) {
	g, frames, _ := newTestConnIDGenerator(t)
	if _, err := g.issuePathConnID(1); err != nil {
		t.Fatalf("issuePathConnID(1): %v", err)
	}
	nc := (*frames)[0].(*wire.NewConnectionIDFrame)
	got, err := nc.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	// 7e 78 (type 0x3e78 as a 2-byte varint) | 01 (path_id) | 00 (sequence) |
	// 00 (retire_prior_to) | 04 (cid len) | <4-byte cid> | 16-byte reset token.
	wantPrefix := []byte{0x7e, 0x78, 0x01, 0x00, 0x00, 0x04}
	if !bytes.HasPrefix(got, wantPrefix) {
		t.Fatalf("encode prefix = % x, want % x (path_id before sequence)", got[:len(wantPrefix)], wantPrefix)
	}
	// type(2) + path_id(1) + seq(1) + retire(1) + len(1) + cid(4) + token(16).
	if len(got) != 2+1+1+1+1+4+16 {
		t.Fatalf("encoded length = %d, want %d", len(got), 2+1+1+1+1+4+16)
	}
}

// assertNoPathNewConnID fails if buf contains the PATH_NEW_CONNECTION_ID frame
// type (0x3e78). Used to prove single-path output carries no multipath CID
// frames.
func assertNoPathNewConnID(t *testing.T, buf []byte) {
	t.Helper()
	marker := quicvarint.Append(nil, uint64(wire.FrameTypePathNewConnectionID))
	if bytes.Contains(buf, marker) {
		t.Fatalf("buffer % x contains PATH_NEW_CONNECTION_ID marker % x", buf, marker)
	}
}

// newMultipathConn builds a minimal *Conn for read-side handler tests, mirroring
// the construction in multipath_frame_guard_test.go. on selects whether
// multipath is negotiated.
func newMultipathConn(on bool) *Conn {
	cfg := &Config{}
	peer := &wire.TransportParameters{}
	if on {
		maxLocal := uint32(8)
		pid := protocol.PathID(8)
		cfg.InitialMaxPathID = &maxLocal
		peer.InitialMaxPathID = &pid
	}
	c := &Conn{config: cfg}
	c.peerParams.Store(peer)
	c.multipathManager = newMultipathManager()
	c.perPathDestConnIDs = make(map[protocol.PathID]protocol.ConnectionID)
	return c
}

func TestCanOpenPathUsesPeerInitialMaxPathID(t *testing.T) {
	c := newMultipathConn(true)
	if !c.canOpenPath(protocol.PathID(1)) {
		t.Fatal("canOpenPath(1) = false, want true from peer initial_max_path_id")
	}
	if c.canOpenPath(protocol.PathIDZero) {
		t.Fatal("canOpenPath(0) = true, want false")
	}
	if c.canOpenPath(protocol.PathID(9)) {
		t.Fatal("canOpenPath(9) = true, want false above local and peer max")
	}

	peerInitial := protocol.PathID(1)
	c.peerParams.Load().InitialMaxPathID = &peerInitial
	if c.canOpenPath(protocol.PathID(2)) {
		t.Fatal("canOpenPath(2) = true, want false above peer initial max")
	}
	c.multipathManager.handleMaxPathID(protocol.PathID(2))
	if !c.canOpenPath(protocol.PathID(2)) {
		t.Fatal("canOpenPath(2) = false, want true after MAX_PATH_ID raises peer max")
	}
}

// TestHandlePathNewConnectionIDRecordsDestConnID proves the read side of 5c: an
// incoming PATH_NEW_CONNECTION_ID{PathID:1} records a distinct DCID for path 1
// in perPathDestConnIDs, and destConnIDForPath(1) returns it.
func TestHandlePathNewConnectionIDRecordsDestConnID(t *testing.T) {
	c := newMultipathConn(true)
	pathCID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	pid := protocol.PathID(1)
	frame := &wire.NewConnectionIDFrame{
		PathID:         &pid,
		SequenceNumber: 0,
		ConnectionID:   pathCID,
	}
	if err := c.handleNewConnectionIDFrame(frame); err != nil {
		t.Fatalf("handleNewConnectionIDFrame: %v", err)
	}
	got, ok := c.perPathDestConnIDs[1]
	if !ok {
		t.Fatalf("path 1 DCID not recorded")
	}
	if got != pathCID {
		t.Fatalf("recorded DCID %s, want %s", got, pathCID)
	}
	resolved, ok := c.destConnIDForPath(1)
	if !ok || resolved != pathCID {
		t.Fatalf("destConnIDForPath(1) = %s,%v, want %s,true", resolved, ok, pathCID)
	}
	if c.multipathOut != nil {
		t.Fatal("PATH_NEW_CONNECTION_ID recorded a DCID but should not open path state")
	}
}

func TestHandlePathCIDsBlockedRecordsStats(t *testing.T) {
	c := newMultipathConn(true)
	g, frames, _ := newTestConnIDGenerator(t)
	c.connIDGenerator = g

	if err := c.handlePathCIDsBlockedFrame(&wire.PathCIDsBlockedFrame{PathID: 1, NextSeq: 0}); err != nil {
		t.Fatalf("handlePathCIDsBlockedFrame: %v", err)
	}
	if len(*frames) != 0 {
		t.Fatalf("queued %d frames, want 0 (informational only)", len(*frames))
	}
	if c.connStats.PathCIDsBlocked.Load() != 1 {
		t.Fatalf("connStats.PathCIDsBlocked = %d, want 1", c.connStats.PathCIDsBlocked.Load())
	}
	if c.multipathOut != nil {
		t.Fatal("PATH_CIDS_BLOCKED should not open path state")
	}

	if err := c.handlePathCIDsBlockedFrame(&wire.PathCIDsBlockedFrame{PathID: 1, NextSeq: 0}); err != nil {
		t.Fatalf("handle duplicate PATH_CIDS_BLOCKED: %v", err)
	}
	if len(*frames) != 0 {
		t.Fatalf("queued %d frames after duplicate, want 0", len(*frames))
	}
	if c.connStats.PathCIDsBlocked.Load() != 2 {
		t.Fatalf("connStats.PathCIDsBlocked = %d, want 2", c.connStats.PathCIDsBlocked.Load())
	}
}

// TestHandlePathNewConnectionIDRejectedWhenOff proves a path-qualified frame on a
// single-path connection is a protocol violation (defensive double-guard).
func TestHandlePathNewConnectionIDRejectedWhenOff(t *testing.T) {
	c := newMultipathConn(false)
	pid := protocol.PathID(1)
	frame := &wire.NewConnectionIDFrame{PathID: &pid, ConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4})}
	err := c.handleNewConnectionIDFrame(frame)
	if err == nil {
		t.Fatalf("PATH_NEW_CONNECTION_ID with multipath off should error")
	}
	te, ok := err.(*qerr.TransportError)
	if !ok || te.ErrorCode != qerr.ProtocolViolation {
		t.Fatalf("error = %v, want ProtocolViolation", err)
	}
	if len(c.perPathDestConnIDs) != 0 {
		t.Fatalf("rejected frame must not record a DCID, got %v", c.perPathDestConnIDs)
	}
}

// TestHandlePathNewConnectionIDPathZeroUsesConnIDManager proves the noq
// path-qualified PathID 0 form is accepted as connection-level CID state.
func TestHandlePathNewConnectionIDPathZeroUsesConnIDManager(t *testing.T) {
	c := newMultipathConn(true)
	initial := protocol.ParseConnectionID([]byte{0x0a, 0x0b, 0x0c, 0x0d})
	c.connIDManager = newConnIDManager(
		initial,
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(wire.Frame) {},
	)
	pid := protocol.PathIDZero
	frame := &wire.NewConnectionIDFrame{
		PathID:         &pid,
		SequenceNumber: 1,
		ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
	}
	if err := c.handleNewConnectionIDFrame(frame); err != nil {
		t.Fatalf("handleNewConnectionIDFrame: %v", err)
	}
	if len(c.perPathDestConnIDs) != 0 {
		t.Fatalf("PathID 0 frame must not touch perPathDestConnIDs, got %v", c.perPathDestConnIDs)
	}
	if got := len(c.connIDManager.queue); got != 1 {
		t.Fatalf("connIDManager queue len = %d, want 1", got)
	}
	if got := c.connIDManager.queue[0].ConnectionID; got != frame.ConnectionID {
		t.Fatalf("queued CID = %s, want %s", got, frame.ConnectionID)
	}
}

// TestDestConnIDForPathZeroUsesConnIDManager proves PathIDZero's DCID always
// comes from connIDManager.Get (the single connection-level CID), keeping
// single-path sends byte-identical, and that a non-zero path's DCID is distinct
// from it (perPathDestConnIDs[1] != connIDManager.Get()).
func TestDestConnIDForPathZeroUsesConnIDManager(t *testing.T) {
	c := newMultipathConn(true)
	active := protocol.ParseConnectionID([]byte{0x0a, 0x0b, 0x0c, 0x0d})
	c.connIDManager = newConnIDManager(
		active,
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(wire.Frame) {},
	)

	got, ok := c.destConnIDForPath(protocol.PathIDZero)
	if !ok || got != active {
		t.Fatalf("destConnIDForPath(0) = %s,%v, want %s,true (connIDManager.Get)", got, ok, active)
	}

	// Before the peer issues a path-1 CID, resolution reports not-ok.
	if _, ok := c.destConnIDForPath(1); ok {
		t.Fatalf("destConnIDForPath(1) should be not-ok before PATH_NEW_CONNECTION_ID")
	}

	pathCID := protocol.ParseConnectionID([]byte{0x11, 0x22, 0x33, 0x44})
	pid := protocol.PathID(1)
	if err := c.handleNewConnectionIDFrame(&wire.NewConnectionIDFrame{PathID: &pid, ConnectionID: pathCID}); err != nil {
		t.Fatalf("handleNewConnectionIDFrame: %v", err)
	}
	p1, ok := c.destConnIDForPath(1)
	if !ok || p1 != pathCID {
		t.Fatalf("destConnIDForPath(1) = %s,%v, want %s,true", p1, ok, pathCID)
	}
	if p1 == c.connIDManager.Get() {
		t.Fatalf("path-1 DCID %s must differ from connIDManager.Get() %s", p1, c.connIDManager.Get())
	}
}

// TestHandlePlainNewConnectionIDUnchanged proves the non-multipath read path is
// unchanged: a plain NEW_CONNECTION_ID (PathID nil) is routed to connIDManager
// and never lands in perPathDestConnIDs.
func TestHandlePlainNewConnectionIDUnchanged(t *testing.T) {
	c := newMultipathConn(false)
	var added []wire.Frame
	c.connIDManager = newConnIDManager(
		protocol.ParseConnectionID([]byte{0x01, 0x02, 0x03, 0x04}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) { added = append(added, f) },
	)
	var token protocol.StatelessResetToken
	frame := &wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xaa, 0xbb, 0xcc, 0xdd}),
		StatelessResetToken: token,
	}
	if err := c.handleNewConnectionIDFrame(frame); err != nil {
		t.Fatalf("handleNewConnectionIDFrame (plain): %v", err)
	}
	if len(c.perPathDestConnIDs) != 0 {
		t.Fatalf("plain NEW_CONNECTION_ID must not touch perPathDestConnIDs, got %v", c.perPathDestConnIDs)
	}
}

// TestIssueFirstPathCIDsBatchAndSequenceNumbers verifies that when multipath is
// negotiated with max path id N and peer limit L, exactly N * min(L, cap) path
// CID frames are queued with strictly monotonic sequence numbers starting at 0 per path.
func TestIssueFirstPathCIDsBatchAndSequenceNumbers(t *testing.T) {
	g, frames, added := newTestConnIDGenerator(t)
	peerLimit := uint64(4)
	if err := g.SetMaxActiveConnIDs(peerLimit); err != nil {
		t.Fatalf("SetMaxActiveConnIDs: %v", err)
	}

	// For path 0, SetMaxActiveConnIDs queued peerLimit-1 = 3 frames.
	if len(*frames) != 3 {
		t.Fatalf("path 0 queued %d frames, want 3", len(*frames))
	}
	*frames = (*frames)[:0]
	*added = (*added)[:0]

	maxPathID := protocol.PathID(3)
	if err := g.IssueFirstPathCIDs(maxPathID); err != nil {
		t.Fatalf("IssueFirstPathCIDs(3): %v", err)
	}

	// 3 paths (1, 2, 3) * 4 CIDs each = 12 frames.
	if len(*frames) != 12 {
		t.Fatalf("queued %d frames, want 12", len(*frames))
	}
	if len(*added) != 12 {
		t.Fatalf("added %d CIDs, want 12", len(*added))
	}

	perPathSeqs := make(map[protocol.PathID][]uint64)
	for _, f := range *frames {
		nc, ok := f.(*wire.NewConnectionIDFrame)
		if !ok {
			t.Fatalf("expected *wire.NewConnectionIDFrame, got %T", f)
		}
		if nc.PathID == nil {
			t.Fatalf("PathID is nil in path frame")
		}
		if *nc.PathID == protocol.PathIDZero {
			t.Fatalf("PathIDZero appeared in PATH_NEW_CONNECTION_ID")
		}
		perPathSeqs[*nc.PathID] = append(perPathSeqs[*nc.PathID], nc.SequenceNumber)
	}

	for pid := protocol.PathID(1); pid <= maxPathID; pid++ {
		seqs := perPathSeqs[pid]
		if len(seqs) != 4 {
			t.Fatalf("path %d got %d frames, want 4", pid, len(seqs))
		}
		for i, seq := range seqs {
			if seq != uint64(i) {
				t.Fatalf("path %d seq %d != %d", pid, seq, i)
			}
		}
	}

	// Calling again with same or smaller maxPathID is a no-op (idempotent).
	*frames = (*frames)[:0]
	if err := g.IssueFirstPathCIDs(maxPathID); err != nil {
		t.Fatalf("IssueFirstPathCIDs duplicate: %v", err)
	}
	if len(*frames) != 0 {
		t.Fatalf("IssueFirstPathCIDs duplicate queued %d frames, want 0", len(*frames))
	}

	// Raising MAX_PATH_ID from 3 to 5 issues batches ONLY for paths 4 and 5 (2 * 4 = 8 frames).
	if err := g.IssueFirstPathCIDs(protocol.PathID(5)); err != nil {
		t.Fatalf("IssueFirstPathCIDs(5): %v", err)
	}
	if len(*frames) != 8 {
		t.Fatalf("raising to 5 queued %d frames, want 8", len(*frames))
	}
	for _, f := range *frames {
		nc := f.(*wire.NewConnectionIDFrame)
		if *nc.PathID < 4 || *nc.PathID > 5 {
			t.Fatalf("unexpected PathID %d on raise", *nc.PathID)
		}
	}
}

// TestRetireMultipleCIDsReplenishesToBudget verifies that retiring multiple CIDs on one path
// restores that path to the full budget while leaving other paths untouched.
func TestRetireMultipleCIDsReplenishesToBudget(t *testing.T) {
	g, frames, _ := newTestConnIDGenerator(t)
	peerLimit := uint64(3)
	if err := g.SetMaxActiveConnIDs(peerLimit); err != nil {
		t.Fatalf("SetMaxActiveConnIDs: %v", err)
	}
	if err := g.IssueFirstPathCIDs(protocol.PathID(2)); err != nil {
		t.Fatalf("IssueFirstPathCIDs: %v", err)
	}

	// Paths 1 and 2 each have 3 CIDs (seqs 0, 1, 2).
	if len(g.pathSrcConnIDs[1]) != 3 || len(g.pathSrcConnIDs[2]) != 3 {
		t.Fatalf("initial path sizes: path1=%d, path2=%d", len(g.pathSrcConnIDs[1]), len(g.pathSrcConnIDs[2]))
	}

	*frames = (*frames)[:0]
	// Retire seq 0 on path 1.
	if err := g.RetirePath(1, 0, protocol.ParseConnectionID([]byte{0xff}), monotime.Now()); err != nil {
		t.Fatalf("RetirePath(1, 0): %v", err)
	}
	if len(g.pathSrcConnIDs[1]) != 3 {
		t.Fatalf("path 1 size after 1 retire = %d, want 3", len(g.pathSrcConnIDs[1]))
	}
	if len(g.pathSrcConnIDs[2]) != 3 {
		t.Fatalf("path 2 size touched: %d", len(g.pathSrcConnIDs[2]))
	}
	// Emitted seq 3 for path 1.
	if len(*frames) != 1 {
		t.Fatalf("queued %d frames, want 1", len(*frames))
	}
	nc := (*frames)[0].(*wire.NewConnectionIDFrame)
	if *nc.PathID != 1 || nc.SequenceNumber != 3 {
		t.Fatalf("replacement = {PathID:%v Seq:%d}, want {1 3}", nc.PathID, nc.SequenceNumber)
	}

	*frames = (*frames)[:0]
	// Retire seq 1 on path 1.
	if err := g.RetirePath(1, 1, protocol.ParseConnectionID([]byte{0xff}), monotime.Now()); err != nil {
		t.Fatalf("RetirePath(1, 1): %v", err)
	}
	if len(g.pathSrcConnIDs[1]) != 3 {
		t.Fatalf("path 1 size after 2nd retire = %d, want 3", len(g.pathSrcConnIDs[1]))
	}
	nc = (*frames)[0].(*wire.NewConnectionIDFrame)
	if *nc.PathID != 1 || nc.SequenceNumber != 4 {
		t.Fatalf("replacement = {PathID:%v Seq:%d}, want {1 4}", nc.PathID, nc.SequenceNumber)
	}
}
