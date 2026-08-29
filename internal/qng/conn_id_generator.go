package quic

import (
	"fmt"
	"slices"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

type connRunnerCallbacks struct {
	AddConnectionID    func(protocol.ConnectionID)
	RemoveConnectionID func(protocol.ConnectionID)
	ReplaceWithClosed  func([]protocol.ConnectionID, []byte, time.Duration)
}

// The memory address of the Transport is used as the key.
type connRunners map[connRunner]connRunnerCallbacks

func (cr connRunners) AddConnectionID(id protocol.ConnectionID) {
	for _, c := range cr {
		c.AddConnectionID(id)
	}
}

func (cr connRunners) RemoveConnectionID(id protocol.ConnectionID) {
	for _, c := range cr {
		c.RemoveConnectionID(id)
	}
}

func (cr connRunners) ReplaceWithClosed(ids []protocol.ConnectionID, b []byte, expiry time.Duration) {
	for _, c := range cr {
		c.ReplaceWithClosed(ids, b, expiry)
	}
}

type connIDToRetire struct {
	t      monotime.Time
	connID protocol.ConnectionID
}

type connIDGenerator struct {
	generator   ConnectionIDGenerator
	highestSeq  uint64
	connRunners connRunners

	activeSrcConnIDs map[uint64]protocol.ConnectionID
	// cidPath indexes every issued source connection ID by the path it
	// belongs to, for per-packet lookup in pathForLocalConnID.
	cidPath                 map[protocol.ConnectionID]protocol.PathID
	connIDsToRetire         []connIDToRetire       // sorted by t
	initialClientDestConnID *protocol.ConnectionID // nil for the client

	// pathSrcConnIDs / pathHighestSeq hold the connection IDs we (the issuer)
	// emit for QUIC multipath (draft-ietf-quic-multipath) paths via
	// PATH_NEW_CONNECTION_ID (0x3e78). They are keyed by protocol.PathID and are
	// STRICTLY SEPARATE from activeSrcConnIDs/highestSeq, which serve the single
	// connection-level CID sequence space (PathID 0). Each multipath PathID owns
	// an independent CID sequence number space (frame.rs:2005-2012 IssuedCid is
	// scoped to its path_id). Lazily initialized: no entry exists, and no frame
	// is emitted, unless multipath is negotiated and a non-zero path is opened.
	pathSrcConnIDs map[protocol.PathID]map[uint64]protocol.ConnectionID
	pathHighestSeq map[protocol.PathID]uint64

	peerActiveConnIDLimit uint64
	maxPathIDWithCIDs     protocol.PathID

	statelessResetter *statelessResetter

	queueControlFrame func(wire.Frame)
}

func newConnIDGenerator(
	runner connRunner,
	initialConnectionID protocol.ConnectionID,
	initialClientDestConnID *protocol.ConnectionID, // nil for the client
	statelessResetter *statelessResetter,
	callbacks connRunnerCallbacks,
	queueControlFrame func(wire.Frame),
	generator ConnectionIDGenerator,
) *connIDGenerator {
	m := &connIDGenerator{
		generator:             generator,
		activeSrcConnIDs:      make(map[uint64]protocol.ConnectionID),
		cidPath:               make(map[protocol.ConnectionID]protocol.PathID),
		statelessResetter:     statelessResetter,
		connRunners:           map[connRunner]connRunnerCallbacks{runner: callbacks},
		queueControlFrame:     queueControlFrame,
		peerActiveConnIDLimit: protocol.DefaultActiveConnectionIDLimit,
	}
	m.activeSrcConnIDs[0] = initialConnectionID
	m.cidPath[initialConnectionID] = protocol.PathIDZero
	m.initialClientDestConnID = initialClientDestConnID
	if initialClientDestConnID != nil {
		m.cidPath[*initialClientDestConnID] = protocol.PathIDZero
	}
	return m
}

func (m *connIDGenerator) issueCIDsLimit() uint64 {
	return min(m.peerActiveConnIDLimit, protocol.MaxIssuedConnectionIDs)
}

func (m *connIDGenerator) SetMaxActiveConnIDs(limit uint64) error {
	m.peerActiveConnIDLimit = limit
	if m.generator.ConnectionIDLen() == 0 {
		return nil
	}
	// The active_connection_id_limit transport parameter is the number of
	// connection IDs the peer will store. This limit includes the connection ID
	// used during the handshake, and the one sent in the preferred_address
	// transport parameter.
	// We currently don't send the preferred_address transport parameter,
	// so we can issue (limit - 1) connection IDs.
	for i := uint64(len(m.activeSrcConnIDs)); i < m.issueCIDsLimit(); i++ {
		if err := m.issueNewConnID(); err != nil {
			return err
		}
	}
	budget := m.issueCIDsLimit()
	for pid := protocol.PathID(1); pid <= m.maxPathIDWithCIDs; pid++ {
		cur := uint64(len(m.pathSrcConnIDs[pid]))
		for i := cur; i < budget; i++ {
			if _, err := m.issuePathConnID(pid); err != nil {
				return err
			}
		}
	}
	return nil
}

// IssueFirstPathCIDs issues an initial batch of connection IDs up to the budget
// for newly covered paths when local MAX_PATH_ID is set or raised, matching noq's
// issue_first_path_cids (connection/mod.rs:6030-6044). maxPathIDWithCIDs tracks
// the high-water mark so raises are incremental and idempotent.
func (m *connIDGenerator) IssueFirstPathCIDs(maxPathID protocol.PathID) error {
	if m.generator.ConnectionIDLen() == 0 {
		if maxPathID > m.maxPathIDWithCIDs {
			m.maxPathIDWithCIDs = maxPathID
		}
		return nil
	}
	budget := m.issueCIDsLimit()
	for pid := m.maxPathIDWithCIDs + 1; pid <= maxPathID; pid++ {
		cur := uint64(len(m.pathSrcConnIDs[pid]))
		for i := cur; i < budget; i++ {
			if _, err := m.issuePathConnID(pid); err != nil {
				return err
			}
		}
	}
	if maxPathID > m.maxPathIDWithCIDs {
		m.maxPathIDWithCIDs = maxPathID
	}
	return nil
}

func (m *connIDGenerator) Retire(seq uint64, sentWithDestConnID protocol.ConnectionID, expiry monotime.Time) error {
	if seq > m.highestSeq {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (highest issued: %d)", seq, m.highestSeq),
		}
	}
	connID, ok := m.activeSrcConnIDs[seq]
	// We might already have deleted this connection ID, if this is a duplicate frame.
	if !ok {
		return nil
	}
	if connID == sentWithDestConnID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (%s), which was used as the Destination Connection ID on this packet", seq, connID),
		}
	}
	m.queueConnIDForRetiring(connID, expiry)

	delete(m.activeSrcConnIDs, seq)
	delete(m.cidPath, connID)
	// Don't issue a replacement for the initial connection ID.
	if seq == 0 {
		return nil
	}
	return m.issueNewConnID()
}

func (m *connIDGenerator) RetirePath(pid protocol.PathID, seq uint64, sentWithDestConnID protocol.ConnectionID, expiry monotime.Time) error {
	if pid == protocol.PathIDZero {
		return m.Retire(seq, sentWithDestConnID, expiry)
	}
	highestNext, ok := m.pathHighestSeq[pid]
	if !ok || seq >= highestNext {
		highest := uint64(0)
		if ok && highestNext > 0 {
			highest = highestNext - 1
		}
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d on path %d (highest issued: %d)", seq, pid, highest),
		}
	}
	ids := m.pathSrcConnIDs[pid]
	connID, ok := ids[seq]
	if !ok {
		return nil
	}
	if connID == sentWithDestConnID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d on path %d (%s), which was used as the Destination Connection ID on this packet", seq, pid, connID),
		}
	}
	m.queueConnIDForRetiring(connID, expiry)
	delete(ids, seq)
	delete(m.cidPath, connID)
	if len(ids) == 0 {
		delete(m.pathSrcConnIDs, pid)
	}
	// Replenish active pool to budget (noq connection/mod.rs:5084 semantics)
	budget := m.issueCIDsLimit()
	for uint64(len(m.pathSrcConnIDs[pid])) < budget {
		if _, err := m.issuePathConnID(pid); err != nil {
			return err
		}
	}
	return nil
}

func (m *connIDGenerator) queueConnIDForRetiring(connID protocol.ConnectionID, expiry monotime.Time) {
	idx := slices.IndexFunc(m.connIDsToRetire, func(c connIDToRetire) bool {
		return c.t.After(expiry)
	})
	if idx == -1 {
		idx = len(m.connIDsToRetire)
	}
	m.connIDsToRetire = slices.Insert(m.connIDsToRetire, idx, connIDToRetire{t: expiry, connID: connID})
}

func (m *connIDGenerator) issueNewConnID() error {
	connID, err := m.generator.GenerateConnectionID()
	if err != nil {
		return err
	}
	m.activeSrcConnIDs[m.highestSeq+1] = connID
	m.cidPath[connID] = protocol.PathIDZero
	m.connRunners.AddConnectionID(connID)
	m.queueControlFrame(&wire.NewConnectionIDFrame{
		SequenceNumber:      m.highestSeq + 1,
		ConnectionID:        connID,
		StatelessResetToken: m.statelessResetter.GetStatelessResetToken(connID),
	})
	m.highestSeq++
	return nil
}

// issuePathConnID issues a connection ID for the QUIC multipath path pid and
// emits a PATH_NEW_CONNECTION_ID frame (0x3e78) advertising it. It mirrors
// issueNewConnID, but the frame carries pid (NewConnectionIDFrame.PathID) and
// the sequence number is drawn from pid's own per-path sequence space, not the
// connection-level highestSeq. This is the draft-multipath CID-issuance side; it
// must never be called for PathIDZero, whose CIDs flow through issueNewConnID.
//
// Reference: frame.rs:2015-2026 (NewConnectionId::encode writes path_id then
// sequence) and frame.rs:2005-2012 (IssuedCid scoped to path_id). The wire codec
// is new_connection_id_frame.go:84-90.
func (m *connIDGenerator) issuePathConnID(pid protocol.PathID) (protocol.ConnectionID, error) {
	if pid == protocol.PathIDZero {
		return protocol.ConnectionID{}, fmt.Errorf("issuePathConnID called with PathIDZero")
	}
	if m.generator.ConnectionIDLen() == 0 {
		// Zero-length connection IDs: nothing to issue, and the peer addresses
		// us by 4-tuple. Return the zero-length CID without emitting a frame.
		return protocol.ConnectionID{}, nil
	}
	connID, err := m.generator.GenerateConnectionID()
	if err != nil {
		return protocol.ConnectionID{}, err
	}
	if m.pathSrcConnIDs == nil {
		m.pathSrcConnIDs = make(map[protocol.PathID]map[uint64]protocol.ConnectionID)
		m.pathHighestSeq = make(map[protocol.PathID]uint64)
	}
	ids, ok := m.pathSrcConnIDs[pid]
	if !ok {
		ids = make(map[uint64]protocol.ConnectionID)
		m.pathSrcConnIDs[pid] = ids
	}
	seq := m.pathHighestSeq[pid]
	ids[seq] = connID
	m.cidPath[connID] = pid
	m.pathHighestSeq[pid] = seq + 1
	m.connRunners.AddConnectionID(connID)
	pidCopy := pid
	m.queueControlFrame(&wire.NewConnectionIDFrame{
		PathID:              &pidCopy,
		SequenceNumber:      seq,
		ConnectionID:        connID,
		StatelessResetToken: m.statelessResetter.GetStatelessResetToken(connID),
	})
	return connID, nil
}

// pathForLocalConnID reports which multipath PathID one of our issued source
// connection IDs belongs to. The PathIDZero (connection-level) CIDs live in
// activeSrcConnIDs; non-zero path CIDs live in pathSrcConnIDs (issuePathConnID).
// The receive side uses this to attribute an inbound 1-RTT packet (addressed to
// one of our CIDs) to the path it belongs to, so the packet is acked as a
// PATH_ACK{pid}. ok is false for a CID we never issued.
func (m *connIDGenerator) pathForLocalConnID(connID protocol.ConnectionID) (protocol.PathID, bool) {
	pid, ok := m.cidPath[connID]
	return pid, ok
}

func (m *connIDGenerator) SetHandshakeComplete(connIDExpiry monotime.Time) {
	if m.initialClientDestConnID != nil {
		m.queueConnIDForRetiring(*m.initialClientDestConnID, connIDExpiry)
		delete(m.cidPath, *m.initialClientDestConnID)
		m.initialClientDestConnID = nil
	}
}

func (m *connIDGenerator) RemoveRetiredConnIDs(now monotime.Time) {
	if len(m.connIDsToRetire) == 0 {
		return
	}
	for _, c := range m.connIDsToRetire {
		if c.t.After(now) {
			break
		}
		m.connRunners.RemoveConnectionID(c.connID)
		m.connIDsToRetire = m.connIDsToRetire[1:]
	}
}

func (m *connIDGenerator) RemoveAll() {
	if m.initialClientDestConnID != nil {
		m.connRunners.RemoveConnectionID(*m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		m.connRunners.RemoveConnectionID(connID)
	}
	for _, ids := range m.pathSrcConnIDs {
		for _, connID := range ids {
			m.connRunners.RemoveConnectionID(connID)
		}
	}
	for _, c := range m.connIDsToRetire {
		m.connRunners.RemoveConnectionID(c.connID)
	}
}

func (m *connIDGenerator) ReplaceWithClosed(connClose []byte, expiry time.Duration) {
	connIDs := make([]protocol.ConnectionID, 0, len(m.activeSrcConnIDs)+len(m.connIDsToRetire)+1)
	if m.initialClientDestConnID != nil {
		connIDs = append(connIDs, *m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		connIDs = append(connIDs, connID)
	}
	for _, ids := range m.pathSrcConnIDs {
		for _, connID := range ids {
			connIDs = append(connIDs, connID)
		}
	}
	for _, c := range m.connIDsToRetire {
		connIDs = append(connIDs, c.connID)
	}
	m.connRunners.ReplaceWithClosed(connIDs, connClose, expiry)
}

func (m *connIDGenerator) AddConnRunner(runner connRunner, r connRunnerCallbacks) {
	// The transport might have already been added earlier.
	// This happens if the application migrates back to and old path.
	if _, ok := m.connRunners[runner]; ok {
		return
	}
	m.connRunners[runner] = r
	if m.initialClientDestConnID != nil {
		r.AddConnectionID(*m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		r.AddConnectionID(connID)
	}
	for _, ids := range m.pathSrcConnIDs {
		for _, connID := range ids {
			r.AddConnectionID(connID)
		}
	}
}
