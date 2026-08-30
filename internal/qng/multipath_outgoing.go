package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// This file is the X1 Stage 5f send-side multipath orchestration
// (draft-ietf-quic-multipath): opening a second PathID, validating it with a
// PATH_CHALLENGE/PATH_RESPONSE exchange, and scheduling 1-RTT sends over it.
//
// It is deliberately separate from path_manager_outgoing.go, which is the RFC
// 9000 single-path connection-MIGRATION manager (the int64 pathID concept that
// switches the active 4-tuple and discards the old one). Multipath keeps BOTH
// paths alive: PathIDZero never stops carrying data, and a non-zero path is an
// additional, independent number space + congestion controller (5a) addressed
// by its own connection IDs (5c). Nothing here touches pathManagerOutgoing.
//
// Threading: every field of multipathOutgoing is owned by the connection's run
// goroutine. The sentPacketHandler / receivedPacketHandler / connIDGenerator
// have no locks and are read by the packer on every 1-RTT packet, so opening a
// path from an application goroutine would race them (confirmed with -race).
// Conn.OpenPath therefore only enqueues an openPathRequest; the run loop
// performs the actual provisioning in processOpenPathRequests.

// ErrPathLimit is returned by OpenPath when the peer has not yet advertised a
// large enough MAX_PATH_ID, or when the requested path would exceed the local
// limit. The condition can be transient immediately after handshake completion,
// while the peer's MAX_PATH_ID frame is still in flight.
var ErrPathLimit = errors.New("quic: path limit prevents opening path")

// pathOpenState tracks the local lifecycle of one non-zero multipath PathID.
// It mirrors the recovery-irrelevant subset of reference/paths.rs that the
// initiator drives: sending PATH_CHALLENGEs (on_path_challenges_unconfirmed,
// paths.rs:185) until a PATH_RESPONSE validates the path (validated,
// paths.rs:200), then reporting it (open_status, paths.rs:273).
type pathOpenState struct {
	id protocol.PathID

	// challenges holds the PATH_CHALLENGE tokens we have sent on this path and
	// not yet seen validated. A PATH_RESPONSE carrying any of them validates the
	// path (paths.rs:497-527: a response to any sent challenge validates).
	challenges [][8]byte

	// challengeSent is set once we have emitted at least one PATH_CHALLENGE, so
	// driveMultipath does not re-send on every run-loop iteration.
	challengeSent bool

	// validated is set when a matching PATH_RESPONSE has been received. Until
	// then the path carries only its PATH_CHALLENGE; application data waits for
	// validation (RFC 9000 §8: do not send non-probing data on an unvalidated
	// path). It corresponds to PathData::validated (paths.rs:200).
	validated bool

	// validatedChan is closed when validated flips to true, so Conn.OpenPath
	// (running on the application goroutine) can block until the run loop
	// reports the path usable.
	validatedChan chan struct{}

	// pendingResponses holds PATH_RESPONSE tokens we owe the peer for
	// PATH_CHALLENGEs it sent on this path. driveMultipath flushes them.
	pendingResponses [][8]byte

	// sendData is the per-path application send queue: DATAGRAM payloads the
	// application asked to send specifically over this path
	// (MultipathPath.SendDatagram). Keeping it per-path (rather than reusing the
	// connection datagram queue) is what makes "this datagram rode path N"
	// deterministic, and leaves the path-0 send loop byte-identical. It is
	// drained only in the run goroutine.
	sendData [][]byte

	// qntRoute is the validated remote address for a QNT-opened path. Packets
	// for this path are sent to this address instead of the connection's
	// original remote address.
	qntRoute netip.AddrPort
	// qntUDPAddr is the allocation-bearing net representation of qntRoute. The
	// route is immutable after path creation, so convert it once rather than on
	// every pass through the send loop.
	qntUDPAddr *net.UDPAddr

	// cidBlockedSent is set after we ask the peer for a path connection ID.
	cidBlockedSent bool
}

// openPathRequest is the command Conn.OpenPath hands to the run goroutine. The
// run loop fills in result/err and closes done.
type openPathRequest struct {
	pid  protocol.PathID
	done chan struct{}
	err  error
	path *MultipathPath
}

// multipathOutgoing is the run-goroutine-owned send-side multipath state.
type multipathOutgoing struct {
	paths map[protocol.PathID]*pathOpenState
	// nextPathID is the PathID to assign to the next opened path. PathIDZero is
	// the always-present initial path, so non-zero paths start at 1.
	nextPathID protocol.PathID
	// migratedRemote is the direct route the ordinary (path-0) send conn has been
	// migrated onto after a QNT route was validated+selected. Zero until the first
	// migration; guards processQNTValidatedPathOpen against re-migrating every
	// round. Ordinary stream frames egress here, not the relay-mapped remote.
	migratedRemote netip.AddrPort
	// premigrationRemote is the ordinary send remote captured before the first
	// QNT migration. For the relay-first path this is the relay-mapped address;
	// for direct-first dials Endpoint may seed a relay fallback explicitly.
	premigrationRemote net.Addr
	// revertedRoute / revertedRouteUntil impose a cooldown on re-migrating to
	// a route that was recently reverted. A fresh QNT validation is evidence a
	// route came back (the challenge round-tripped on the exact 4-tuple), but
	// validated candidates from the same round can arrive seconds apart, and
	// re-migrating into a link that is still flapping would churn the
	// connection through repeated congestion resets. After the cooldown a
	// freshly validated route is trusted again, so a transient flap does not
	// forfeit the direct path for the connection's lifetime.
	revertedRoute      netip.AddrPort
	revertedRouteUntil monotime.Time
}

// qntRemigrationCooldown is how long after a revert a reverted route is
// refused re-migration. QNT re-validates routes on the holepunch upgrade
// cadence, so one cooldown window typically spans a full validation round.
const qntRemigrationCooldown = 30 * time.Second

func newMultipathOutgoing() *multipathOutgoing {
	return &multipathOutgoing{
		paths:      make(map[protocol.PathID]*pathOpenState),
		nextPathID: 1,
	}
}

// queuePathResponse records a PATH_RESPONSE owed on path pid. The path may not
// be provisioned yet if this is racing the lazy join; the response is dropped
// in that case, and the peer will re-send its PATH_CHALLENGE.
func (m *multipathOutgoing) queuePathResponse(pid protocol.PathID, data [8]byte) {
	st, ok := m.paths[pid]
	if !ok {
		return
	}
	st.pendingResponses = append(st.pendingResponses, data)
}

// MultipathPath is the application handle to a non-zero multipath PathID. It is
// returned by Conn.OpenPath. Validated blocks until the path completes its
// PATH_CHALLENGE/PATH_RESPONSE validation, at which point 1-RTT packets
// (including application data) are scheduled over it by the run loop.
type MultipathPath struct {
	conn      *Conn
	id        protocol.PathID
	validated chan struct{}
}

// PathID returns the draft-multipath PathID of this path.
func (p *MultipathPath) PathID() protocol.PathID { return p.id }

// Validated blocks until the path has been validated (a PATH_RESPONSE to our
// PATH_CHALLENGE arrived) or ctx is done / the connection closed.
func (p *MultipathPath) Validated(ctx context.Context) error {
	select {
	case <-p.validated:
		return nil
	case <-p.conn.ctx.Done():
		return context.Cause(p.conn.ctx)
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// OpenPath opens a second QUIC multipath path (draft-ietf-quic-multipath) over
// the connection's existing socket, distinguished from PathIDZero by its own
// connection IDs rather than its 4-tuple. It is the draft-multipath path-open,
// NOT the RFC 9000 single-path migration AddPath: both paths stay alive.
//
// OpenPath requires multipath to have been negotiated and the handshake to be
// confirmed (PATH_NEW_CONNECTION_ID / PATH_CHALLENGE are 1-RTT-only). It hands
// the request to the run goroutine, which provisions the per-path send/recv
// state, issues a path connection ID, and begins the PATH_CHALLENGE validation.
// The returned MultipathPath.Validated blocks until the path is usable.
//
// tr is accepted for API parity with AddPath and future multi-socket paths; in
// this build the second path shares the connection's socket (the peer demuxes
// by connection ID), so tr may be nil.
func (c *Conn) OpenPath(tr *Transport) (*MultipathPath, error) {
	if !c.multipathNegotiated() {
		return nil, errors.New("quic: multipath not negotiated")
	}
	req := &openPathRequest{done: make(chan struct{})}
	select {
	case c.openPathQueue <- req:
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
	c.scheduleSending()
	select {
	case <-req.done:
		return req.path, req.err
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

// PathAcksReceived returns the number of PATH_ACK / PATH_ACK_ECN frames this
// connection has received for its non-zero multipath paths. It is safe to call
// from any goroutine and is used to confirm a second path's packets were
// acknowledged (driving that path's bytes-in-flight down).
func (c *Conn) PathAcksReceived() uint64 { return c.pathAcksReceived.Load() }

// LastPathAckID returns the PathID carried by the most recently received
// PATH_ACK / PATH_ACK_ECN frame and whether any such frame has been received.
// It lets a test confirm an acknowledgement arrived for a specific non-zero
// path. It is safe to call from any goroutine.
func (c *Conn) LastPathAckID() (protocol.PathID, bool) {
	v := c.lastPathAckID.Load()
	if v == 0 {
		return protocol.PathIDZero, false
	}
	return protocol.PathID(v - 1), true
}

// pathStatsRequest is the command Conn.PathStats hands to the run goroutine,
// which fills in stats/ok and closes done.
type pathStatsRequest struct {
	pid   protocol.PathID
	stats ackhandler.PathDebugStats
	ok    bool
	done  chan struct{}
}

// PathStats returns the live application-data recovery snapshot for the
// multipath PathID pid (its own number space + congestion controller). It is a
// test-support hook: the query runs on the connection's run goroutine — the
// only goroutine permitted to read the lock-free sentPacketHandler — so it is
// race-free. ok is false if pid is not an open path or the connection closed.
func (c *Conn) PathStats(pid protocol.PathID) (ackhandler.PathDebugStats, bool) {
	req := &pathStatsRequest{pid: pid, done: make(chan struct{})}
	select {
	case c.pathStatsQueue <- req:
	case <-c.ctx.Done():
		return ackhandler.PathDebugStats{}, false
	}
	c.scheduleSending()
	select {
	case <-req.done:
		return req.stats, req.ok
	case <-c.ctx.Done():
		return ackhandler.PathDebugStats{}, false
	}
}

// PathInfo is a snapshot of one qng multipath path's application-facing state.
//
// Path 0 is the initial path and is not listed here. The entries returned by
// [Conn.Paths] are real qng non-zero paths provisioned by OpenPath or by a peer
// packet that caused lazy path join. RemoteAddr is set only when qng has an
// address that actually routes the path, currently for QNT-opened paths.
type PathInfo struct {
	// ID is the QUIC multipath PathID.
	ID protocol.PathID
	// Validated reports whether the path completed PATH_CHALLENGE /
	// PATH_RESPONSE validation and can carry non-probing application data.
	Validated bool
	// RemoteAddr is the remote UDP route for this path, when known.
	RemoteAddr netip.AddrPort
	// SmoothedRTT is the path's application-data RTT estimate, when HasRTT is
	// true.
	SmoothedRTT time.Duration
	// HasRTT reports whether SmoothedRTT was observed for this path.
	HasRTT bool
	// BytesInFlight is the path's current application-data bytes in flight,
	// when HasBytesInFlight is true.
	BytesInFlight protocol.ByteCount
	// HasBytesInFlight reports whether BytesInFlight was observed for this path.
	HasBytesInFlight bool
	// BytesSent is the cumulative 1-RTT/0-RTT application-data packet
	// bytes sent on this path, when HasBytesSent is true. It excludes
	// Initial/Handshake packets and UDP framing overhead.
	BytesSent uint64
	// HasBytesSent reports whether BytesSent was observed for this path.
	HasBytesSent bool
	// BytesReceived is the cumulative 1-RTT/0-RTT application-data packet
	// bytes received on this path, when HasBytesReceived is true. It excludes
	// Initial/Handshake packets and UDP framing overhead.
	BytesReceived uint64
	// HasBytesReceived reports whether BytesReceived was observed for this path.
	HasBytesReceived bool
	// CongestionWindow is the path's current congestion window, when
	// HasCongestionWindow is true.
	CongestionWindow protocol.ByteCount
	// HasCongestionWindow reports whether CongestionWindow was observed for this
	// path.
	HasCongestionWindow bool
	// LostPackets is the number of application-data packets declared lost on
	// this path, when HasLoss is true.
	LostPackets uint64
	// LostBytes is the number of application-data bytes declared lost on this
	// path, when HasLoss is true.
	LostBytes uint64
	// HasLoss reports whether LostPackets and LostBytes were observed for this
	// path.
	HasLoss bool
}

// pathSnapshotRequest is the command Conn.Paths hands to the run goroutine,
// which fills in paths and closes done.
type pathSnapshotRequest struct {
	performance performanceSnapshotRequest
	paths       []PathInfo
	done        chan struct{}
}

// Paths returns a snapshot of this connection's non-zero qng multipath paths.
// The query runs on the connection's run goroutine because the path-open state
// is owned there. It returns nil if no non-zero path has been opened or the
// connection is closed.
func (c *Conn) Paths() []PathInfo {
	req := &pathSnapshotRequest{done: make(chan struct{})}
	select {
	case c.pathSnapshotQueue <- req:
	case <-c.ctx.Done():
		return nil
	}
	c.scheduleSending()
	select {
	case <-req.done:
		return req.paths
	case <-c.ctx.Done():
		return nil
	}
}

// SetMigrationFallbackRemote records a fallback remote for QNT active
// migration. It is used when the connection was established directly but the
// caller also knows a relay route for the peer.
func (c *Conn) SetMigrationFallbackRemote(addr net.Addr) {
	if addr == nil {
		return
	}
	req := &setMigrationFallbackRequest{addr: addr, done: make(chan struct{})}
	select {
	case c.setMigrationFallbackQueue <- req:
	case <-c.ctx.Done():
		return
	}
	c.scheduleSending()
	select {
	case <-req.done:
	case <-c.ctx.Done():
	}
}

type setMigrationFallbackRequest struct {
	addr net.Addr
	done chan struct{}
}

func (c *Conn) processSetMigrationFallbackRequests() {
	for {
		select {
		case req := <-c.setMigrationFallbackQueue:
			if c.multipathOut == nil {
				c.multipathOut = newMultipathOutgoing()
			}
			if c.multipathOut.premigrationRemote == nil ||
				(c.conn != nil && addrsEqual(c.multipathOut.premigrationRemote, c.conn.RemoteAddr())) {
				c.multipathOut.premigrationRemote = req.addr
			}
			close(req.done)
		default:
			return
		}
	}
}

// processPathSnapshotRequests answers pending Paths queries. Run goroutine
// only (called from the run loop), so reading multipathOut is safe.
func (c *Conn) processPathSnapshotRequests() {
	for {
		select {
		case req := <-c.pathSnapshotQueue:
			req.performance.fill(&c.performance)
			if c.multipathOut != nil && len(c.multipathOut.paths) > 0 {
				req.paths = make([]PathInfo, 0, len(c.multipathOut.paths))
				for pid, st := range c.multipathOut.paths {
					info := PathInfo{
						ID:         pid,
						Validated:  st.validated,
						RemoteAddr: st.qntRoute,
					}
					if stats, ok := c.sentPacketHandler.PathDebugStats(pid); ok {
						if stats.HasRTT {
							info.SmoothedRTT = stats.SmoothedRTT
							info.HasRTT = true
						}
						info.BytesInFlight = stats.BytesInFlight
						info.HasBytesInFlight = true
						info.BytesSent = stats.BytesSent
						info.HasBytesSent = true
						info.BytesReceived = stats.BytesReceived
						info.HasBytesReceived = true
						info.CongestionWindow = stats.CongestionWindow
						info.HasCongestionWindow = true
						info.LostPackets = stats.LostPackets
						info.LostBytes = stats.LostBytes
						info.HasLoss = true
					}
					req.paths = append(req.paths, info)
				}
				sort.Slice(req.paths, func(i, j int) bool {
					return req.paths[i].ID < req.paths[j].ID
				})
			}
			close(req.done)
		default:
			return
		}
	}
}

// processPathStatsRequests answers pending PathStats queries. Run goroutine
// only (called from the run loop), so reading the sentPacketHandler is safe.
func (c *Conn) processPathStatsRequests() {
	for {
		select {
		case req := <-c.pathStatsQueue:
			req.stats, req.ok = c.sentPacketHandler.PathDebugStats(req.pid)
			close(req.done)
		default:
			return
		}
	}
}

// processOpenPathRequests drains pending OpenPath requests. It runs in the run
// goroutine, so it can safely provision the (unlocked) sentPacketHandler /
// receivedPacketHandler / connIDGenerator state for the new path.
func (c *Conn) processOpenPathRequests() error {
	for {
		select {
		case req := <-c.openPathQueue:
			req.path, req.err = c.openPathLocked()
			close(req.done)
		default:
			return nil
		}
	}
}

// processQNTValidatedPathOpen consumes at most one validated QNT candidate and
// provisions a route-bearing multipath path for it. Run goroutine only.
//
// A QNT route provisioned here carries per-path DATAGRAM sends, but ordinary
// QUIC stream frames egress through the connection's path-0 send conn, which
// still targets the relay-mapped remote set at establishment. On the client,
// once a direct route is validated+selected we also migrate the ordinary send
// conn onto it (RFC 9000 §9 connection migration): change the send remote to
// the direct 4-tuple and reset MTU for the new path. This makes stream payload
// follow the selected direct path instead of staying on relay. The server then
// observes app data on the direct path and completes its existing passive
// migration.
func (c *Conn) processQNTValidatedPathOpen(now monotime.Time) error {
	_, route, ok, err := c.qntOpenValidatedPathLocked()
	if errors.Is(err, ErrPathLimit) {
		return nil
	}
	if err != nil {
		return err
	}
	if ok && c.perspective == protocol.PerspectiveClient {
		c.migrateOrdinarySendToQNTRoute(route, now)
		c.scheduleSending()
	}
	return nil
}

// migrateOrdinarySendToQNTRoute points the connection's path-0 send conn at a
// validated direct route so ordinary stream frames egress there. It mirrors the
// server-side passive-migration block (handlePathChallenge) and runs at most
// once per route, in the run goroutine.
func (c *Conn) migrateOrdinarySendToQNTRoute(route netip.AddrPort, now monotime.Time) {
	// Migrating the ordinary send conn touches the send-side recovery state and
	// the live send conn, which only exist once the handshake is confirmed. The
	// same gate guards driveMultipath. A QNT route only validates well after the
	// handshake in practice, so this never skips a real migration.
	if !c.handshakeConfirmed || c.conn == nil {
		return
	}
	if !route.IsValid() || route.Port() == 0 {
		return
	}
	if m := c.multipathOut; m != nil {
		if m.migratedRemote == route ||
			(m.revertedRoute == route && now.Before(m.revertedRouteUntil)) {
			return
		}
	}
	initialPacketSize := protocol.ByteCount(c.config.InitialPacketSize)
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if params := c.peerParams.Load(); params.MaxUDPPayloadSize > 0 && params.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = params.MaxUDPPayloadSize
	}
	c.sentPacketHandler.MigratedPath(now, initialPacketSize)
	c.currentMTUEstimate.Store(uint32(estimateMaxPayloadSize(initialPacketSize)))
	c.mtuDiscoverer.Reset(now, initialPacketSize, maxPacketSize)
	if c.multipathOut != nil && c.multipathOut.premigrationRemote == nil {
		c.multipathOut.premigrationRemote = c.conn.RemoteAddr()
	}
	c.conn.ChangeRemoteAddr(net.UDPAddrFromAddrPort(route), packetInfo{})
	// Send one ordinary non-probing frame on the migrated direct remote before
	// application streams depend on it. The peer's existing RFC 9000 passive
	// migration path switches its return address only after observing non-probing
	// traffic on the new 4-tuple.
	c.framer.QueueControlFrame(&wire.PingFrame{})
	if c.multipathOut != nil {
		c.multipathOut.migratedRemote = route
	}
}

func (c *Conn) maybeRevertQNTMigrationOnPTO(now monotime.Time) {
	const revertPTOThreshold = 3
	m := c.multipathOut
	if m == nil || !m.migratedRemote.IsValid() || m.premigrationRemote == nil {
		return
	}
	if c.sentPacketHandler.PTOCount() < revertPTOThreshold {
		return
	}
	c.revertQNTMigration(now)
}

func (c *Conn) maybeRevertQNTMigrationOnIdle(now monotime.Time) {
	deadline := c.qntMigrationFallbackDeadline()
	if deadline.IsZero() || now.Before(deadline) {
		return
	}
	c.revertQNTMigration(now)
}

func (c *Conn) qntMigrationFallbackDeadline() monotime.Time {
	m := c.multipathOut
	if m == nil || !m.migratedRemote.IsValid() || m.premigrationRemote == nil {
		return 0
	}
	threshold := max(5*time.Second, c.rttStats.PTO(true)*3)
	return c.lastPacketReceivedTime.Add(threshold)
}

func (c *Conn) revertQNTMigration(now monotime.Time) {
	m := c.multipathOut
	if m == nil || !m.migratedRemote.IsValid() || m.premigrationRemote == nil {
		return
	}
	initialPacketSize := protocol.ByteCount(c.config.InitialPacketSize)
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if params := c.peerParams.Load(); params.MaxUDPPayloadSize > 0 && params.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = params.MaxUDPPayloadSize
	}
	c.sentPacketHandler.MigratedPath(now, initialPacketSize)
	c.currentMTUEstimate.Store(uint32(estimateMaxPayloadSize(initialPacketSize)))
	c.mtuDiscoverer.Reset(now, initialPacketSize, maxPacketSize)
	c.conn.ChangeRemoteAddr(m.premigrationRemote, packetInfo{})
	m.revertedRoute = m.migratedRemote
	m.revertedRouteUntil = now.Add(qntRemigrationCooldown)
	m.migratedRemote = netip.AddrPort{}
	c.scheduleSending()
}

// openPathLocked provisions a new non-zero path. Invariant: run goroutine only.
func (c *Conn) openPathLocked() (*MultipathPath, error) {
	if c.multipathOut == nil {
		c.multipathOut = newMultipathOutgoing()
	}
	pid := c.multipathOut.nextPathID
	if !c.canOpenPath(pid) {
		return nil, fmt.Errorf("%w: path %d peer max path id not raised that far", ErrPathLimit, pid)
	}
	c.multipathOut.nextPathID++

	if err := c.allocatePathLocked(pid); err != nil {
		return nil, err
	}

	st := &pathOpenState{id: pid, validatedChan: make(chan struct{})}
	c.multipathOut.paths[pid] = st
	c.scheduleSending() // wake the loop to send the first PATH_CHALLENGE
	return &MultipathPath{conn: c, id: pid, validated: st.validatedChan}, nil
}

func (c *Conn) qntOpenValidatedPathLocked() (protocol.PathID, netip.AddrPort, bool, error) {
	if _, ok := c.qntPeekValidatedProbe(); !ok {
		return protocol.PathIDZero, netip.AddrPort{}, false, nil
	}
	if c.multipathOut == nil {
		c.multipathOut = newMultipathOutgoing()
	}
	pid := c.multipathOut.nextPathID
	if !c.canOpenPath(pid) {
		return protocol.PathIDZero, netip.AddrPort{}, false, fmt.Errorf("%w: path %d peer max path id not raised that far", ErrPathLimit, pid)
	}
	if err := c.allocatePathLocked(pid); err != nil {
		return protocol.PathIDZero, netip.AddrPort{}, false, err
	}
	route, ok := c.qntPopValidatedProbe()
	if !ok {
		return protocol.PathIDZero, netip.AddrPort{}, false, nil
	}
	c.multipathOut.nextPathID++
	st := &pathOpenState{
		id:            pid,
		validated:     true,
		validatedChan: make(chan struct{}),
		qntRoute:      route,
		qntUDPAddr:    qntProbeUDPAddr(route),
	}
	close(st.validatedChan)
	c.multipathOut.paths[pid] = st
	return pid, route, true, nil
}

func (c *Conn) allocatePathLocked(pid protocol.PathID) error {
	// Per-path send + receive recovery state (5a / 5e). Each gets its own
	// independent packet-number space.
	if err := c.sentPacketHandler.AddPath(pid); err != nil {
		return fmt.Errorf("quic: add send path %d: %w", pid, err)
	}
	if err := c.receivedPacketHandler.AddPath(pid, c.logger); err != nil {
		c.sentPacketHandler.RemovePath(pid)
		return fmt.Errorf("quic: add recv path %d: %w", pid, err)
	}
	// Top up our connection IDs for this path (5c), so the peer can address
	// packets to it; a no-op when IssueFirstPathCIDs already filled the pool.
	// Queues PATH_NEW_CONNECTION_ID (0x3e78) frames on path 0.
	if err := c.connIDGenerator.ensurePathCIDs(pid); err != nil {
		c.receivedPacketHandler.RemovePath(pid)
		c.sentPacketHandler.RemovePath(pid)
		return fmt.Errorf("quic: issue path %d connection id: %w", pid, err)
	}
	return nil
}

// driveMultipath performs the per-path send work for every open non-zero path.
// It runs in the run goroutine after the ordinary path-0 send. For each path it
// either (a) sends a PATH_CHALLENGE if the path is still unvalidated and we have
// its DCID, or (b) packs a 1-RTT packet (PATH_ACK + any pending data) once the
// path is validated. It returns after sending at most one datagram per path so
// the run loop keeps cycling through receives.
func (c *Conn) driveMultipath(now monotime.Time) error {
	if c.multipathOut == nil || !c.handshakeConfirmed {
		return nil
	}
	for pid, st := range c.multipathOut.paths {
		connID, ok := c.destConnIDForPath(pid)
		if !ok {
			// The peer has not issued a PATH_NEW_CONNECTION_ID for this path yet;
			// ask once and try again after it responds.
			if !st.cidBlockedSent {
				c.queueControlFrame(&wire.PathCIDsBlockedFrame{PathID: pid, NextSeq: 0})
				st.cidBlockedSent = true
			}
			continue
		}
		// Flush any PATH_RESPONSEs we owe on this path first, so the peer can
		// validate it promptly.
		if len(st.pendingResponses) > 0 {
			frames := make([]ackhandler.Frame, 0, len(st.pendingResponses))
			for _, tok := range st.pendingResponses {
				frames = append(frames, ackhandler.Frame{Frame: &wire.PathResponseFrame{Data: tok}})
			}
			st.pendingResponses = nil
			if err := c.sendPathPacket(pid, connID, st, frames, now); err != nil {
				return err
			}
		}
		if !st.validated {
			if err := c.sendPathChallenge(pid, connID, st, now); err != nil {
				return err
			}
			continue
		}
		if err := c.sendOnPath(pid, st, now); err != nil {
			return err
		}
	}
	return nil
}

// pathDatagram is a DATAGRAM payload destined for a specific multipath PathID,
// carried from MultipathPath.SendDatagram into the run goroutine.
type pathDatagram struct {
	pid  protocol.PathID
	data []byte
}

// SendDatagram queues a DATAGRAM to be sent specifically over this multipath
// path. The datagram is delivered to the peer's ordinary datagram receive queue
// (DATAGRAM frames are not path-scoped on the wire), but it is guaranteed to
// ride a 1-RTT packet addressed to this path's connection ID and drawn from this
// path's packet-number space — which is what makes it observable as "data over
// PathID n".
func (p *MultipathPath) SendDatagram(b []byte) error {
	return p.conn.SendDatagramOnPath(p.id, b)
}

// SendDatagramOnPath queues a DATAGRAM to be sent over the multipath PathID pid.
// It is the thread-safe entry point both the OpenPath initiator
// (MultipathPath.SendDatagram) and the lazily-joined peer use to put data on a
// non-zero path: it only touches pathDatagramQueue (a channel), never the
// run-goroutine-owned multipathOut, so it is safe to call from any goroutine.
// The run loop drops the datagram if pid is not an open path.
func (c *Conn) SendDatagramOnPath(pid protocol.PathID, b []byte) error {
	if pid == protocol.PathIDZero {
		return errors.New("quic: SendDatagramOnPath requires a non-zero path id")
	}
	data := make([]byte, len(b))
	copy(data, b)
	select {
	case c.pathDatagramQueue <- pathDatagram{pid: pid, data: data}:
		c.scheduleSending()
		return nil
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	}
}

// drainPathDatagrams moves queued per-path DATAGRAM sends into their path's send
// queue. Run goroutine only (called from the run loop alongside
// processOpenPathRequests).
func (c *Conn) drainPathDatagrams() {
	if c.multipathOut == nil {
		return
	}
	for {
		select {
		case d := <-c.pathDatagramQueue:
			if st, ok := c.multipathOut.paths[d.pid]; ok {
				st.sendData = append(st.sendData, d.data)
			}
		default:
			return
		}
	}
}

// sendPathChallenge emits a PATH_CHALLENGE on path pid (addressed to the peer's
// pid DCID), recording its token for later validation. It mirrors
// PathData::record_path_challenge_sent (paths.rs:436-447). It sends at most one
// challenge per path until a response arrives or the path is re-armed.
func (c *Conn) sendPathChallenge(pid protocol.PathID, connID protocol.ConnectionID, st *pathOpenState, now monotime.Time) error {
	if st.challengeSent {
		return nil
	}
	mode := c.sentPacketHandler.SendModeForPath(now, pid)
	if mode != ackhandler.SendAny && mode != ackhandler.SendAck {
		return nil
	}
	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	st.challenges = append(st.challenges, token)
	st.challengeSent = true
	frame := ackhandler.Frame{Frame: &wire.PathChallengeFrame{Data: token}}
	return c.sendPathPacket(pid, connID, st, []ackhandler.Frame{frame}, now)
}

// sendOnPath packs and sends one 1-RTT packet targeting the validated path pid:
// a PATH_ACK{pid} for what we received plus that path's pending DATAGRAM
// payloads (its own send queue). It is a no-op (no datagram sent) when there is
// nothing to pack. Application data riding pid carries its bytes-in-flight on
// pid's own controller, so it is driven down by the peer's PATH_ACK{pid}.
func (c *Conn) sendOnPath(pid protocol.PathID, st *pathOpenState, now monotime.Time) error {
	if hasInvalidQNTRoute(st) {
		return nil
	}
	if c.pathSendQueueBlocked(st) {
		return nil
	}
	mode := c.sentPacketHandler.SendModeForPath(now, pid)
	if mode != ackhandler.SendAny && mode != ackhandler.SendAck {
		return nil
	}
	// Only feed application datagrams once the congestion controller permits new
	// data; on SendAck we still emit the PATH_ACK but hold the data.
	var datagrams [][]byte
	if mode == ackhandler.SendAny {
		datagrams = st.sendData
	}
	buf := getPacketBuffer()
	ecn := c.multipathECNMode()
	p, packed, err := c.packer.AppendPacketForPath(buf, pid, datagrams, c.maxPacketSize(), now, c.version)
	if err != nil {
		buf.Release()
		if err == errNothingToPack {
			return nil
		}
		return err
	}
	// Drop exactly the datagrams that were packed into this packet; any that did
	// not fit stay queued for the next packet.
	if packed > 0 {
		st.sendData = st.sendData[packed:]
		if len(st.sendData) == 0 {
			st.sendData = nil
		}
	}
	c.logShortHeaderPacket(p, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(p, ecn, now)
	c.sendPathBuffer(buf, ecn, st)
	// If there is more queued data on this path, keep the loop cycling.
	if len(st.sendData) > 0 {
		c.scheduleSending()
	}
	return nil
}

// sendPathPacket packs the given frames into a single 1-RTT packet on path pid
// (its DCID + its packet number) and sends it. Used for PATH_CHALLENGE, which
// must not be coalesced with path-0 data because it has to ride the new path's
// connection ID so the peer attributes the validation to pid.
func (c *Conn) sendPathPacket(pid protocol.PathID, connID protocol.ConnectionID, st *pathOpenState, frames []ackhandler.Frame, now monotime.Time) error {
	if hasInvalidQNTRoute(st) {
		return nil
	}
	if c.pathSendQueueBlocked(st) {
		return nil
	}
	buf := getPacketBuffer()
	ecn := c.multipathECNMode()
	p, err := c.packer.PackPathFramesPacket(buf, pid, connID, frames, c.maxPacketSize(), c.version)
	if err != nil {
		buf.Release()
		return err
	}
	c.logShortHeaderPacket(p, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(p, ecn, now)
	c.sendPathBuffer(buf, ecn, st)
	return nil
}

func (c *Conn) pathSendQueueBlocked(st *pathOpenState) bool {
	if st != nil && st.qntRoute.IsValid() {
		return false
	}
	if c.sendQueue == nil || !c.sendQueue.WouldBlock() {
		return false
	}
	c.scheduleSending()
	return true
}

func (c *Conn) sendPathBuffer(buf *packetBuffer, ecn protocol.ECN, st *pathOpenState) {
	if st != nil && st.qntRoute.IsValid() {
		addr := st.qntUDPAddr
		if addr == nil {
			addr = qntProbeUDPAddr(st.qntRoute)
			st.qntUDPAddr = addr
		}
		if addr == nil {
			buf.Release()
			return
		}
		c.sendQNTProbeBuffer(buf, addr)
		return
	}
	c.sendQueue.Send(buf, 0, ecn)
}

func hasInvalidQNTRoute(st *pathOpenState) bool {
	return st != nil && st.qntRoute.IsValid() && !validQNTProbeAddr(st.qntRoute)
}

func (c *Conn) multipathECNMode() protocol.ECN {
	if !c.conn.capabilities().ECN {
		return protocol.ECNUnsupported
	}
	return protocol.ECNNon
}

// handleMultipathPathResponse checks whether a received PATH_RESPONSE validates
// one of our outstanding multipath PATH_CHALLENGEs. A response to any token we
// sent on a path validates that path (paths.rs:505-527: validates the path the
// challenge was sent on, regardless of the path the response arrived on). It
// reports whether the token matched a multipath challenge. Run goroutine only.
func (c *Conn) handleMultipathPathResponse(f *wire.PathResponseFrame) bool {
	if c.multipathOut == nil {
		return false
	}
	for _, st := range c.multipathOut.paths {
		for _, tok := range st.challenges {
			if tok == f.Data {
				if !st.validated {
					st.validated = true
					st.challenges = nil
					close(st.validatedChan)
					c.scheduleSending() // start sending data on the now-validated path
				}
				return true
			}
		}
	}
	return false
}
