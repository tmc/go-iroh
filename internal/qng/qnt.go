package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// ErrNATTraversalNotNegotiated is returned by n0 QUIC NAT traversal operations
// when the n0_nat_traversal extension has not been negotiated.
var ErrNATTraversalNotNegotiated = errors.New("quic: n0 nat traversal not negotiated")

// ErrNATTraversalNotEnoughAddresses is returned when QNT is negotiated but a
// traversal round cannot start because either the local candidate set or the
// peer's ADD_ADDRESS set is empty.
var ErrNATTraversalNotEnoughAddresses = errors.New("quic: not enough nat traversal addresses")

// ErrNATTraversalTooManyAddresses is returned when a QNT address set is full.
var ErrNATTraversalTooManyAddresses = errors.New("quic: too many nat traversal addresses")

// NATTraversalCandidate is a local address the application believes is worth
// advertising to the peer for n0 QUIC NAT traversal. qng owns address-family
// canonicalization before any address is put on the wire.
type NATTraversalCandidate struct {
	Addr netip.AddrPort
}

type qntLocalState struct {
	mu                     sync.Mutex
	remoteOnce             sync.Once
	local                  []qntLocalAddress
	nextLocalAddressSeqNo  uint64
	nextRemoteAddressSeqNo uint64
	remote                 *qntRemoteAddressState
	round                  uint64
	pendingReachOut        []*wire.ReachOutFrame
	pendingProbes          []netip.AddrPort
	sentProbes             map[[8]byte]netip.AddrPort
	probeAttempts          map[netip.AddrPort]uint8
	validatedProbes        []netip.AddrPort
	retryAttempt           uint8
	nextRetry              monotime.Time
	// remoteReady is closed once the remote candidate set first becomes
	// non-empty; created lazily under mu.
	remoteReady     chan struct{}
	remoteReadyDone bool
}

func (st *qntLocalState) remoteReadyChLocked() chan struct{} {
	if st.remoteReady == nil {
		st.remoteReady = make(chan struct{})
	}
	return st.remoteReady
}

func (st *qntLocalState) signalRemoteReadyLocked() {
	if st.remoteReadyDone {
		return
	}
	st.remoteReadyDone = true
	close(st.remoteReadyChLocked())
}

type qntLocalAddress struct {
	addr netip.AddrPort
	seq  uint64
}

const qntMaxProbeAttempts = 9

const qntSyntheticRemoteSeqBase = 1 << 62

// AddNATTraversalAddress adds a local QNT candidate address.
func (c *Conn) AddNATTraversalAddress(addr netip.AddrPort) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if slices.ContainsFunc(st.local, func(a qntLocalAddress) bool {
		return a.addr == addr
	}) {
		return nil
	}
	if len(st.local) >= c.qntLocalAddressLimit() {
		return ErrNATTraversalTooManyAddresses
	}
	seq := st.nextLocalAddressSeqNo
	st.nextLocalAddressSeqNo++
	st.local = append(st.local, qntLocalAddress{addr: addr, seq: seq})
	if c.perspective == protocol.PerspectiveServer {
		c.queueLocalAddAddressFrame(seq, addr)
	}
	return nil
}

// RemoveNATTraversalAddress removes a local QNT candidate address.
func (c *Conn) RemoveNATTraversalAddress(addr netip.AddrPort) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	i := slices.IndexFunc(st.local, func(a qntLocalAddress) bool {
		return a.addr == addr
	})
	if i < 0 {
		st.mu.Unlock()
		return nil
	}
	seq := st.local[i].seq
	st.local = slices.Delete(st.local, i, i+1)
	st.mu.Unlock()
	if c.perspective == protocol.PerspectiveServer {
		c.queueLocalRemoveAddressFrame(seq)
	}
	return nil
}

// AddRemoteNATTraversalAddress adds a remote QNT candidate learned from an
// authenticated address source outside the peer's ADD_ADDRESS frames, such as a
// dialed endpoint ticket.
func (c *Conn) AddRemoteNATTraversalAddress(addr netip.AddrPort) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, got := range st.remote.addresses() {
		if got == addr {
			return nil
		}
	}
	if len(st.remote.addrs) >= st.remote.max {
		return ErrNATTraversalTooManyAddresses
	}
	if st.nextRemoteAddressSeqNo == 0 {
		st.nextRemoteAddressSeqNo = qntSyntheticRemoteSeqBase
	}
	seq := st.nextRemoteAddressSeqNo
	st.nextRemoteAddressSeqNo++
	st.remote.addrs[seq] = addr
	st.signalRemoteReadyLocked()
	return nil
}

// InitiateNATTraversalRound starts one client-side QNT round. qng queues
// REACH_OUT frames, owns NAT probe retry scheduling, matches PATH_RESPONSE
// frames, and opens validated four-tuples as multipath paths. The returned
// addresses are informational; qng, not socket, owns probing.
func (c *Conn) InitiateNATTraversalRound(ctx context.Context) ([]netip.AddrPort, error) {
	if !c.qntAPINegotiated() {
		return nil, ErrNATTraversalNotNegotiated
	}
	st := c.qntLocalState()
	st.mu.Lock()
	remote := st.remote.addresses()
	if len(st.local) == 0 || len(remote) == 0 {
		st.mu.Unlock()
		return nil, ErrNATTraversalNotEnoughAddresses
	}
	st.round++
	st.pendingReachOut = st.pendingReachOut[:0]
	st.pendingProbes = append(st.pendingProbes[:0], remote...)
	clear(st.sentProbes)
	st.retryAttempt = 0
	st.nextRetry = 0
	st.probeAttempts = make(map[netip.AddrPort]uint8, len(remote))
	for _, addr := range remote {
		st.probeAttempts[addr] = qntMaxProbeAttempts - 1
	}
	for _, local := range st.local {
		st.pendingReachOut = append(st.pendingReachOut, &wire.ReachOutFrame{
			Round: st.round,
			Addr:  local.addr.Addr(),
			Port:  local.addr.Port(),
		})
	}
	st.mu.Unlock()
	c.qntQueuePendingReachOutFrames()
	return remote, nil
}

// NATTraversalRemoteAddrsReady returns a channel closed once this connection
// first knows a remote NAT traversal candidate (peer ADD_ADDRESS frame or
// [Conn.AddRemoteNATTraversalAddress]) — the earliest moment a QNT round can
// start. It never closes when no candidate ever arrives, e.g. on the server
// side of QNT, which receives no ADD_ADDRESS.
func (c *Conn) NATTraversalRemoteAddrsReady() <-chan struct{} {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.remoteReadyChLocked()
}

// NATTraversalAddresses returns the remote ADD_ADDRESS set known to qng.
func (c *Conn) NATTraversalAddresses() ([]netip.AddrPort, error) {
	if !c.qntAPINegotiated() {
		return nil, ErrNATTraversalNotNegotiated
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.remote.addresses(), nil
}

func (c *Conn) qntLocalState() *qntLocalState {
	c.qnt.remoteOnce.Do(func() {
		c.qnt.remote = newQNTRemoteAddressState(c.qntRemoteAddressLimit())
	})
	return &c.qnt
}

func (c *Conn) qntLocalNATTraversalAddresses() []netip.AddrPort {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	addrs := make([]netip.AddrPort, 0, len(st.local))
	for _, a := range st.local {
		addrs = append(addrs, a.addr)
	}
	return addrs
}

func (c *Conn) qntPendingReachOutFrames() []*wire.ReachOutFrame {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return cloneReachOutFrames(st.pendingReachOut)
}

func (c *Conn) qntQueuePendingReachOutFrames() bool {
	if c.framer == nil {
		return false
	}
	st := c.qntLocalState()
	st.mu.Lock()
	frames := cloneReachOutFrames(st.pendingReachOut)
	st.pendingReachOut = st.pendingReachOut[:0]
	st.mu.Unlock()
	for _, frame := range frames {
		if frame != nil {
			c.queueControlFrame(frame)
		}
	}
	return len(frames) > 0
}

func (c *Conn) qntPendingProbeAddresses() []netip.AddrPort {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return slices.Clone(st.pendingProbes)
}

func qntProbeUDPAddr(addr netip.AddrPort) *net.UDPAddr {
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() || addr.Port() == 0 {
		return nil
	}
	return net.UDPAddrFromAddrPort(addr)
}

func (c *Conn) qntRecordSentProbe(challenge [8]byte, remote netip.AddrPort) {
	remote = canonicalNATTraversalAddr(remote)
	if !remote.IsValid() {
		return
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sentProbes == nil {
		st.sentProbes = make(map[[8]byte]netip.AddrPort)
	}
	st.sentProbes[challenge] = remote
}

func (c *Conn) qntNextProbeFrame() (netip.AddrPort, ackhandler.Frame, bool, error) {
	st := c.qntLocalState()
	st.mu.Lock()
	empty := len(st.pendingProbes) == 0
	st.mu.Unlock()
	if empty {
		return netip.AddrPort{}, ackhandler.Frame{}, false, nil
	}

	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return netip.AddrPort{}, ackhandler.Frame{}, false, err
	}
	remote, frame, ok := c.qntPopPendingProbe(challenge)
	if !ok {
		return netip.AddrPort{}, ackhandler.Frame{}, false, nil
	}
	return remote, ackhandler.Frame{Frame: frame}, true, nil
}

func (c *Conn) qntPopPendingProbe(challenge [8]byte) (netip.AddrPort, *wire.PathChallengeFrame, bool) {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.pendingProbes) == 0 {
		return netip.AddrPort{}, nil, false
	}
	remote := st.pendingProbes[0]
	st.pendingProbes = st.pendingProbes[1:]
	remote = canonicalNATTraversalAddr(remote)
	if !remote.IsValid() || remote.Port() == 0 {
		return netip.AddrPort{}, nil, false
	}
	if st.sentProbes == nil {
		st.sentProbes = make(map[[8]byte]netip.AddrPort)
	}
	st.sentProbes[challenge] = remote
	return remote, &wire.PathChallengeFrame{Data: challenge}, true
}

func (c *Conn) qntPackNextProbe(connID protocol.ConnectionID, v protocol.Version) (netip.AddrPort, shortHeaderPacket, *packetBuffer, bool, error) {
	if c.packer == nil {
		return netip.AddrPort{}, shortHeaderPacket{}, nil, false, nil
	}
	remote, frame, ok, err := c.qntNextProbeFrame()
	if err != nil || !ok {
		return netip.AddrPort{}, shortHeaderPacket{}, nil, false, err
	}
	if qntProbeUDPAddr(remote) == nil {
		return netip.AddrPort{}, shortHeaderPacket{}, nil, false, nil
	}
	packet, buf, err := c.packer.PackPathProbePacket(connID, []ackhandler.Frame{frame}, v)
	if err != nil {
		return netip.AddrPort{}, shortHeaderPacket{}, nil, false, err
	}
	return remote, packet, buf, true, nil
}

func (c *Conn) qntConsumePathResponse(frame *wire.PathResponseFrame, source netip.AddrPort) (netip.AddrPort, bool) {
	if frame == nil {
		return netip.AddrPort{}, false
	}
	source = canonicalNATTraversalAddr(source)
	if !source.IsValid() {
		return netip.AddrPort{}, false
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	remote, ok := st.sentProbes[frame.Data]
	if !ok || remote != source {
		return netip.AddrPort{}, false
	}
	delete(st.sentProbes, frame.Data)
	delete(st.probeAttempts, remote)
	st.pendingProbes = slices.DeleteFunc(st.pendingProbes, func(addr netip.AddrPort) bool {
		return addr == remote
	})
	if !qntHasRetryableProbeLocked(st) {
		st.nextRetry = 0
	}
	return remote, true
}

func (c *Conn) qntQueueValidatedProbe(addr netip.AddrPort) bool {
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() || addr.Port() == 0 {
		return false
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if slices.Contains(st.validatedProbes, addr) {
		return false
	}
	st.validatedProbes = append(st.validatedProbes, addr)
	return true
}

func (c *Conn) qntAcceptsUnmatchedPathResponse(source netip.AddrPort) bool {
	source = canonicalNATTraversalAddr(source)
	if !source.IsValid() {
		return false
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if slices.Contains(st.pendingProbes, source) || slices.Contains(st.validatedProbes, source) {
		return true
	}
	for _, addr := range st.sentProbes {
		if addr == source {
			return true
		}
	}
	if c.multipathOut != nil {
		for _, path := range c.multipathOut.paths {
			if path.qntRoute == source {
				return true
			}
		}
	}
	return false
}

func (c *Conn) qntPopValidatedProbe() (netip.AddrPort, bool) {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.validatedProbes) == 0 {
		return netip.AddrPort{}, false
	}
	addr := st.validatedProbes[0]
	st.validatedProbes = st.validatedProbes[1:]
	return addr, true
}

func (c *Conn) qntPeekValidatedProbe() (netip.AddrPort, bool) {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.validatedProbes) == 0 {
		return netip.AddrPort{}, false
	}
	return st.validatedProbes[0], true
}

func (c *Conn) queueLocalAddAddressFrame(seq uint64, addr netip.AddrPort) {
	if c.framer == nil {
		return
	}
	c.queueControlFrame(&wire.AddAddressFrame{
		SeqNo: seq,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})
}

func (c *Conn) queueLocalRemoveAddressFrame(seq uint64) {
	if c.framer == nil {
		return
	}
	c.queueControlFrame(&wire.RemoveAddressFrame{SeqNo: seq})
}

func cloneReachOutFrames(frames []*wire.ReachOutFrame) []*wire.ReachOutFrame {
	clones := make([]*wire.ReachOutFrame, len(frames))
	for i, frame := range frames {
		if frame == nil {
			continue
		}
		clone := *frame
		clones[i] = &clone
	}
	return clones
}

func (c *Conn) addRemoteNATTraversalAddress(addr netip.AddrPort) error {
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() {
		return nil
	}
	return c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 0,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})
}

func (c *Conn) handleAddAddressFrame(frame *wire.AddAddressFrame) error {
	return c.addRemoteNATTraversalAddressFrame(frame)
}

func (c *Conn) handleReachOutFrame(frame *wire.ReachOutFrame) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	if frame == nil {
		return nil
	}
	return c.qntQueueReachOutProbe(frame)
}

func (c *Conn) qntQueueReachOutProbe(frame *wire.ReachOutFrame) error {
	addr := canonicalAddrPort(frame.Addr, frame.Port)
	if !addr.IsValid() || addr.Port() == 0 {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if frame.Round < st.round {
		return nil
	}
	if frame.Round > st.round {
		st.round = frame.Round
		st.pendingProbes = st.pendingProbes[:0]
		clear(st.sentProbes)
		clear(st.probeAttempts)
		st.validatedProbes = st.validatedProbes[:0]
		st.retryAttempt = 0
		st.nextRetry = 0
	}
	if qntHasProbeLocked(st, addr) {
		return nil
	}
	if qntProbeCountLocked(st) >= int(c.qntRemoteAddressLimit()) {
		return ErrNATTraversalTooManyAddresses
	}
	st.pendingProbes = append(st.pendingProbes, addr)
	if st.probeAttempts == nil {
		st.probeAttempts = make(map[netip.AddrPort]uint8)
	}
	st.probeAttempts[addr] = qntMaxProbeAttempts - 1
	return nil
}

func (c *Conn) qntQueueProbeRetries() bool {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	var queued bool
	for addr, remaining := range st.probeAttempts {
		if !qntCanRetryProbeLocked(st, addr, remaining) {
			continue
		}
		st.probeAttempts[addr] = remaining - 1
		st.pendingProbes = append(st.pendingProbes, addr)
		queued = true
	}
	if queued {
		st.retryAttempt++
		st.nextRetry = 0
	}
	return queued
}

func (c *Conn) qntArmNextRetry(now monotime.Time, initialRTT time.Duration) (monotime.Time, bool) {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if !qntHasRetryableProbeLocked(st) {
		st.nextRetry = 0
		return 0, false
	}
	delay := qntRetryDelay(st.retryAttempt, initialRTT)
	if delay <= 0 {
		st.nextRetry = 0
		return 0, false
	}
	st.nextRetry = now.Add(delay)
	return st.nextRetry, true
}

func (c *Conn) qntNextRetryDeadline() monotime.Time {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.nextRetry
}

func (c *Conn) qntHandleRetryDeadline(now monotime.Time) bool {
	deadline := c.qntNextRetryDeadline()
	if deadline.IsZero() || now.Before(deadline) {
		return false
	}
	if !c.qntQueueProbeRetries() {
		c.qntClearNextRetry()
		return false
	}
	return true
}

func (c *Conn) qntClearNextRetry() {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.nextRetry = 0
}

func (c *Conn) qntRetryAttempt() uint8 {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.retryAttempt
}

func qntHasRetryableProbeLocked(st *qntLocalState) bool {
	for addr, remaining := range st.probeAttempts {
		if qntCanRetryProbeLocked(st, addr, remaining) {
			return true
		}
	}
	return false
}

func qntCanRetryProbeLocked(st *qntLocalState, addr netip.AddrPort, remaining uint8) bool {
	return remaining > 0 &&
		!slices.Contains(st.pendingProbes, addr) &&
		!slices.Contains(st.validatedProbes, addr) &&
		qntHasSentProbeLocked(st, addr)
}

func qntHasSentProbeLocked(st *qntLocalState, addr netip.AddrPort) bool {
	for _, sent := range st.sentProbes {
		if sent == addr {
			return true
		}
	}
	return false
}

func qntHasProbeLocked(st *qntLocalState, addr netip.AddrPort) bool {
	if slices.Contains(st.pendingProbes, addr) || slices.Contains(st.validatedProbes, addr) {
		return true
	}
	for _, sent := range st.sentProbes {
		if sent == addr {
			return true
		}
	}
	return false
}

// qntKnownCandidate reports whether source is a QNT candidate this connection
// is aware of: a probe target (pending/sent/validated) or an advertised remote
// address. A PATH_CHALLENGE arriving from such an address is a QNT probe on a
// new candidate 4-tuple and must be answered on that same 4-tuple so the peer
// can validate it, independent of RFC 9000 migration perspective rules.
func (c *Conn) qntKnownCandidate(source netip.AddrPort) bool {
	source = canonicalNATTraversalAddr(source)
	if !source.IsValid() {
		return false
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if qntHasProbeLocked(st, source) {
		return true
	}
	for _, addr := range st.remote.addresses() {
		if addr == source {
			return true
		}
	}
	return false
}

func qntProbeCountLocked(st *qntLocalState) int {
	n := len(st.pendingProbes) + len(st.validatedProbes)
	for _, sent := range st.sentProbes {
		if !slices.Contains(st.pendingProbes, sent) && !slices.Contains(st.validatedProbes, sent) {
			n++
		}
	}
	return n
}

func (c *Conn) handleRemoveAddressFrame(frame *wire.RemoveAddressFrame) error {
	return c.removeRemoteNATTraversalAddressFrame(frame)
}

func (c *Conn) addRemoteNATTraversalAddressFrame(frame *wire.AddAddressFrame) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	if frame == nil {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	_, _, err := st.remote.add(frame)
	if err == nil && len(st.remote.addresses()) > 0 {
		st.signalRemoteReadyLocked()
	}
	return err
}

func (c *Conn) removeRemoteNATTraversalAddressFrame(frame *wire.RemoveAddressFrame) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	if frame == nil {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.remote.remove(frame)
	return nil
}

func canonicalNATTraversalAddr(addr netip.AddrPort) netip.AddrPort {
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

func (c *Conn) qntAPINegotiated() bool {
	if c == nil || c.config == nil {
		return false
	}
	return c.qntNegotiated()
}

func (c *Conn) qntRemoteAddressLimit() uint8 {
	if c == nil || c.config == nil {
		return 0
	}
	if p := maxRemoteNATTraversalAddressesParam(c.config.MaxRemoteNATTraversalAddresses); p != nil {
		return *p
	}
	return 0
}

func (c *Conn) qntLocalAddressLimit() int {
	if c == nil {
		return 0
	}
	params := c.peerParams.Load()
	if params == nil || params.MaxRemoteNATTraversalAddresses == nil {
		return 0
	}
	return int(*params.MaxRemoteNATTraversalAddresses)
}
