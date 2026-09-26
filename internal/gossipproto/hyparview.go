package gossipproto

import (
	"math/rand"
	"time"
)

// HyparviewConfig configures the HyParView membership state machine.
type HyparviewConfig struct {
	ActiveViewCapacity      int
	PassiveViewCapacity     int
	ActiveRandomWalkLength  Ttl
	PassiveRandomWalkLength Ttl
	ShuffleRandomWalkLength Ttl
	ShuffleActiveViewCount  int
	ShufflePassiveViewCount int
	ShuffleInterval         time.Duration
	NeighborRequestTimeout  time.Duration
}

// DefaultHyparviewConfig returns the Rust iroh-gossip HyParView defaults.
func DefaultHyparviewConfig() HyparviewConfig {
	return HyparviewConfig{
		ActiveViewCapacity:      5,
		PassiveViewCapacity:     30,
		ActiveRandomWalkLength:  6,
		PassiveRandomWalkLength: 3,
		ShuffleRandomWalkLength: 6,
		ShuffleActiveViewCount:  3,
		ShufflePassiveViewCount: 4,
		ShuffleInterval:         time.Minute,
		NeighborRequestTimeout:  500 * time.Millisecond,
	}
}

// HyparviewInEvent is an input to the HyParView state machine.
type HyparviewInEvent struct {
	Kind    HyparviewInEventKind
	From    PeerID
	Message HyparviewMessage
	Timer   HyparviewTimer
	Peer    PeerID
	Data    *PeerData
}

// HyparviewInEventKind identifies a HyParView input.
type HyparviewInEventKind uint8

const (
	HyparviewRecvMessage HyparviewInEventKind = iota
	HyparviewTimerExpired
	HyparviewPeerDisconnected
	HyparviewRequestJoin
	HyparviewUpdatePeerData
	HyparviewQuit
)

// HyparviewOutEvent is an output from the HyParView state machine.
type HyparviewOutEvent struct {
	Kind    HyparviewOutEventKind
	To      PeerID
	Message HyparviewMessage
	After   time.Duration
	Timer   HyparviewTimer
	Event   HyparviewEvent
	Data    *PeerData
}

// HyparviewOutEventKind identifies a HyParView output.
type HyparviewOutEventKind uint8

const (
	HyparviewSendMessage HyparviewOutEventKind = iota
	HyparviewScheduleTimer
	HyparviewDisconnectPeer
	HyparviewEmitEvent
	HyparviewPeerData
)

// HyparviewEvent is an application event emitted by HyparviewState.
type HyparviewEvent struct {
	Kind HyparviewEventKind
	Peer PeerID
}

// HyparviewEventKind identifies a HyParView application event.
type HyparviewEventKind uint8

const (
	HyparviewNeighborUp HyparviewEventKind = iota
	HyparviewNeighborDown
)

// HyparviewTimer is an opaque timer value emitted by HyparviewState.
type HyparviewTimer struct {
	Kind HyparviewTimerKind
	Peer PeerID
}

// HyparviewTimerKind identifies a HyParView timer.
type HyparviewTimerKind uint8

const (
	HyparviewTimerDoShuffle HyparviewTimerKind = iota
	HyparviewTimerPendingNeighborRequest
)

// HyparviewStats are counters tracked by the HyParView state machine.
type HyparviewStats struct {
	TotalConnections int
}

// HyparviewState is the IO-less HyParView membership state machine.
type HyparviewState struct {
	me     PeerID
	meData *PeerData
	config HyparviewConfig
	rand   *rand.Rand

	active  peerList
	passive peerList

	shuffleScheduled bool
	stats            HyparviewStats

	pendingNeighbor map[PeerID]struct{}
	peerData        map[PeerID]PeerData
	aliveDisconnect map[PeerID]struct{}
}

// NewHyparviewState returns a HyParView state machine for me.
func NewHyparviewState(me PeerID, data *PeerData, config HyparviewConfig) *HyparviewState {
	return NewHyparviewStateWithRand(me, data, config, nil)
}

// NewHyparviewStateWithRand returns a HyParView state machine using r for peer
// selection. A nil r uses a process-local random source.
func NewHyparviewStateWithRand(me PeerID, data *PeerData, config HyparviewConfig, r *rand.Rand) *HyparviewState {
	if config == (HyparviewConfig{}) {
		config = DefaultHyparviewConfig()
	}
	if r == nil {
		r = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return &HyparviewState{
		me:              me,
		meData:          clonePeerDataPtr(data),
		config:          config,
		rand:            r,
		pendingNeighbor: map[PeerID]struct{}{},
		peerData:        map[PeerID]PeerData{},
		aliveDisconnect: map[PeerID]struct{}{},
	}
}

// Stats returns the current HyParView counters.
func (s *HyparviewState) Stats() HyparviewStats {
	return s.stats
}

// ActivePeers returns a snapshot of the active view.
func (s *HyparviewState) ActivePeers() []PeerID {
	return s.active.slice()
}

// PassivePeers returns a snapshot of the passive view.
func (s *HyparviewState) PassivePeers() []PeerID {
	return s.passive.slice()
}

// Handle applies ev and returns protocol outputs for the caller to process.
func (s *HyparviewState) Handle(ev HyparviewInEvent) []HyparviewOutEvent {
	var out []HyparviewOutEvent
	switch ev.Kind {
	case HyparviewRecvMessage:
		s.handleMessage(ev.From, ev.Message, &out)
	case HyparviewTimerExpired:
		switch ev.Timer.Kind {
		case HyparviewTimerDoShuffle:
			s.handleShuffleTimer(&out)
		case HyparviewTimerPendingNeighborRequest:
			s.handlePendingNeighborTimer(ev.Timer.Peer, &out)
		}
	case HyparviewPeerDisconnected:
		s.handleConnectionClosed(ev.Peer, &out)
	case HyparviewRequestJoin:
		s.handleJoin(ev.Peer, &out)
	case HyparviewUpdatePeerData:
		s.meData = clonePeerDataPtr(ev.Data)
	case HyparviewQuit:
		s.handleQuit(&out)
	}
	if !s.shuffleScheduled {
		out = append(out, HyparviewOutEvent{
			Kind:  HyparviewScheduleTimer,
			After: s.config.ShuffleInterval,
			Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle},
		})
		s.shuffleScheduled = true
	}
	return out
}

func (s *HyparviewState) handleMessage(from PeerID, message HyparviewMessage, out *[]HyparviewOutEvent) {
	isDisconnect := message.Kind == HyparviewDisconnect
	if !isDisconnect && !s.active.contains(from) {
		s.stats.TotalConnections++
	}
	switch message.Kind {
	case HyparviewJoin:
		s.onJoin(from, message.Join, out)
	case HyparviewForwardJoin:
		s.onForwardJoin(from, message.ForwardJoin, out)
	case HyparviewShuffle:
		s.onShuffle(from, message.Shuffle, out)
	case HyparviewShuffleReply:
		s.onShuffleReply(message.ShuffleReply, out)
	case HyparviewNeighbor:
		s.onNeighbor(from, message.Neighbor, out)
	case HyparviewDisconnect:
		s.onDisconnect(from, message.Disconnect, out)
	}
	if !isDisconnect && !s.active.contains(from) {
		*out = append(*out, HyparviewOutEvent{Kind: HyparviewDisconnectPeer, To: from})
	}
}

func (s *HyparviewState) handleJoin(peer PeerID, out *[]HyparviewOutEvent) {
	*out = append(*out, HyparviewOutEvent{
		Kind:    HyparviewSendMessage,
		To:      peer,
		Message: HyparviewMessage{Kind: HyparviewJoin, Join: clonePeerDataPtr(s.meData)},
	})
}

func (s *HyparviewState) onJoin(peer PeerID, data *PeerData, out *[]HyparviewOutEvent) {
	// A Join comes from fresh topic state that is waiting for a Neighbor.
	// Any Neighbor we sent the peer before went to state it has since
	// dropped, so forget it and answer again. Otherwise a peer that quit
	// before our answer arrived stays pending here and is never answered.
	delete(s.pendingNeighbor, peer)
	s.addActive(peer, data, PriorityHigh, true, out)
	info := PeerInfo{ID: peer, Data: clonePeerDataPtr(data)}
	for _, node := range s.active.without(peer) {
		*out = append(*out, HyparviewOutEvent{
			Kind: HyparviewSendMessage,
			To:   node,
			Message: HyparviewMessage{
				Kind:        HyparviewForwardJoin,
				ForwardJoin: ForwardJoin{Peer: info, Ttl: s.config.ActiveRandomWalkLength},
			},
		})
	}
}

func (s *HyparviewState) onForwardJoin(sender PeerID, message ForwardJoin, out *[]HyparviewOutEvent) {
	peer := message.Peer.ID
	// A ForwardJoin comes from a Join the peer sent from fresh topic
	// state, so, as in onJoin, any Neighbor we sent it before may have
	// gone to state it has since dropped. Forget it, so the peer is
	// answered or the walk forwarded as if nothing were pending.
	delete(s.pendingNeighbor, peer)
	if s.active.contains(peer) {
		s.insertPeerInfo(message.Peer, out)
		s.sendNeighbor(peer, PriorityHigh, out)
		return
	}
	if message.Ttl == 0 || s.active.len() <= 1 {
		s.insertPeerInfo(message.Peer, out)
		s.sendNeighbor(peer, PriorityHigh, out)
		return
	}
	if message.Ttl == s.config.PassiveRandomWalkLength {
		s.addPassive(peer, message.Peer.Data, out)
	}
	if next, ok := s.active.randomWithout(s.rand, sender); ok {
		message.Ttl--
		*out = append(*out, HyparviewOutEvent{
			Kind:    HyparviewSendMessage,
			To:      next,
			Message: HyparviewMessage{Kind: HyparviewForwardJoin, ForwardJoin: message},
		})
	}
}

func (s *HyparviewState) onNeighbor(from PeerID, details Neighbor, out *[]HyparviewOutEvent) {
	_, isReply := s.pendingNeighbor[from]
	delete(s.pendingNeighbor, from)
	if !s.addActive(from, details.Data, details.Priority, !isReply, out) {
		s.sendDisconnect(from, true, out)
	}
}

func (s *HyparviewState) onDisconnect(peer PeerID, details Disconnect, out *[]HyparviewOutEvent) {
	delete(s.pendingNeighbor, peer)
	if s.active.contains(peer) {
		s.removeActive(peer, removalDisconnectReceived, details.Alive, true, out)
	} else if details.Alive && s.passive.contains(peer) {
		s.aliveDisconnect[peer] = struct{}{}
	}
}

func (s *HyparviewState) handleConnectionClosed(peer PeerID, out *[]HyparviewOutEvent) {
	delete(s.pendingNeighbor, peer)
	if s.active.contains(peer) {
		s.removeActive(peer, removalConnectionClosed, false, true, out)
		return
	}
	if _, ok := s.aliveDisconnect[peer]; ok {
		delete(s.aliveDisconnect, peer)
		return
	}
	s.passive.remove(peer)
	delete(s.peerData, peer)
}

func (s *HyparviewState) handleQuit(out *[]HyparviewOutEvent) {
	for _, peer := range s.active.slice() {
		s.active.remove(peer)
		s.sendDisconnect(peer, false, out)
	}
}

func (s *HyparviewState) onShuffle(from PeerID, shuffle Shuffle, out *[]HyparviewOutEvent) {
	if shuffle.Ttl == 0 || s.active.len() <= 1 {
		n := len(shuffle.Nodes)
		for _, node := range shuffle.Nodes {
			s.addPassive(node.ID, node.Data, out)
		}
		s.sendShuffleReply(shuffle.Origin, n, out)
		return
	}
	if next, ok := s.active.randomWithout(s.rand, shuffle.Origin, from); ok {
		shuffle.Ttl--
		*out = append(*out, HyparviewOutEvent{
			Kind:    HyparviewSendMessage,
			To:      next,
			Message: HyparviewMessage{Kind: HyparviewShuffle, Shuffle: shuffle},
		})
	}
}

func (s *HyparviewState) sendShuffleReply(to PeerID, n int, out *[]HyparviewOutEvent) {
	var nodes []PeerInfo
	for _, id := range s.passive.shuffledN(s.rand, n) {
		nodes = append(nodes, s.peerInfo(id))
	}
	for _, id := range s.active.shuffledN(s.rand, n-len(nodes)) {
		nodes = append(nodes, s.peerInfo(id))
	}
	*out = append(*out, HyparviewOutEvent{
		Kind:    HyparviewSendMessage,
		To:      to,
		Message: HyparviewMessage{Kind: HyparviewShuffleReply, ShuffleReply: ShuffleReply{Nodes: nodes}},
	})
}

func (s *HyparviewState) onShuffleReply(reply ShuffleReply, out *[]HyparviewOutEvent) {
	for _, node := range reply.Nodes {
		s.addPassive(node.ID, node.Data, out)
	}
	s.refillActiveFromPassive(nil, out)
}

func (s *HyparviewState) handleShuffleTimer(out *[]HyparviewOutEvent) {
	if node, ok := s.active.random(s.rand); ok {
		var nodes []PeerInfo
		for _, id := range s.active.shuffledWithoutN(s.rand, s.config.ShuffleActiveViewCount, node) {
			nodes = append(nodes, s.peerInfo(id))
		}
		for _, id := range s.passive.shuffledWithoutN(s.rand, s.config.ShufflePassiveViewCount, node) {
			nodes = append(nodes, s.peerInfo(id))
		}
		nodes = append(nodes, PeerInfo{ID: s.me, Data: clonePeerDataPtr(s.meData)})
		*out = append(*out, HyparviewOutEvent{
			Kind: HyparviewSendMessage,
			To:   node,
			Message: HyparviewMessage{
				Kind:    HyparviewShuffle,
				Shuffle: Shuffle{Origin: s.me, Nodes: nodes, Ttl: s.config.ShuffleRandomWalkLength},
			},
		})
	}
	*out = append(*out, HyparviewOutEvent{
		Kind:  HyparviewScheduleTimer,
		After: s.config.ShuffleInterval,
		Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle},
	})
}

func (s *HyparviewState) handlePendingNeighborTimer(peer PeerID, out *[]HyparviewOutEvent) {
	if _, ok := s.pendingNeighbor[peer]; !ok {
		return
	}
	delete(s.pendingNeighbor, peer)
	s.passive.remove(peer)
	s.refillActiveFromPassive(nil, out)
}

func (s *HyparviewState) sendDisconnect(peer PeerID, alive bool, out *[]HyparviewOutEvent) {
	s.sendShuffleReply(peer, s.config.ShuffleActiveViewCount+s.config.ShufflePassiveViewCount, out)
	*out = append(*out,
		HyparviewOutEvent{
			Kind:    HyparviewSendMessage,
			To:      peer,
			Message: HyparviewMessage{Kind: HyparviewDisconnect, Disconnect: Disconnect{Alive: alive}},
		},
		HyparviewOutEvent{Kind: HyparviewDisconnectPeer, To: peer},
	)
}

func (s *HyparviewState) addActive(peer PeerID, data *PeerData, priority Priority, reply bool, out *[]HyparviewOutEvent) bool {
	if peer == s.me {
		return false
	}
	s.insertPeerInfo(PeerInfo{ID: peer, Data: clonePeerDataPtr(data)}, out)
	if s.active.contains(peer) {
		if reply {
			s.sendNeighbor(peer, priority, out)
		}
		return true
	}
	if priority == PriorityLow && s.active.len() >= s.config.ActiveViewCapacity {
		return false
	}
	if s.active.len() >= s.config.ActiveViewCapacity {
		if old, ok := s.active.random(s.rand); ok {
			s.removeActive(old, removalRandom, false, false, out)
		}
	}
	s.passive.remove(peer)
	if s.active.insert(peer) {
		*out = append(*out, HyparviewOutEvent{
			Kind:  HyparviewEmitEvent,
			Event: HyparviewEvent{Kind: HyparviewNeighborUp, Peer: peer},
		})
		if reply {
			s.sendNeighbor(peer, priority, out)
		}
	}
	return true
}

func (s *HyparviewState) addPassive(peer PeerID, data *PeerData, out *[]HyparviewOutEvent) {
	s.insertPeerInfo(PeerInfo{ID: peer, Data: clonePeerDataPtr(data)}, out)
	if peer == s.me || s.active.contains(peer) || s.passive.contains(peer) {
		return
	}
	if s.passive.len() >= s.config.PassiveViewCapacity {
		if old, ok := s.passive.random(s.rand); ok {
			s.passive.remove(old)
		}
	}
	s.passive.insert(peer)
}

type removalReason uint8

const (
	removalConnectionClosed removalReason = iota
	removalDisconnectReceived
	removalRandom
)

func (s *HyparviewState) removeActive(peer PeerID, reason removalReason, alive bool, refill bool, out *[]HyparviewOutEvent) {
	if !s.active.remove(peer) {
		return
	}
	*out = append(*out, HyparviewOutEvent{
		Kind:  HyparviewEmitEvent,
		Event: HyparviewEvent{Kind: HyparviewNeighborDown, Peer: peer},
	})
	switch reason {
	case removalRandom:
		s.sendDisconnect(peer, true, out)
	case removalConnectionClosed, removalDisconnectReceived:
		*out = append(*out, HyparviewOutEvent{Kind: HyparviewDisconnectPeer, To: peer})
	}
	keepPassive := false
	switch reason {
	case removalConnectionClosed:
		_, keepPassive = s.aliveDisconnect[peer]
		delete(s.aliveDisconnect, peer)
	case removalDisconnectReceived:
		keepPassive = alive
	case removalRandom:
		keepPassive = true
	}
	if keepPassive {
		data := clonePeerDataPtr(nil)
		if d, ok := s.peerData[peer]; ok {
			dd := d
			data = &dd
			delete(s.peerData, peer)
		}
		s.addPassive(peer, data, out)
		if reason != removalConnectionClosed {
			s.aliveDisconnect[peer] = struct{}{}
		}
	}
	if refill {
		s.refillActiveFromPassive([]PeerID{peer}, out)
	}
}

func (s *HyparviewState) refillActiveFromPassive(skip []PeerID, out *[]HyparviewOutEvent) {
	if s.active.len()+len(s.pendingNeighbor) >= s.config.ActiveViewCapacity {
		return
	}
	var allSkip []PeerID
	allSkip = append(allSkip, skip...)
	for peer := range s.pendingNeighbor {
		allSkip = append(allSkip, peer)
	}
	if peer, ok := s.passive.randomWithout(s.rand, allSkip...); ok {
		priority := PriorityLow
		if s.active.len() == 0 {
			priority = PriorityHigh
		}
		s.sendNeighbor(peer, priority, out)
		*out = append(*out, HyparviewOutEvent{
			Kind:  HyparviewScheduleTimer,
			After: s.config.NeighborRequestTimeout,
			Timer: HyparviewTimer{Kind: HyparviewTimerPendingNeighborRequest, Peer: peer},
		})
	}
}

func (s *HyparviewState) sendNeighbor(peer PeerID, priority Priority, out *[]HyparviewOutEvent) {
	if s.isPending(peer) {
		return
	}
	s.pendingNeighbor[peer] = struct{}{}
	*out = append(*out, HyparviewOutEvent{
		Kind: HyparviewSendMessage,
		To:   peer,
		Message: HyparviewMessage{
			Kind:     HyparviewNeighbor,
			Neighbor: Neighbor{Priority: priority, Data: clonePeerDataPtr(s.meData)},
		},
	})
}

func (s *HyparviewState) insertPeerInfo(info PeerInfo, out *[]HyparviewOutEvent) {
	if info.Data == nil {
		return
	}
	data := clonePeerData(*info.Data)
	old, ok := s.peerData[info.ID]
	if (!ok || !samePeerData(old, data)) && len(data) != 0 {
		dd := clonePeerData(data)
		*out = append(*out, HyparviewOutEvent{Kind: HyparviewPeerData, To: info.ID, Data: &dd})
	}
	s.peerData[info.ID] = data
}

func (s *HyparviewState) peerInfo(id PeerID) PeerInfo {
	if data, ok := s.peerData[id]; ok {
		dd := clonePeerData(data)
		return PeerInfo{ID: id, Data: &dd}
	}
	return PeerInfo{ID: id}
}

func (s *HyparviewState) isPending(peer PeerID) bool {
	_, ok := s.pendingNeighbor[peer]
	return ok
}

type peerList []PeerID

func (l *peerList) insert(peer PeerID) bool {
	if l.contains(peer) {
		return false
	}
	*l = append(*l, peer)
	return true
}

func (l *peerList) remove(peer PeerID) bool {
	for i, p := range *l {
		if p == peer {
			copy((*l)[i:], (*l)[i+1:])
			*l = (*l)[:len(*l)-1]
			return true
		}
	}
	return false
}

func (l peerList) contains(peer PeerID) bool {
	for _, p := range l {
		if p == peer {
			return true
		}
	}
	return false
}

func (l peerList) len() int { return len(l) }

func (l peerList) slice() []PeerID {
	return append([]PeerID(nil), l...)
}

func (l peerList) random(r *rand.Rand) (PeerID, bool) {
	if len(l) == 0 {
		return PeerID{}, false
	}
	return l[r.Intn(len(l))], true
}

func (l peerList) shuffledN(r *rand.Rand, n int) []PeerID {
	if n <= 0 {
		return nil
	}
	return l.shuffledWithoutN(r, n)
}

func (l peerList) without(skip ...PeerID) []PeerID {
	var out []PeerID
	for _, peer := range l {
		if !peerIn(peer, skip) {
			out = append(out, peer)
		}
	}
	return out
}

func (l peerList) shuffledWithoutN(r *rand.Rand, n int, skip ...PeerID) []PeerID {
	peers := l.without(skip...)
	if n > len(peers) {
		n = len(peers)
	}
	r.Shuffle(len(peers), func(i, j int) {
		peers[i], peers[j] = peers[j], peers[i]
	})
	return peers[:n]
}

func (l peerList) randomWithout(r *rand.Rand, skip ...PeerID) (PeerID, bool) {
	peers := l.without(skip...)
	if len(peers) == 0 {
		return PeerID{}, false
	}
	return peers[r.Intn(len(peers))], true
}

func peerIn(peer PeerID, peers []PeerID) bool {
	for _, p := range peers {
		if p == peer {
			return true
		}
	}
	return false
}

func clonePeerDataPtr(data *PeerData) *PeerData {
	if data == nil {
		return nil
	}
	out := clonePeerData(*data)
	return &out
}

func clonePeerData(data PeerData) PeerData {
	return append(PeerData(nil), data...)
}

func samePeerData(a, b PeerData) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
