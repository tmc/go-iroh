package gossipproto

import (
	"math"
	"math/bits"
	"time"

	"github.com/tmc/go-iroh/internal/postcard"
	"lukechampine.com/blake3"
)

// MessageIDFromContent returns the PlumTree message ID for content.
func MessageIDFromContent(content []byte) MessageID {
	return MessageID(blake3.Sum256(content))
}

// Scope is the requested broadcast scope.
type Scope uint8

const (
	// ScopeSwarm broadcasts to the epidemic overlay.
	ScopeSwarm Scope = iota
	// ScopeNeighbors broadcasts only to direct neighbors.
	ScopeNeighbors
)

// PlumtreeConfig configures the PlumTree state machine.
type PlumtreeConfig struct {
	GraftTimeout1         time.Duration
	GraftTimeout2         time.Duration
	DispatchTimeout       time.Duration
	OptimizationThreshold Round
	MessageCacheRetention time.Duration
	MessageIDRetention    time.Duration
	CacheEvictInterval    time.Duration
	MaxPayloadSize        int
}

// DefaultPlumtreeConfig returns the Rust iroh-gossip PlumTree defaults.
func DefaultPlumtreeConfig() PlumtreeConfig {
	return PlumtreeConfig{
		GraftTimeout1:         80 * time.Millisecond,
		GraftTimeout2:         40 * time.Millisecond,
		DispatchTimeout:       5 * time.Millisecond,
		OptimizationThreshold: 7,
		MessageCacheRetention: 30 * time.Second,
		MessageIDRetention:    90 * time.Second,
		CacheEvictInterval:    time.Second,
		MaxPayloadSize:        MaxPlumtreeSize(DefaultMaxMessageSize),
	}
}

// MaxPlumtreeSize returns the largest encoded PlumTree message that fits a
// frame. A frame holds the TopicMessage enum tag (1 byte) and the PlumTree
// message, and must be strictly shorter than maxMessageSize.
func MaxPlumtreeSize(maxMessageSize int) int {
	return NormalizeMaxMessageSize(maxMessageSize) - 2
}

// MaxGossipSize returns the largest encoded size of a PlumTree Gossip message
// with contentLen bytes of content, accounting for the round growing up to
// math.MaxUint16 at subsequent hops.
func MaxGossipSize(contentLen int, scope Scope) int {
	if contentLen < 0 {
		contentLen = 0
	}
	dscope := DeliveryScope{Kind: DeliveryScopeSwarm, Round: Round(math.MaxUint16)}
	if scope == ScopeNeighbors {
		dscope = DeliveryScope{Kind: DeliveryScopeNeighbors}
	}
	empty := PlumtreeMessage{
		Kind: PlumtreeGossip,
		Gossip: Gossip{
			Scope: dscope,
		},
	}
	b, err := postcard.Marshal(empty)
	if err != nil {
		panic(err)
	}
	prefixSize := 1
	if contentLen > 0 {
		prefixSize = (bits.Len(uint(contentLen)) + 6) / 7
	}
	return len(b) - 1 + prefixSize + contentLen
}

// BroadcastFits reports whether a broadcast with contentLen bytes of content
// fits a frame at every hop.
func BroadcastFits(contentLen int, scope Scope, maxMessageSize int) bool {
	return MaxGossipSize(contentLen, scope) <= MaxPlumtreeSize(maxMessageSize)
}

// MaxContentSize returns the largest broadcast content length that fits a frame
// at every hop.
func MaxContentSize(maxMessageSize int) int {
	for n := MaxPlumtreeSize(maxMessageSize); n >= 0; n-- {
		if BroadcastFits(n, ScopeSwarm, maxMessageSize) {
			return n
		}
	}
	return 0
}

// MaxPayloadSize returns the largest broadcast content that fits in
// maxMessageSize at every hop.
func MaxPayloadSize(maxMessageSize int) int {
	return MaxContentSize(maxMessageSize)
}

// DefaultMaxPayloadSize returns the Rust-default PlumTree content budget.
func DefaultMaxPayloadSize() int { return MaxContentSize(DefaultMaxMessageSize) }

// PlumtreeStats are counters tracked by the PlumTree state machine.
type PlumtreeStats struct {
	PayloadMessagesReceived uint64
	ControlMessagesReceived uint64
	MaxLastDeliveryHop      uint16
}

// PlumtreeInEvent is an input to the PlumTree state machine.
type PlumtreeInEvent struct {
	Kind     PlumtreeInEventKind
	From     PeerID
	Message  PlumtreeMessage
	Content  []byte
	Scope    Scope
	Timer    PlumtreeTimer
	Neighbor PeerID
	Now      time.Time
}

// PlumtreeInEventKind identifies a PlumTree input.
type PlumtreeInEventKind uint8

const (
	PlumtreeRecvMessage PlumtreeInEventKind = iota
	PlumtreeBroadcast
	PlumtreeTimerExpired
	PlumtreeNeighborUp
	PlumtreeNeighborDown
)

// PlumtreeOutEvent is an output from the PlumTree state machine.
type PlumtreeOutEvent struct {
	Kind    PlumtreeOutEventKind
	To      PeerID
	Message PlumtreeMessage
	After   time.Duration
	Timer   PlumtreeTimer
	Event   PlumtreeEvent
}

// PlumtreeOutEventKind identifies a PlumTree output.
type PlumtreeOutEventKind uint8

const (
	PlumtreeSendMessage PlumtreeOutEventKind = iota
	PlumtreeScheduleTimer
	PlumtreeEmitEvent
)

// PlumtreeTimer is an opaque timer value emitted by PlumtreeState.
type PlumtreeTimer struct {
	Kind PlumtreeTimerKind
	ID   MessageID
}

// PlumtreeTimerKind identifies a PlumTree timer.
type PlumtreeTimerKind uint8

const (
	PlumtreeTimerSendGraft PlumtreeTimerKind = iota
	PlumtreeTimerDispatchLazyPush
	PlumtreeTimerEvictCache
)

// PlumtreeEvent is an application event emitted by PlumtreeState.
type PlumtreeEvent struct {
	Kind          PlumtreeEventKind
	Content       []byte
	DeliveredFrom PeerID
	Scope         DeliveryScope
}

// PlumtreeEventKind identifies a PlumTree application event.
type PlumtreeEventKind uint8

const (
	PlumtreeReceived PlumtreeEventKind = iota
)

// PlumtreeState is the IO-less PlumTree broadcast state machine.
type PlumtreeState struct {
	me     PeerID
	config PlumtreeConfig

	eager map[PeerID]struct{}
	lazy  map[PeerID]struct{}

	lazyQueue map[PeerID][]IHave
	missing   map[MessageID][]graftTarget
	nmissing  map[PeerID]int // targets per peer in missing
	ntargets  int            // targets in missing
	received  map[MessageID]time.Time
	cache     map[MessageID]cachedGossip

	graftTimerScheduled    map[MessageID]struct{}
	graftedUntil           map[PeerID]time.Time
	dispatchTimerScheduled bool
	init                   bool

	stats          PlumtreeStats
	maxPayloadSize int
}

// maxMissingPerPeer bounds how many messages one peer may have announced
// by IHave and not yet delivered. A peer that announces more is not asked for
// them; its IHaves are the backup path, and eager pushes still arrive.
const maxMissingPerPeer = 1024

// maxMissing bounds the targets of messages announced by IHave and not yet
// delivered, and the graft timers for them, across all peers.
const maxMissing = 16 * maxMissingPerPeer

type graftTarget struct {
	peer  PeerID
	round Round
}

type cachedGossip struct {
	message Gossip
	expire  time.Time
}

// NewPlumtreeState returns a PlumTree state machine for me.
func NewPlumtreeState(me PeerID, config PlumtreeConfig) *PlumtreeState {
	if config == (PlumtreeConfig{}) {
		config = DefaultPlumtreeConfig()
	}
	if config.MaxPayloadSize <= 0 {
		config.MaxPayloadSize = MaxPlumtreeSize(DefaultMaxMessageSize)
	}
	return &PlumtreeState{
		me:                     me,
		config:                 config,
		eager:                  map[PeerID]struct{}{},
		lazy:                   map[PeerID]struct{}{},
		lazyQueue:              map[PeerID][]IHave{},
		missing:                map[MessageID][]graftTarget{},
		nmissing:               map[PeerID]int{},
		received:               map[MessageID]time.Time{},
		cache:                  map[MessageID]cachedGossip{},
		graftTimerScheduled:    map[MessageID]struct{}{},
		graftedUntil:           map[PeerID]time.Time{},
		dispatchTimerScheduled: false,
		maxPayloadSize:         config.MaxPayloadSize,
	}
}

// Stats returns the current PlumTree counters.
func (s *PlumtreeState) Stats() PlumtreeStats {
	return s.stats
}

// MaxPayloadSize returns the largest application payload configured for s.
func (s *PlumtreeState) MaxPayloadSize() int { return s.maxPayloadSize }

// Handle applies ev and returns protocol outputs for the caller to process.
func (s *PlumtreeState) Handle(ev PlumtreeInEvent) []PlumtreeOutEvent {
	var out []PlumtreeOutEvent
	if !s.init {
		s.init = true
		s.onEvictCacheTimer(ev.Now, &out)
	}
	switch ev.Kind {
	case PlumtreeRecvMessage:
		s.handleMessage(ev.From, ev.Message, ev.Now, &out)
	case PlumtreeBroadcast:
		s.broadcast(ev.Content, ev.Scope, ev.Now, &out)
	case PlumtreeTimerExpired:
		switch ev.Timer.Kind {
		case PlumtreeTimerDispatchLazyPush:
			s.onDispatchTimer(&out)
		case PlumtreeTimerSendGraft:
			s.onSendGraftTimer(ev.Timer.ID, ev.Now, &out)
		case PlumtreeTimerEvictCache:
			s.onEvictCacheTimer(ev.Now, &out)
		}
	case PlumtreeNeighborUp:
		s.addEager(ev.Neighbor)
	case PlumtreeNeighborDown:
		s.onNeighborDown(ev.Neighbor)
	}
	return out
}

func (s *PlumtreeState) handleMessage(sender PeerID, message PlumtreeMessage, now time.Time, out *[]PlumtreeOutEvent) {
	if message.Kind == PlumtreeGossip {
		s.stats.PayloadMessagesReceived++
	} else {
		s.stats.ControlMessagesReceived++
	}
	_, isEager := s.eager[sender]
	_, isLazy := s.lazy[sender]
	fromPeer := isEager || isLazy
	switch message.Kind {
	case PlumtreeGossip:
		s.onGossip(sender, fromPeer, message.Gossip, now, out)
	case PlumtreePrune:
		if fromPeer {
			s.addLazy(sender)
		}
	case PlumtreeIHave:
		if fromPeer {
			s.onIHave(sender, message.IHave, out)
		}
	case PlumtreeGraft:
		if fromPeer {
			s.onGraft(sender, message.Graft, now, out)
		}
	}
}

func (s *PlumtreeState) broadcast(content []byte, scope Scope, now time.Time, out *[]PlumtreeOutEvent) {
	if MaxGossipSize(len(content), scope) > s.maxPayloadSize {
		return
	}
	id := MessageIDFromContent(content)
	dscope := DeliveryScope{Kind: DeliveryScopeSwarm}
	if scope == ScopeNeighbors {
		dscope = DeliveryScope{Kind: DeliveryScopeNeighbors}
	}
	message := Gossip{ID: id, Content: cloneBytes(content), Scope: dscope}
	if dscope.Kind == DeliveryScopeSwarm {
		s.received[id] = now.Add(s.config.MessageIDRetention)
		s.cache[id] = cachedGossip{message: message, expire: now.Add(s.config.MessageCacheRetention)}
		s.lazyPush(message, s.me, out)
	}
	s.eagerPush(message, s.me, out)
}

func (s *PlumtreeState) onGossip(sender PeerID, fromPeer bool, message Gossip, now time.Time, out *[]PlumtreeOutEvent) {
	if message.ID != MessageIDFromContent(message.Content) {
		return
	}
	if _, ok := s.received[message.ID]; ok {
		if until, protected := s.graftedUntil[sender]; protected && !now.IsZero() && now.Before(until) {
			return
		}
		if fromPeer {
			s.addLazy(sender)
		}
		*out = append(*out, PlumtreeOutEvent{
			Kind:    PlumtreeSendMessage,
			To:      sender,
			Message: PlumtreeMessage{Kind: PlumtreePrune},
		})
		return
	}

	eventMessage := message
	if message.Scope.Kind == DeliveryScopeSwarm {
		s.received[message.ID] = now.Add(s.config.MessageIDRetention)
		forward := message
		forward.Scope.Round++
		s.cache[message.ID] = cachedGossip{message: forward, expire: now.Add(s.config.MessageCacheRetention)}
		s.eagerPush(forward, sender, out)
		s.lazyPush(forward, sender, out)
		delete(s.graftTimerScheduled, message.ID)
		previous := s.missing[message.ID]
		delete(s.missing, message.ID)
		for _, target := range previous {
			s.forgetMissing(target.peer)
		}
		if fromPeer {
			s.optimizeTree(sender, forward, previous, now, out)
		}
		if message.Scope.Round > Round(s.stats.MaxLastDeliveryHop) {
			s.stats.MaxLastDeliveryHop = uint16(message.Scope.Round)
		}
	}

	*out = append(*out, PlumtreeOutEvent{
		Kind: PlumtreeEmitEvent,
		Event: PlumtreeEvent{
			Kind:          PlumtreeReceived,
			Content:       cloneBytes(eventMessage.Content),
			DeliveredFrom: sender,
			Scope:         eventMessage.Scope,
		},
	})
}

func (s *PlumtreeState) optimizeTree(sender PeerID, message Gossip, ihaves []graftTarget, now time.Time, out *[]PlumtreeOutEvent) {
	if message.Scope.Kind != DeliveryScopeSwarm || len(ihaves) == 0 {
		return
	}
	best := ihaves[0]
	for _, candidate := range ihaves[1:] {
		if candidate.round < best.round {
			best = candidate
		}
	}
	round := message.Scope.Round
	if best.round < round && round-best.round >= s.config.OptimizationThreshold {
		if _, ok := s.eager[best.peer]; !ok {
			s.addEager(best.peer)
			s.markGrafted(best.peer, now)
			*out = append(*out, PlumtreeOutEvent{
				Kind: PlumtreeSendMessage,
				To:   best.peer,
				Message: PlumtreeMessage{
					Kind:  PlumtreeGraft,
					Graft: Graft{Round: best.round},
				},
			})
		}
		s.addLazy(sender)
		*out = append(*out, PlumtreeOutEvent{
			Kind:    PlumtreeSendMessage,
			To:      sender,
			Message: PlumtreeMessage{Kind: PlumtreePrune},
		})
	}
}

func (s *PlumtreeState) onIHave(sender PeerID, ihaves []IHave, out *[]PlumtreeOutEvent) {
	for _, ihave := range ihaves {
		if _, ok := s.received[ihave.ID]; ok {
			continue
		}
		if s.nmissing[sender] >= maxMissingPerPeer || s.ntargets >= maxMissing ||
			len(s.graftTimerScheduled) >= maxMissing || hasGraftTarget(s.missing[ihave.ID], sender) {
			continue
		}
		s.missing[ihave.ID] = append(s.missing[ihave.ID], graftTarget{peer: sender, round: ihave.Round})
		s.nmissing[sender]++
		s.ntargets++
		if _, ok := s.graftTimerScheduled[ihave.ID]; !ok {
			s.graftTimerScheduled[ihave.ID] = struct{}{}
			*out = append(*out, PlumtreeOutEvent{
				Kind:  PlumtreeScheduleTimer,
				After: s.config.GraftTimeout1,
				Timer: PlumtreeTimer{Kind: PlumtreeTimerSendGraft, ID: ihave.ID},
			})
		}
	}
}

func (s *PlumtreeState) onSendGraftTimer(id MessageID, now time.Time, out *[]PlumtreeOutEvent) {
	delete(s.graftTimerScheduled, id)
	if _, ok := s.received[id]; ok {
		return
	}
	targets := s.missing[id]
	if len(targets) == 0 {
		return
	}
	target := targets[0]
	s.missing[id] = targets[1:]
	if len(s.missing[id]) == 0 {
		delete(s.missing, id)
	}
	s.forgetMissing(target.peer)
	s.addEager(target.peer)
	s.markGrafted(target.peer, now)
	*out = append(*out,
		PlumtreeOutEvent{
			Kind: PlumtreeSendMessage,
			To:   target.peer,
			Message: PlumtreeMessage{
				Kind:  PlumtreeGraft,
				Graft: Graft{ID: &id, Round: target.round},
			},
		},
		PlumtreeOutEvent{
			Kind:  PlumtreeScheduleTimer,
			After: s.config.GraftTimeout2,
			Timer: PlumtreeTimer{Kind: PlumtreeTimerSendGraft, ID: id},
		},
	)
}

func (s *PlumtreeState) onGraft(sender PeerID, graft Graft, now time.Time, out *[]PlumtreeOutEvent) {
	s.addEager(sender)
	s.markGrafted(sender, now)
	if graft.ID == nil {
		return
	}
	if cached, ok := s.cache[*graft.ID]; ok {
		*out = append(*out, PlumtreeOutEvent{
			Kind:    PlumtreeSendMessage,
			To:      sender,
			Message: PlumtreeMessage{Kind: PlumtreeGossip, Gossip: cached.message},
		})
	}
}

// markGrafted shields a newly grafted eager peer from immediate pruning on
// duplicate deliveries (upstream iroh-gossip#207).
func (s *PlumtreeState) markGrafted(peer PeerID, now time.Time) {
	if now.IsZero() {
		return
	}
	grace := max(2*s.config.GraftTimeout1, time.Second)
	s.graftedUntil[peer] = now.Add(grace)
}

func (s *PlumtreeState) onDispatchTimer(out *[]PlumtreeOutEvent) {
	// Reserve 1 byte for the enum discriminator and 5 bytes for the list
	// length varint (enough for any list that fits a frame).
	chunkLen := (s.maxPayloadSize - 6) / iHavePostcardMaxSize
	if chunkLen < 1 {
		chunkLen = 1
	}
	for peer, ihaves := range s.lazyQueue {
		for len(ihaves) > 0 {
			n := min(chunkLen, len(ihaves))
			*out = append(*out, PlumtreeOutEvent{
				Kind:    PlumtreeSendMessage,
				To:      peer,
				Message: PlumtreeMessage{Kind: PlumtreeIHave, IHave: append([]IHave(nil), ihaves[:n]...)},
			})
			ihaves = ihaves[n:]
		}
		delete(s.lazyQueue, peer)
	}
	s.dispatchTimerScheduled = false
}

func (s *PlumtreeState) onNeighborDown(peer PeerID) {
	for id, targets := range s.missing {
		targets = removeGraftTargets(targets, peer)
		if len(targets) == 0 {
			delete(s.missing, id)
		} else {
			s.missing[id] = targets
		}
	}
	s.ntargets -= s.nmissing[peer]
	delete(s.nmissing, peer)
	delete(s.eager, peer)
	delete(s.lazy, peer)
	delete(s.graftedUntil, peer)
}

// forgetMissing records that one of peer's targets left missing.
func (s *PlumtreeState) forgetMissing(peer PeerID) {
	s.ntargets--
	if s.nmissing[peer] <= 1 {
		delete(s.nmissing, peer)
	} else {
		s.nmissing[peer]--
	}
}

func hasGraftTarget(targets []graftTarget, peer PeerID) bool {
	for _, target := range targets {
		if target.peer == peer {
			return true
		}
	}
	return false
}

func (s *PlumtreeState) onEvictCacheTimer(now time.Time, out *[]PlumtreeOutEvent) {
	for id, expire := range s.received {
		if !expire.After(now) {
			delete(s.received, id)
		}
	}
	for id, cached := range s.cache {
		if !cached.expire.After(now) {
			delete(s.cache, id)
		}
	}
	for peer, until := range s.graftedUntil {
		if !until.After(now) {
			delete(s.graftedUntil, peer)
		}
	}
	*out = append(*out, PlumtreeOutEvent{
		Kind:  PlumtreeScheduleTimer,
		After: s.config.CacheEvictInterval,
		Timer: PlumtreeTimer{Kind: PlumtreeTimerEvictCache},
	})
}

func (s *PlumtreeState) addEager(peer PeerID) {
	delete(s.lazy, peer)
	s.eager[peer] = struct{}{}
}

func (s *PlumtreeState) addLazy(peer PeerID) {
	delete(s.eager, peer)
	s.lazy[peer] = struct{}{}
}

func (s *PlumtreeState) eagerPush(message Gossip, sender PeerID, out *[]PlumtreeOutEvent) {
	for peer := range s.eager {
		if peer == s.me || peer == sender {
			continue
		}
		*out = append(*out, PlumtreeOutEvent{
			Kind:    PlumtreeSendMessage,
			To:      peer,
			Message: PlumtreeMessage{Kind: PlumtreeGossip, Gossip: message},
		})
	}
}

func (s *PlumtreeState) lazyPush(message Gossip, sender PeerID, out *[]PlumtreeOutEvent) {
	if message.Scope.Kind != DeliveryScopeSwarm {
		return
	}
	for peer := range s.lazy {
		if peer == sender {
			continue
		}
		s.lazyQueue[peer] = append(s.lazyQueue[peer], IHave{ID: message.ID, Round: message.Scope.Round})
	}
	if !s.dispatchTimerScheduled {
		*out = append(*out, PlumtreeOutEvent{
			Kind:  PlumtreeScheduleTimer,
			After: s.config.DispatchTimeout,
			Timer: PlumtreeTimer{Kind: PlumtreeTimerDispatchLazyPush},
		})
		s.dispatchTimerScheduled = true
	}
}

func removeGraftTargets(targets []graftTarget, peer PeerID) []graftTarget {
	n := 0
	for _, target := range targets {
		if target.peer != peer {
			targets[n] = target
			n++
		}
	}
	return targets[:n]
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
