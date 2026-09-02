package gossip

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"
	"time"

	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const defaultTopicEventCap = 2048

// JoinOptions configures a topic subscription.
type JoinOptions struct {
	// Bootstrap are the peers dialed to join the topic's overlay.
	Bootstrap []netaddr.EndpointAddr

	// SubscriptionCapacity is the number of events the subscription buffers
	// for a receiver that is not reading yet. Zero means 2048.
	SubscriptionCapacity int
}

// EventKind identifies a topic event.
type EventKind uint8

const (
	// NeighborUp reports a new direct neighbor for the topic.
	NeighborUp EventKind = iota
	// NeighborDown reports a dropped direct neighbor for the topic.
	NeighborDown
	// Received reports an application gossip message.
	Received
	// PeerData reports metadata propagated by the topic membership overlay.
	PeerData
	// Lagged reports that a slow receiver missed events; [Event.Dropped]
	// says how many. The stream continues after it; the receiver has lost
	// the dropped events, not the subscription.
	//
	// A full subscription queue drops the newest event, not the oldest, so
	// the marker is delivered in the position the loss happened. Rust
	// iroh-gossip rides a tokio broadcast channel and drops the oldest
	// instead; the divergence is deliberate, not a porting mistake.
	Lagged
)

// DeliveryScope identifies how a received message was delivered.
type DeliveryScope uint8

const (
	// DeliverySwarm reports an epidemic overlay delivery.
	DeliverySwarm DeliveryScope = iota
	// DeliveryNeighbors reports a direct-neighbor delivery.
	DeliveryNeighbors
)

// Event is emitted by a subscribed gossip topic.
type Event struct {
	Kind          EventKind
	Peer          key.EndpointID
	Data          []byte
	Content       []byte
	DeliveredFrom key.EndpointID
	Scope         DeliveryScope
	// Round is the PlumTree delivery round for DeliverySwarm messages.
	// It is zero for direct-neighbor delivery.
	Round uint16
	// Dropped is the number of events lost before a [Lagged] event. It is
	// zero for every other kind.
	Dropped uint64
}

// GossipOption configures a Gossip instance.
type GossipOption func(*Gossip)

// WithMaxMessageSize sets the maximum postcard frame body size. Non-positive
// values use the Rust default.
func WithMaxMessageSize(n int) GossipOption {
	return func(g *Gossip) {
		if n > 0 {
			g.maxMessageSize = gossipproto.NormalizeMaxMessageSize(n)
		}
	}
}

// Gossip publishes and subscribes to iroh-gossip topics.
//
// Register [Gossip.Handler] with an iroh Router under [ALPN].
type Gossip struct {
	ep             *iroh.Endpoint
	maxMessageSize int

	mu          sync.Mutex
	state       *gossipproto.State
	topics      map[TopicID]map[*Topic]struct{}
	neighbors   map[TopicID]map[PeerID]struct{}
	peerAddrs   map[PeerID]netaddr.EndpointAddr
	peerSenders map[PeerID]*Sender
	metrics     gossipMetrics
	closed      bool
	// joinWait is closed and replaced whenever a topic's neighbor set
	// changes or a topic closes, waking every Joined caller.
	joinWait chan struct{}
}

// NewGossip returns a Gossip instance for ep.
func NewGossip(ep *iroh.Endpoint, opts ...GossipOption) *Gossip {
	g := &Gossip{
		ep:             ep,
		maxMessageSize: gossipproto.DefaultMaxMessageSize,
		topics:         make(map[TopicID]map[*Topic]struct{}),
		neighbors:      make(map[TopicID]map[PeerID]struct{}),
		peerAddrs:      make(map[PeerID]netaddr.EndpointAddr),
		peerSenders:    make(map[PeerID]*Sender),
	}
	for _, opt := range opts {
		opt(g)
	}
	if ep != nil {
		config := gossipproto.DefaultConfig()
		config.MaxMessageSize = g.maxMessageSize
		g.state = gossipproto.NewState(peerIDFromEndpoint(ep.ID()), nil, config)
	}
	return g
}

// MaxMessageSize returns the normalized gossip frame body size.
func (g *Gossip) MaxMessageSize() int {
	if g == nil {
		return gossipproto.DefaultMaxMessageSize
	}
	return gossipproto.NormalizeMaxMessageSize(g.maxMessageSize)
}

// Handler returns the protocol handler for registering this Gossip with an
// iroh Router.
func (g *Gossip) Handler() iroh.ProtocolHandler { return g }

// Metrics returns a point-in-time snapshot of gossip counters.
func (g *Gossip) Metrics() Metrics {
	if g == nil {
		return Metrics{}
	}
	return g.metrics.snapshot()
}

// Shutdown closes topic subscriptions and open topic send streams.
func (g *Gossip) Shutdown(ctx context.Context) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	var out []gossipproto.OutEvent
	now := time.Now()
	for topic, subs := range g.topics {
		out = append(out, g.handleLocked(gossipproto.InEvent{
			Kind:  gossipproto.CommandEvent,
			Topic: topic,
			Command: gossipproto.TopicCommand{
				Kind: gossipproto.TopicCommandQuit,
			},
			Now: now,
		})...)
		for t := range subs {
			t.closeEvents()
		}
	}
	g.topics = make(map[TopicID]map[*Topic]struct{})
	g.wakeJoinWaiters()
	senders := make([]*Sender, 0, len(g.peerSenders))
	for peer, sender := range g.peerSenders {
		delete(g.peerSenders, peer)
		senders = append(senders, sender)
	}
	g.mu.Unlock()
	g.dispatch(ctx, out)
	for _, sender := range senders {
		_ = sender.Close()
	}
}

// Accept handles one incoming iroh-gossip connection.
func (g *Gossip) Accept(ctx context.Context, conn *iroh.Conn) error {
	if g == nil {
		return errors.New("gossip: nil Gossip")
	}
	from := peerIDFromEndpoint(conn.RemoteID())
	g.metrics.actorTickEndpoint.Add(1)
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return errors.New("gossip: closed")
	}
	sender := NewSender(conn, g.maxMessageSize)
	g.peerSenders[from] = sender
	g.mu.Unlock()

	h := Handler{
		MaxMessageSize: g.maxMessageSize,
		Handle: func(ctx context.Context, from key.EndpointID, msg Message) error {
			return g.receive(ctx, from, msg)
		},
	}
	err := h.Accept(ctx, conn)
	g.mu.Lock()
	if g.peerSenders[from] == sender {
		delete(g.peerSenders, from)
	}
	out := g.handleLocked(gossipproto.InEvent{
		Kind: gossipproto.PeerDisconnected,
		Peer: from,
		Now:  time.Now(),
	})
	g.mu.Unlock()
	g.dispatch(ctx, out)
	return err
}

// Subscribe joins topic and returns a local handle for publishing and receiving
// events. Bootstrap peers are dialed as needed.
func (g *Gossip) Subscribe(ctx context.Context, topic TopicID, bootstrap []netaddr.EndpointAddr) (*Topic, error) {
	return g.SubscribeWithOpts(ctx, topic, JoinOptions{Bootstrap: bootstrap})
}

// SubscribeWithOpts joins topic with opts and returns a local handle for
// publishing and receiving events.
func (g *Gossip) SubscribeWithOpts(ctx context.Context, topic TopicID, opts JoinOptions) (*Topic, error) {
	if g == nil || g.ep == nil || g.state == nil {
		return nil, errors.New("gossip: nil Gossip")
	}
	capacity := opts.SubscriptionCapacity
	if capacity <= 0 {
		capacity = defaultTopicEventCap
	}
	bootstrap := opts.Bootstrap
	t := &Topic{
		g:      g,
		id:     topic,
		events: make(chan Event, capacity),
	}
	peers := make([]PeerID, 0, len(bootstrap))
	for _, addr := range bootstrap {
		if addr.ID.IsZero() {
			continue
		}
		peer := peerIDFromEndpoint(addr.ID)
		peers = append(peers, peer)
	}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, errors.New("gossip: closed")
	}
	for _, addr := range bootstrap {
		if addr.ID.IsZero() {
			continue
		}
		g.peerAddrs[peerIDFromEndpoint(addr.ID)] = addr
	}
	if g.topics[topic] == nil {
		g.topics[topic] = make(map[*Topic]struct{})
	}
	g.topics[topic][t] = struct{}{}
	out := g.handleLocked(gossipproto.InEvent{
		Kind:  gossipproto.CommandEvent,
		Topic: topic,
		Command: gossipproto.TopicCommand{
			Kind:  gossipproto.TopicCommandJoin,
			Peers: peers,
		},
		Now: time.Now(),
	})
	g.mu.Unlock()
	g.dispatch(ctx, out)
	return t, nil
}

// SubscribeAndJoin subscribes to topic and waits until it has a direct neighbor.
func (g *Gossip) SubscribeAndJoin(ctx context.Context, topic TopicID, bootstrap []netaddr.EndpointAddr) (*Topic, error) {
	t, err := g.SubscribeWithOpts(ctx, topic, JoinOptions{Bootstrap: bootstrap})
	if err != nil {
		return nil, err
	}
	if err := t.Joined(ctx); err != nil {
		_ = t.Close()
		return nil, err
	}
	return t, nil
}

func (g *Gossip) receive(ctx context.Context, from key.EndpointID, msg Message) error {
	g.metrics.actorTickRx.Add(1)
	g.metrics.recordRecv(gossipproto.TopicMessage(msg.Message))
	g.mu.Lock()
	out := g.handleLocked(gossipproto.InEvent{
		Kind:    gossipproto.RecvMessage,
		From:    peerIDFromEndpoint(from),
		Message: gossipproto.Message(msg),
		Now:     time.Now(),
	})
	g.mu.Unlock()
	g.dispatch(ctx, out)
	return nil
}

func (g *Gossip) command(ctx context.Context, topic TopicID, cmd gossipproto.TopicCommand) error {
	g.metrics.actorTickInEventRx.Add(1)
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return errors.New("gossip: closed")
	}
	out := g.handleLocked(gossipproto.InEvent{
		Kind:    gossipproto.CommandEvent,
		Topic:   topic,
		Command: cmd,
		Now:     time.Now(),
	})
	g.mu.Unlock()
	g.dispatch(ctx, out)
	return nil
}

func (g *Gossip) closeTopic(t *Topic) error {
	g.mu.Lock()
	alreadyClosed := t.isClosed()
	if !alreadyClosed {
		t.closeEvents()
	}
	delete(g.topics[t.id], t)
	g.wakeJoinWaiters()
	empty := len(g.topics[t.id]) == 0
	if empty {
		delete(g.topics, t.id)
	}
	var out []gossipproto.OutEvent
	if empty && !g.closed {
		out = g.handleLocked(gossipproto.InEvent{
			Kind:  gossipproto.CommandEvent,
			Topic: t.id,
			Command: gossipproto.TopicCommand{
				Kind: gossipproto.TopicCommandQuit,
			},
			Now: time.Now(),
		})
	}
	g.mu.Unlock()
	g.dispatch(context.Background(), out)
	return nil
}

func (g *Gossip) handleLocked(in gossipproto.InEvent) []gossipproto.OutEvent {
	if g.state == nil {
		return nil
	}
	return g.state.Handle(in)
}

func (g *Gossip) dispatch(ctx context.Context, events []gossipproto.OutEvent) {
	for _, ev := range events {
		g.metrics.actorTickMain.Add(1)
		switch ev.Kind {
		case gossipproto.SendMessage:
			g.metrics.recordSend(ev.Message.Message)
			if err := g.send(ctx, ev.To, ev.Message); err != nil {
				g.mu.Lock()
				out := g.handleLocked(gossipproto.InEvent{
					Kind: gossipproto.PeerDisconnected,
					Peer: ev.To,
					Now:  time.Now(),
				})
				g.mu.Unlock()
				if len(out) > 0 {
					g.dispatch(ctx, out)
				}
			}
		case gossipproto.EmitEvent:
			g.emit(ev.Topic, ev.Event)
		case gossipproto.PeerDataEvent:
			g.emitPeerData(ev.Topic, ev.To, ev.Data)
		case gossipproto.ScheduleTimer:
			g.schedule(ev.After, ev.Timer)
		case gossipproto.DisconnectPeer:
			g.disconnect(ev.To)
		}
	}
}

func (g *Gossip) send(ctx context.Context, peer PeerID, msg gossipproto.Message) error {
	g.mu.Lock()
	sender := g.peerSenders[peer]
	addr, hasAddr := g.peerAddrs[peer]
	g.mu.Unlock()
	if sender == nil {
		if !hasAddr {
			return fmt.Errorf("gossip: no address for peer %s", peer)
		}
		if err := g.connect(ctx, peer, addr); err != nil {
			return err
		}
		g.mu.Lock()
		sender = g.peerSenders[peer]
		g.mu.Unlock()
	}
	if sender == nil {
		return fmt.Errorf("gossip: no sender for peer %s", peer)
	}
	return sender.Send(ctx, Message(msg))
}

func (g *Gossip) connect(ctx context.Context, peer PeerID, addr netaddr.EndpointAddr) error {
	g.metrics.actorTickDialer.Add(1)
	conn, err := g.ep.Connect(ctx, addr, ALPN)
	if err != nil {
		g.metrics.actorTickDialerFailure.Add(1)
		return fmt.Errorf("gossip: connect peer: %w", err)
	}
	g.metrics.actorTickDialerSuccess.Add(1)
	g.mu.Lock()
	g.peerSenders[peer] = NewSender(conn, g.maxMessageSize)
	g.mu.Unlock()
	go func() {
		_ = g.Accept(conn.Context(), conn)
	}()
	return nil
}

// joinWaiter returns a channel closed on the next neighbor-set change. Callers
// must take it before reading the neighbor set, or they can miss the wakeup for
// a change that lands between the read and the wait. g.mu must be held.
func (g *Gossip) joinWaiter() chan struct{} {
	if g.joinWait == nil {
		g.joinWait = make(chan struct{})
	}
	return g.joinWait
}

// wakeJoinWaiters wakes every Joined caller. g.mu must be held.
func (g *Gossip) wakeJoinWaiters() {
	if g.joinWait != nil {
		close(g.joinWait)
		g.joinWait = nil
	}
}

func (g *Gossip) emit(topic TopicID, ev gossipproto.TopicEvent) {
	event, ok := publicEvent(ev)
	if !ok {
		return
	}
	g.mu.Lock()
	if ev.Kind == gossipproto.TopicNeighborUp {
		g.metrics.neighborUp.Add(1)
		if g.neighbors[topic] == nil {
			g.neighbors[topic] = make(map[PeerID]struct{})
		}
		g.neighbors[topic][ev.Peer] = struct{}{}
		g.wakeJoinWaiters()
	} else if ev.Kind == gossipproto.TopicNeighborDown {
		g.metrics.neighborDown.Add(1)
		delete(g.neighbors[topic], ev.Peer)
		g.wakeJoinWaiters()
	}
	subs := make([]*Topic, 0, len(g.topics[topic]))
	for t := range g.topics[topic] {
		subs = append(subs, t)
	}
	g.mu.Unlock()
	for _, t := range subs {
		t.sendEvent(event)
	}
}

func (g *Gossip) emitPeerData(topic TopicID, peer PeerID, data *gossipproto.PeerData) {
	id, err := endpointFromPeerID(peer)
	if err != nil {
		return
	}
	ev := Event{Kind: PeerData, Peer: id}
	if data != nil {
		ev.Data = append([]byte(nil), (*data)...)
	}
	g.mu.Lock()
	subs := make([]*Topic, 0, len(g.topics[topic]))
	for t := range g.topics[topic] {
		subs = append(subs, t)
	}
	g.mu.Unlock()
	for _, t := range subs {
		t.sendEvent(ev)
	}
}

func (g *Gossip) schedule(after time.Duration, timer gossipproto.Timer) {
	if after < 0 {
		after = 0
	}
	time.AfterFunc(after, func() {
		g.metrics.actorTickTimers.Add(1)
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			return
		}
		out := g.handleLocked(gossipproto.InEvent{
			Kind:  gossipproto.TimerExpired,
			Timer: timer,
			Now:   time.Now(),
		})
		g.mu.Unlock()
		g.dispatch(context.Background(), out)
	})
}

func (g *Gossip) disconnect(peer PeerID) {
	g.mu.Lock()
	sender := g.peerSenders[peer]
	delete(g.peerSenders, peer)
	g.mu.Unlock()
	if sender != nil {
		_ = sender.Close()
	}
}

// Topic is a local subscription to one gossip topic.
type Topic struct {
	g      *Gossip
	id     TopicID
	events chan Event

	mu      sync.Mutex
	closed  bool
	dropped uint64 // events dropped since the last Lagged; a marker is owed while non-zero
}

// ID returns the topic ID.
func (t *Topic) ID() TopicID { return t.id }

// Split returns separate sender and receiver handles for t.
func (t *Topic) Split() (*Sender, *Receiver) {
	return &Sender{topic: t}, &Receiver{topic: t}
}

// Broadcast sends content to the topic's epidemic overlay.
func (t *Topic) Broadcast(ctx context.Context, content []byte) error {
	if t.isClosed() {
		return errors.New("gossip: topic closed")
	}
	return t.g.command(ctx, t.id, gossipproto.TopicCommand{
		Kind:    gossipproto.TopicCommandBroadcast,
		Content: append([]byte(nil), content...),
		Scope:   gossipproto.ScopeSwarm,
	})
}

// Broadcast sends content to the sender's topic epidemic overlay.
func (s *Sender) Broadcast(ctx context.Context, content []byte) error {
	if s == nil || s.topic == nil {
		return errors.New("gossip: nil topic sender")
	}
	return s.topic.Broadcast(ctx, content)
}

// BroadcastNeighbors sends content to the topic's direct neighbors.
func (t *Topic) BroadcastNeighbors(ctx context.Context, content []byte) error {
	if t.isClosed() {
		return errors.New("gossip: topic closed")
	}
	return t.g.command(ctx, t.id, gossipproto.TopicCommand{
		Kind:    gossipproto.TopicCommandBroadcast,
		Content: append([]byte(nil), content...),
		Scope:   gossipproto.ScopeNeighbors,
	})
}

// BroadcastNeighbors sends content to the sender's direct topic neighbors.
func (s *Sender) BroadcastNeighbors(ctx context.Context, content []byte) error {
	if s == nil || s.topic == nil {
		return errors.New("gossip: nil topic sender")
	}
	return s.topic.BroadcastNeighbors(ctx, content)
}

// JoinPeers dials and joins additional peers for this topic.
func (t *Topic) JoinPeers(ctx context.Context, peers []netaddr.EndpointAddr) error {
	if t.isClosed() {
		return errors.New("gossip: topic closed")
	}
	ids := make([]PeerID, 0, len(peers))
	t.g.mu.Lock()
	for _, addr := range peers {
		if addr.ID.IsZero() {
			continue
		}
		peer := peerIDFromEndpoint(addr.ID)
		ids = append(ids, peer)
		t.g.peerAddrs[peer] = addr
	}
	t.g.mu.Unlock()
	return t.g.command(ctx, t.id, gossipproto.TopicCommand{
		Kind:  gossipproto.TopicCommandJoin,
		Peers: ids,
	})
}

// JoinPeers dials and joins additional peers for the sender's topic.
func (s *Sender) JoinPeers(ctx context.Context, peers []netaddr.EndpointAddr) error {
	if s == nil || s.topic == nil {
		return errors.New("gossip: nil topic sender")
	}
	return s.topic.JoinPeers(ctx, peers)
}

// Joined waits until the topic has at least one direct neighbor. It observes
// the neighbor set, not the event stream, so it can run alongside
// [Topic.Events].
func (t *Topic) Joined(ctx context.Context) error {
	_, r := t.Split()
	return r.Joined(ctx)
}

// IsJoined reports whether the topic has at least one direct neighbor.
func (t *Topic) IsJoined() bool {
	_, r := t.Split()
	return r.IsJoined()
}

// Neighbors returns the topic's current direct neighbors.
func (t *Topic) Neighbors() []key.EndpointID {
	_, r := t.Split()
	return r.Neighbors()
}

// Events returns the topic event stream.
//
// The stream starts at Subscribe, not at the call to Events: events that
// arrive before the first call are buffered, so a caller that joins peers and
// only then reads still sees the NeighborUp events for that join. The buffer
// holds [JoinOptions.SubscriptionCapacity] events; a receiver that falls
// further behind loses events and sees a single [Lagged] event marking the
// gap, but keeps the stream. Only [Topic.Close] ends it.
func (t *Topic) Events() iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		for ev := range t.events {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

// Close leaves the topic when this is its last local subscription.
func (t *Topic) Close() error { return t.g.closeTopic(t) }

// Receiver receives events for a gossip topic.
type Receiver struct {
	topic *Topic
}

// Events returns the receiver's topic event stream.
func (r *Receiver) Events() iter.Seq2[Event, error] {
	if r == nil || r.topic == nil {
		return nil
	}
	return r.topic.Events()
}

// Joined waits until the receiver's topic has at least one direct neighbor.
//
// Joined observes the topic's neighbor set, not its event stream, so it can run
// alongside [Receiver.Events] without either one taking the other's events.
func (r *Receiver) Joined(ctx context.Context) error {
	if r == nil || r.topic == nil || r.topic.g == nil {
		return errors.New("gossip: nil receiver")
	}
	g := r.topic.g
	for {
		// Take the waiter before reading the state it reports on, so a
		// neighbor arriving in between wakes this call instead of being
		// missed until the next change.
		g.mu.Lock()
		wait := g.joinWaiter()
		g.mu.Unlock()
		if r.IsJoined() {
			return nil
		}
		if r.topic.isClosed() {
			return errors.New("gossip: topic closed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait:
		}
	}
}

// IsJoined reports whether the receiver's topic has at least one direct neighbor.
func (r *Receiver) IsJoined() bool {
	return len(r.Neighbors()) > 0
}

// Neighbors returns the receiver's current direct neighbors.
func (r *Receiver) Neighbors() []key.EndpointID {
	if r == nil || r.topic == nil || r.topic.g == nil {
		return nil
	}
	r.topic.g.mu.Lock()
	defer r.topic.g.mu.Unlock()
	peers := r.topic.g.neighbors[r.topic.id]
	out := make([]key.EndpointID, 0, len(peers))
	for peer := range peers {
		id, err := endpointFromPeerID(peer)
		if err == nil {
			out = append(out, id)
		}
	}
	return out
}

// sendEvent queues ev for the topic's subscriber. A subscriber that is not
// keeping up loses events, not the stream: sendEvent drops ev and counts it,
// and the next event the subscriber can accept is preceded by one Lagged event
// reporting how many were lost. Only [Topic.closeEvents] closes the stream.
func (t *Topic) sendEvent(ev Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	if t.dropped > 0 {
		// Report the gap before any event that follows it, so the subscriber
		// learns of the loss in the order it happened.
		select {
		case t.events <- Event{Kind: Lagged, Dropped: t.dropped}:
			t.dropped = 0
		default:
			t.dropped++
			return
		}
	}
	select {
	case t.events <- ev:
	default:
		t.dropped++
	}
}

func (t *Topic) closeEvents() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	close(t.events)
}

func (t *Topic) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func publicEvent(ev gossipproto.TopicEvent) (Event, bool) {
	switch ev.Kind {
	case gossipproto.TopicNeighborUp:
		id, err := endpointFromPeerID(ev.Peer)
		if err != nil {
			return Event{}, false
		}
		return Event{Kind: NeighborUp, Peer: id}, true
	case gossipproto.TopicNeighborDown:
		id, err := endpointFromPeerID(ev.Peer)
		if err != nil {
			return Event{}, false
		}
		return Event{Kind: NeighborDown, Peer: id}, true
	case gossipproto.TopicReceived:
		from, err := endpointFromPeerID(ev.DeliveredFrom)
		if err != nil {
			return Event{}, false
		}
		return Event{
			Kind:          Received,
			Content:       append([]byte(nil), ev.Content...),
			DeliveredFrom: from,
			Scope:         publicScope(ev.Scope),
			Round:         uint16(ev.Scope.Round),
		}, true
	default:
		return Event{}, false
	}
}

func publicScope(scope gossipproto.DeliveryScope) DeliveryScope {
	if scope.Kind == gossipproto.DeliveryScopeNeighbors {
		return DeliveryNeighbors
	}
	return DeliverySwarm
}

func peerIDFromEndpoint(id key.EndpointID) PeerID {
	return PeerID(id.Bytes())
}

func endpointFromPeerID(id PeerID) (key.EndpointID, error) {
	return key.NewEndpointID([32]byte(id))
}
