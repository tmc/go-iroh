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

const (
	// sendQueueCap is how many messages may wait to be written to one
	// peer, as Rust iroh-gossip's SEND_QUEUE_CAP.
	sendQueueCap = 64

	// sendWriteTimeout is how long one write to a peer, including any dial
	// it needs, may take before the peer is disconnected. A slow peer holds
	// up its senders, as in Rust iroh-gossip, but Rust waits without limit.
	// The limit is a deliberate divergence: the writes to peers that stop
	// reading stall together and time out together, so however many such
	// peers there are, they hold up the others for about this long.
	sendWriteTimeout = 10 * time.Second
)

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

	mu             sync.Mutex
	state          *gossipproto.State
	topics         map[TopicID]map[*Topic]struct{}
	neighbors      map[TopicID]map[PeerID]struct{}
	generations    map[TopicID]uint64
	nextGeneration uint64
	peerAddrs      map[PeerID]netaddr.EndpointAddr
	peerSenders    map[PeerID]*Sender
	sendQueues     map[PeerID]*sendQueue
	metrics        gossipMetrics
	closed         bool
	// joinWait is closed and replaced whenever a topic's neighbor set
	// changes or a topic closes, waking every Joined caller.
	joinWait chan struct{}

	// testHookDialed, if set, runs after a dial to peer succeeds and before
	// its connection is published.
	testHookDialed func(peer PeerID)
}

// NewGossip returns a Gossip instance for ep.
func NewGossip(ep *iroh.Endpoint, opts ...GossipOption) *Gossip {
	g := &Gossip{
		ep:             ep,
		maxMessageSize: gossipproto.DefaultMaxMessageSize,
		topics:         make(map[TopicID]map[*Topic]struct{}),
		neighbors:      make(map[TopicID]map[PeerID]struct{}),
		generations:    make(map[TopicID]uint64),
		peerAddrs:      make(map[PeerID]netaddr.EndpointAddr),
		peerSenders:    make(map[PeerID]*Sender),
		sendQueues:     make(map[PeerID]*sendQueue),
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
	g.neighbors = make(map[TopicID]map[PeerID]struct{})
	g.generations = make(map[TopicID]uint64)
	g.wakeJoinWaiters()
	g.mu.Unlock()
	_ = g.dispatch(ctx, out)

	// Let the queued Disconnect messages go out, for as long as ctx allows
	// and at most sendWriteTimeout: a peer that stopped reading is dropped
	// by its write limit, but a slow one could take that long per message.
	g.mu.Lock()
	queues := make([]*sendQueue, 0, len(g.sendQueues))
	for _, q := range g.sendQueues {
		queues = append(queues, q)
	}
	g.mu.Unlock()
	drain := time.NewTimer(sendWriteTimeout)
	defer drain.Stop()
wait:
	for _, q := range queues {
		select {
		case <-q.done:
		case <-ctx.Done():
			break wait
		case <-drain.C:
			break wait
		}
	}

	g.mu.Lock()
	var stuck []*Sender
	for peer, q := range g.sendQueues {
		stuck = append(stuck, g.dropQueueLocked(peer, q))
	}
	senders := make([]*Sender, 0, len(g.peerSenders))
	for peer, sender := range g.peerSenders {
		delete(g.peerSenders, peer)
		senders = append(senders, sender)
	}
	g.mu.Unlock()
	for _, s := range stuck {
		closeConn(s)
	}
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
			return g.receive(from, msg)
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
	_ = g.dispatch(context.Background(), out)
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
		g.nextGeneration++
		g.generations[topic] = g.nextGeneration
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
	_ = g.dispatch(context.Background(), out)
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

func (g *Gossip) receive(from key.EndpointID, msg Message) error {
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
	_ = g.dispatch(context.Background(), out)
	return nil
}

// command runs cmd on topic. Its sends wait for room in full peer queues for
// as long as ctx allows; a send that cannot wait longer is abandoned, as if
// lost, and command returns ctx.Err().
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
	return g.dispatch(ctx, out)
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
		// Quit empties the active view without NeighborDown events,
		// so forget the neighbors here.
		delete(g.topics, t.id)
		delete(g.neighbors, t.id)
		delete(g.generations, t.id)
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
	_ = g.dispatch(context.Background(), out)
	return nil
}

func (g *Gossip) handleLocked(in gossipproto.InEvent) []gossipproto.OutEvent {
	if g.state == nil {
		return nil
	}
	out := g.state.Handle(in)
	for i := range out {
		out[i].Generation = g.generations[out[i].Topic]
	}
	return out
}

// dispatch acts on events. It does not write to the network: messages are
// queued for each peer's writer. A full queue blocks the caller, which may be
// a local Broadcast or another peer's reader goroutine in receive, until the
// peer's writer makes room or the peer is dropped for exceeding
// sendWriteTimeout on a write. The wait is deliberate: it is backpressure, as
// in Rust iroh-gossip.
//
// A message that cannot wait because ctx is done is abandoned, as if lost,
// and dispatch goes on to the remaining events so the protocol state stays
// consistent. It returns ctx.Err() if any message was abandoned.
func (g *Gossip) dispatch(ctx context.Context, events []gossipproto.OutEvent) error {
	var err error
	for _, ev := range events {
		g.metrics.actorTickMain.Add(1)
		switch ev.Kind {
		case gossipproto.SendMessage:
			g.metrics.recordSend(ev.Message.Message)
			if _, qerr := g.enqueue(ctx, ev.To, sendItem{msg: ev.Message}, true); qerr != nil && err == nil {
				err = qerr
			}
		case gossipproto.EmitEvent:
			g.emit(ev.Topic, ev.Event, ev.Generation)
		case gossipproto.PeerDataEvent:
			g.emitPeerData(ev.Topic, ev.To, ev.Data, ev.Generation)
		case gossipproto.ScheduleTimer:
			g.schedule(ev.After, ev.Timer)
		case gossipproto.DisconnectPeer:
			// Behind the peer's queued messages, which include the
			// Disconnect that goes with this event. The wait is not
			// abandoned: the write limit bounds it.
			if ok, _ := g.enqueue(context.Background(), ev.To, sendItem{disconnect: true}, false); !ok {
				g.disconnect(ev.To)
			}
		}
	}
	return err
}

// A sendQueue holds the messages waiting to be written to one peer. A
// goroutine running [Gossip.writeQueue] writes them in order while the queue
// is non-empty. g.mu guards the fields.
type sendQueue struct {
	items   []sendItem
	sender  *Sender // the sender being written to, if any
	dropped bool
	room    chan struct{}   // closed when an item leaves the queue
	ctx     context.Context // canceled when the queue is dropped
	cancel  context.CancelFunc
	done    chan struct{} // closed when the writer returns
}

// A sendItem is one message for a peer, or the instruction to close its
// streams once the messages before it are written.
type sendItem struct {
	msg        gossipproto.Message
	disconnect bool
}

// enqueue queues item for peer, starting a writer if none is running, or, if
// start is false, only behind a running writer. If the queue is full, enqueue
// waits for room, for the queue to be dropped, or for ctx to be done, in which
// case it returns ctx.Err(). It needs no timer of its own: the writer is
// always busy with one write, and that write's limit drops the queue. It
// reports whether item was queued.
func (g *Gossip) enqueue(ctx context.Context, peer PeerID, item sendItem, start bool) (bool, error) {
	var q *sendQueue
	for {
		g.mu.Lock()
		if q != nil && q.dropped {
			// Dropped while we waited: the peer is gone.
			g.mu.Unlock()
			return false, nil
		}
		q = g.sendQueues[peer]
		if q == nil {
			if !start {
				g.mu.Unlock()
				return false, nil
			}
			q = &sendQueue{done: make(chan struct{})}
			q.ctx, q.cancel = context.WithCancel(context.Background())
			g.sendQueues[peer] = q
			go g.writeQueue(peer, q)
		}
		if len(q.items) < sendQueueCap {
			q.items = append(q.items, item)
			g.mu.Unlock()
			return true, nil
		}
		if q.room == nil {
			q.room = make(chan struct{})
		}
		room := q.room
		g.mu.Unlock()

		select {
		case <-room:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

// wakeLocked wakes the enqueue calls waiting for room in q. g.mu must be held.
func (q *sendQueue) wakeLocked() {
	if q.room != nil {
		close(q.room)
		q.room = nil
	}
}

// writeQueue writes q's items to peer until q is empty or dropped. A write
// that fails, or that takes longer than sendWriteTimeout, disconnects the
// peer.
func (g *Gossip) writeQueue(peer PeerID, q *sendQueue) {
	defer close(q.done)
	for {
		g.mu.Lock()
		if q.dropped || len(q.items) == 0 {
			if g.sendQueues[peer] == q {
				delete(g.sendQueues, peer)
			}
			q.cancel()
			g.mu.Unlock()
			return
		}
		item := q.items[0]
		q.items = q.items[1:]
		q.wakeLocked()
		g.mu.Unlock()

		if item.disconnect {
			g.disconnect(peer)
			continue
		}
		// Closing the connection is the only way to end a stalled
		// write: it does not watch q.ctx once it is underway.
		limit := time.AfterFunc(sendWriteTimeout, func() { g.dropPeer(peer, q) })
		err := g.send(q, peer, item.msg)
		limit.Stop()
		if err != nil {
			g.dropPeer(peer, q)
			return
		}
	}
}

// dropPeer disconnects peer after a failed or stalled send: it drops the
// peer's send queue, closing the connection a write may be blocked on, and
// tells the protocol the peer is gone. It does nothing if q is no longer the
// peer's queue.
func (g *Gossip) dropPeer(peer PeerID, q *sendQueue) {
	g.mu.Lock()
	if q.dropped || g.sendQueues[peer] != q {
		g.mu.Unlock()
		return
	}
	stuck := g.dropQueueLocked(peer, q)
	out := g.handleLocked(gossipproto.InEvent{
		Kind: gossipproto.PeerDisconnected,
		Peer: peer,
		Now:  time.Now(),
	})
	g.mu.Unlock()
	closeConn(stuck)
	_ = g.dispatch(context.Background(), out)
}

// dropQueueLocked discards q's pending items and stops its writer. It returns
// the sender the writer may be blocked on, whose connection the caller must
// close with [closeConn] after releasing g.mu. g.mu must be held.
func (g *Gossip) dropQueueLocked(peer PeerID, q *sendQueue) *Sender {
	q.dropped = true
	q.items = nil
	q.wakeLocked()
	q.cancel()
	if g.sendQueues[peer] == q {
		delete(g.sendQueues, peer)
	}
	if q.sender != nil && g.peerSenders[peer] == q.sender {
		delete(g.peerSenders, peer)
	}
	return q.sender
}

// closeConn closes the connection of a sender whose writes are being
// abandoned, unblocking any write in progress.
func closeConn(s *Sender) {
	if s != nil {
		_ = s.conn.CloseWithError(0, "gossip: peer dropped")
	}
}

// send writes msg to peer, dialing it first if there is no connection.
func (g *Gossip) send(q *sendQueue, peer PeerID, msg gossipproto.Message) error {
	g.mu.Lock()
	sender := g.peerSenders[peer]
	addr, hasAddr := g.peerAddrs[peer]
	g.mu.Unlock()
	if sender == nil {
		if !hasAddr {
			return fmt.Errorf("gossip: no address for peer %s", peer)
		}
		var err error
		if sender, err = g.connect(q, peer, addr); err != nil {
			return err
		}
	}
	if sender == nil {
		return fmt.Errorf("gossip: no sender for peer %s", peer)
	}
	g.mu.Lock()
	if q.dropped {
		g.mu.Unlock()
		return errors.New("gossip: send queue dropped")
	}
	q.sender = sender
	g.mu.Unlock()
	return sender.Send(q.ctx, Message(msg))
}

// connect dials peer for q's writer and publishes the connection as q's
// sender. If q is dropped while the dial is in flight, as a timed-out write
// drops it, the new connection is closed instead: nothing would own it.
func (g *Gossip) connect(q *sendQueue, peer PeerID, addr netaddr.EndpointAddr) (*Sender, error) {
	g.metrics.actorTickDialer.Add(1)
	conn, err := g.ep.Connect(q.ctx, addr, ALPN)
	if err != nil {
		g.metrics.actorTickDialerFailure.Add(1)
		return nil, fmt.Errorf("gossip: connect peer: %w", err)
	}
	g.metrics.actorTickDialerSuccess.Add(1)
	if g.testHookDialed != nil {
		g.testHookDialed(peer)
	}
	sender := NewSender(conn, g.maxMessageSize)
	g.mu.Lock()
	if q.dropped {
		g.mu.Unlock()
		closeConn(sender)
		return nil, errors.New("gossip: send queue dropped")
	}
	g.peerSenders[peer] = sender
	q.sender = sender
	g.mu.Unlock()
	go func() {
		_ = g.Accept(conn.Context(), conn)
	}()
	return sender, nil
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

func (g *Gossip) emit(topic TopicID, ev gossipproto.TopicEvent, generation uint64) {
	event, ok := publicEvent(ev)
	if !ok {
		return
	}
	g.mu.Lock()
	if g.generations[topic] != generation {
		g.mu.Unlock()
		return
	}
	if ev.Kind == gossipproto.TopicNeighborUp {
		g.metrics.neighborUp.Add(1)
		if g.topics[topic] == nil {
			// Dispatched after the topic closed: do not revive it.
			g.mu.Unlock()
			return
		}
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

func (g *Gossip) emitPeerData(topic TopicID, peer PeerID, data *gossipproto.PeerData, generation uint64) {
	id, err := endpointFromPeerID(peer)
	if err != nil {
		return
	}
	ev := Event{Kind: PeerData, Peer: id}
	if data != nil {
		ev.Data = append([]byte(nil), (*data)...)
	}
	g.mu.Lock()
	if g.generations[topic] != generation {
		g.mu.Unlock()
		return
	}
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
		_ = g.dispatch(context.Background(), out)
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
//
// If a neighbor is not keeping up, Broadcast waits for it until ctx is done;
// then content is not sent to that neighbor, and Broadcast returns ctx.Err().
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

// BroadcastNeighbors sends content to the topic's direct neighbors. It waits
// for a neighbor that is not keeping up as [Topic.Broadcast] does.
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
		joined := len(g.neighbors[r.topic.id]) > 0
		g.mu.Unlock()
		if r.topic.isClosed() {
			return errors.New("gossip: topic closed")
		}
		if joined {
			return nil
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
