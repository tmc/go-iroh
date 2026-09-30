package docs

import (
	"sync"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

const storeBroadcastCapacity = 8

// StoreEventKind tags the variant of a [StoreEvent].
type StoreEventKind uint8

const (
	// StoreEventInsertLocal reports a locally inserted entry.
	StoreEventInsertLocal StoreEventKind = iota
	// StoreEventInsertRemote reports an entry inserted from a peer.
	StoreEventInsertRemote
	// StoreEventLagged reports that a subscriber missed events.
	StoreEventLagged
	// StoreEventContentReady reports that entry content is now locally available.
	StoreEventContentReady
)

func storeEventKind(kind InsertOriginKind) StoreEventKind {
	if kind == InsertOriginRemote {
		return StoreEventInsertRemote
	}
	return StoreEventInsertLocal
}

// StoreEvent reports a store insertion or subscriber lag.
type StoreEvent struct {
	// Kind is which kind of event this is.
	Kind StoreEventKind
	// Sequence is the store-local event sequence.
	Sequence uint64
	// Entry is the inserted entry. It is zero for StoreEventLagged.
	Entry SignedEntry
	// Hash is the content hash for StoreEventContentReady.
	Hash blobs.Hash
	// Removed is the number of older descendant entries removed by the insert.
	Removed int
	// From is the peer an inserted entry came from. It is zero for local inserts.
	From key.EndpointID
	// ContentStatus is the content status given with a remote insert. For an
	// entry synced by range reconciliation, it is the sending peer's status.
	ContentStatus ContentStatus
	// Missed is the number of dropped events for StoreEventLagged.
	Missed uint64
}

type storeWatcher struct {
	mu     sync.Mutex
	subs   map[*storeSub]struct{}
	closed bool
}

type storeSub struct {
	mu     sync.Mutex
	cond   *sync.Cond
	ring   []StoreEvent
	missed uint64
	lagged bool
	closed bool

	ch   chan StoreEvent
	done chan struct{}
	once sync.Once
}

func newStoreWatcher() *storeWatcher {
	return &storeWatcher{subs: make(map[*storeSub]struct{})}
}

// Subscribe registers a subscriber. Events sent before Subscribe are not
// replayed. The returned cancel function stops delivery and closes the channel.
func (w *storeWatcher) Subscribe() (<-chan StoreEvent, func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := &storeSub{
		ch:   make(chan StoreEvent, storeBroadcastCapacity+1),
		done: make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	if w.closed {
		close(s.ch)
		s.closed = true
		return s.ch, func() {}
	}
	w.subs[s] = struct{}{}
	go s.deliver()
	return s.ch, func() { w.unsubscribe(s) }
}

func (w *storeWatcher) unsubscribe(s *storeSub) {
	w.mu.Lock()
	if _, ok := w.subs[s]; !ok {
		w.mu.Unlock()
		return
	}
	delete(w.subs, s)
	w.mu.Unlock()
	s.close()
}

// Send broadcasts ev to every subscriber. Send never blocks.
func (w *storeWatcher) Send(ev StoreEvent) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	subs := make([]*storeSub, 0, len(w.subs))
	for s := range w.subs {
		subs = append(subs, s)
	}
	w.mu.Unlock()
	for _, s := range subs {
		s.enqueue(ev)
	}
}

// Close stops every subscriber and rejects future sends and subscriptions.
func (w *storeWatcher) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	subs := make([]*storeSub, 0, len(w.subs))
	for s := range w.subs {
		subs = append(subs, s)
	}
	w.subs = make(map[*storeSub]struct{})
	w.mu.Unlock()
	for _, s := range subs {
		s.close()
	}
}

func (s *storeSub) enqueue(ev StoreEvent) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if len(s.ring) >= storeBroadcastCapacity {
		s.ring = s.ring[1:]
		s.missed++
		s.lagged = true
	}
	s.ring = append(s.ring, ev)
	s.cond.Signal()
	s.mu.Unlock()
}

func (s *storeSub) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cond.Signal()
	s.mu.Unlock()
	s.once.Do(func() { close(s.done) })
}

func (s *storeSub) deliver() {
	for {
		s.mu.Lock()
		for !s.closed && !s.lagged && len(s.ring) == 0 {
			s.cond.Wait()
		}
		if s.closed && !s.lagged && len(s.ring) == 0 {
			s.mu.Unlock()
			close(s.ch)
			return
		}
		var out StoreEvent
		if s.lagged {
			out = StoreEvent{Kind: StoreEventLagged, Missed: s.missed}
			s.lagged = false
			s.missed = 0
		} else {
			out = s.ring[0]
			s.ring = s.ring[1:]
		}
		s.mu.Unlock()
		select {
		case s.ch <- out:
			continue
		default:
		}
		select {
		case s.ch <- out:
		case <-s.done:
			close(s.ch)
			return
		}
	}
}
