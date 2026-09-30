package gossip

// SendWriteTimeout is sendWriteTimeout, for tests.
const SendWriteTimeout = sendWriteTimeout

// SetDialedHook sets f to run after g dials a peer and before it publishes
// the connection.
func (g *Gossip) SetDialedHook(f func(peer PeerID)) { g.testHookDialed = f }

// DropPeer drops peer's send queue, as a timed-out write does.
func (g *Gossip) DropPeer(peer PeerID) {
	g.mu.Lock()
	q := g.sendQueues[peer]
	g.mu.Unlock()
	if q != nil {
		g.dropPeer(peer, q)
	}
}

// HasSender reports whether g holds a connection for sending to peer.
func (g *Gossip) HasSender(peer PeerID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peerSenders[peer] != nil
}

// RejoinDelay is rejoinDelay, for tests.
const RejoinDelay = rejoinDelay
