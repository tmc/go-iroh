package iroh

import (
	"container/list"
	"sync"

	tls "github.com/tmc/go-iroh/internal/itls/tls"
)

// maxTLSTickets is the default upper bound on cached TLS session tickets used
// for 0-RTT connection establishment. It matches the Rust iroh constant
// DEFAULT_MAX_TLS_TICKETS = 8 * 32 (iroh/src/tls.rs:33): roughly 8 tickets for
// each of 32 distinct remote endpoints, an acceptable ~150 KB cache.
const maxTLSTickets = 8 * 32

// SessionCache stores TLS 1.3 session tickets so a repeat dial to a peer can
// resume with 0-RTT early data instead of a fresh handshake. It keeps
// at most [maxTLSTickets] entries, evicting the least recently used.
//
// Entries are bucketed by TLS server name. iroh derives a unique server name
// from each peer's endpoint id (see [ServerName]), so tickets for different
// peers never collide and resuming always targets the correct identity.
//
// A SessionCache is safe for concurrent use. The zero value is not usable; call
// [NewSessionCache].
type SessionCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element // of *sessionEntry
	lru     list.List                // most recently used first
}

type sessionEntry struct {
	key     string
	session *tls.ClientSessionState
}

// NewSessionCache returns a [SessionCache] that retains at most [maxTLSTickets]
// tickets, evicting the least-recently-used entry when full.
func NewSessionCache() *SessionCache {
	return &SessionCache{entries: make(map[string]*list.Element)}
}

// Get implements [tls.ClientSessionCache]. It returns the cached session for
// sessionKey, if any.
func (c *SessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[sessionKey]
	if !ok {
		return nil, false
	}
	c.lru.MoveToFront(e)
	return e.Value.(*sessionEntry).session, true
}

// Put implements [tls.ClientSessionCache]. The TLS stack calls it when a server
// issues a session ticket. A nil session removes the entry, matching the
// [tls.ClientSessionCache] contract.
func (c *SessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[sessionKey]; ok {
		if cs == nil {
			c.lru.Remove(e)
			delete(c.entries, sessionKey)
			return
		}
		e.Value.(*sessionEntry).session = cs
		c.lru.MoveToFront(e)
		return
	}
	if cs == nil {
		return
	}
	if c.lru.Len() >= maxTLSTickets {
		oldest := c.lru.Back()
		c.lru.Remove(oldest)
		delete(c.entries, oldest.Value.(*sessionEntry).key)
	}
	c.entries[sessionKey] = c.lru.PushFront(&sessionEntry{sessionKey, cs})
}

// Len reports the number of server names that hold a ticket.
// It exists for tests and diagnostics.
func (c *SessionCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
