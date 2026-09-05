package socket

import (
	"context"
	"crypto/rand"
	"errors"
	mrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tmc/go-iroh/internal/relayclient"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/watch"
)

// Relay actor timing constants, matching the Rust reference
// (iroh/src/socket/transports/relay/actor.rs).
const (
	// relayInactiveCleanupTime is how long a non-home relay connection may be
	// idle (no datagram sent) before it is closed. The home relay connection
	// never idles out. iroh/src/socket/transports/relay/actor.rs:67.
	relayInactiveCleanupTime = 60 * time.Second

	// pingInterval is how often the actor pings the relay to confirm the
	// connection is alive. It is stricter than the QUIC idle timeout so broken
	// relays are detected faster. iroh/src/socket/transports/relay/actor.rs:73.
	pingInterval = 15 * time.Second

	// sendDatagramBatchSize is the number of datagrams sent to the relay in one
	// batch. iroh/src/socket/transports/relay/actor.rs:80.
	sendDatagramBatchSize = 20

	// connectTimeout bounds establishing a relay connection (dial + handshake).
	// iroh/src/socket/transports/relay/actor.rs:86.
	connectTimeout = 10 * time.Second

	// undeliverableDatagramTimeout is how long datagrams queued while dialing
	// are held before being dropped. QUIC loss recovery retransmits.
	// iroh/src/socket/transports/relay/actor.rs:95.
	undeliverableDatagramTimeout = 3 * time.Second
)

// Backoff bounds for reconnection, matching the Rust ExponentialBuilder
// (iroh/src/socket/transports/relay/actor.rs:352).
const (
	backoffMinDelay = 10 * time.Millisecond
	backoffMaxDelay = 16 * time.Second
)

// Relay ping timeout bounds, matching iroh-relay's PingTracker.
const (
	relayPingTimeoutMin = 500 * time.Millisecond
	relayPingTimeoutMax = 5 * time.Second
)

// Channel depths, matching the Rust reference
// (iroh/src/socket/transports/relay.rs:46 and actor.rs:1254).
const (
	relayRecvQueueDepth   = 512
	relaySendChannelDepth = 256
	perRelaySendDepth     = 64
)

// RelayConnState is the connection state of a relay, published through the home
// relay watcher. It is the Go analog of the Rust RelayConnectionState
// (iroh/src/socket/transports/relay/actor.rs:897).
type RelayConnState int

const (
	// RelayConnecting means the actor is dialing or handshaking.
	RelayConnecting RelayConnState = iota
	// RelayConnected means the connection is established and handshaked.
	RelayConnected
	// RelayDisconnected means there is no connection: an attempt failed or a
	// previously-established connection was lost.
	RelayDisconnected
)

func (s RelayConnState) String() string {
	switch s {
	case RelayConnecting:
		return "connecting"
	case RelayConnected:
		return "connected"
	case RelayDisconnected:
		return "disconnected"
	default:
		return "unknown"
	}
}

// RelayStatus is the connection status of a single home relay, observed through
// [RelayActor.HomeRelayStatus]. It is the Go analog of the Rust RelayStatus
// (iroh/src/endpoint.rs:1832).
//
// The zero value reports no home relay; use [RelayActor.HomeRelayStatus] to
// observe it.
type RelayStatus struct {
	// URL is the home relay URL.
	URL netaddr.RelayURL
	// State is the current connection state.
	State RelayConnState
	// LastError is the most recent connection error while disconnected, or nil.
	LastError error
}

// IsConnected reports whether the relay is connected.
func (s RelayStatus) IsConnected() bool { return s.State == RelayConnected }

// RelaySendItem is one or more datagrams to send to a remote endpoint via a
// relay. It is the Go analog of the Rust RelaySendItem
// (iroh/src/socket/transports/relay/actor.rs:846).
type RelaySendItem struct {
	// RemoteEndpoint is the destination endpoint.
	RemoteEndpoint key.EndpointID
	// URL is the relay through which to reach RemoteEndpoint.
	URL netaddr.RelayURL
	// Datagrams is the payload.
	Datagrams relayproto.Datagrams
}

// RelayRecvDatagram is a datagram received from a relay. It is the Go analog of
// the Rust RelayRecvDatagram (iroh/src/socket/transports/relay/actor.rs:1383).
type RelayRecvDatagram struct {
	// URL is the relay it arrived on.
	URL netaddr.RelayURL
	// Src is the endpoint that sent it.
	Src key.EndpointID
	// Datagrams is the payload.
	Datagrams relayproto.Datagrams
}

// relayDialer dials a relay client. It is an indirection point so tests can
// substitute an in-process relay without a real network dial. The default is
// [relayclient.Connect].
type relayDialer func(ctx context.Context, url netaddr.RelayURL, opts relayclient.Options) (relayClient, error)

// relayClient is the subset of [relayclient.Client] the actor uses. It exists so
// tests can supply a fake client implementing the same Send/Recv/Close surface.
type relayClient interface {
	Send(ctx context.Context, msg relayproto.ClientToRelayMsg) error
	Recv(ctx context.Context) (relayproto.RelayToClientMsg, error)
	Close() error
}

// defaultRelayDialer dials a real relay over WSS.
func defaultRelayDialer(ctx context.Context, url netaddr.RelayURL, opts relayclient.Options) (relayClient, error) {
	return relayclient.Connect(ctx, url, opts)
}

// RelayActorConfig configures a [RelayActor].
//
// SecretKey is required. The zero value is otherwise not usable; build a config
// and pass it to [NewRelayActor].
type RelayActorConfig struct {
	// SecretKey is the local endpoint's secret key, used to authenticate to
	// relays. Required.
	SecretKey key.SecretKey
	// Map is the relay map; consulted for per-relay auth tokens.
	Map *relay.Map
	// dialer overrides the relay dial function. nil uses [defaultRelayDialer].
	dialer relayDialer
}

// RelayActor manages connections to relay servers. It starts one [activeRelay]
// per relay URL on demand, routes outgoing datagrams to the right one, and
// surfaces received datagrams on a single queue. It tracks the home relay and
// publishes its status through a [watch.Value].
//
// It is the Go analog of the Rust RelayActor
// (iroh/src/socket/transports/relay/actor.rs:855). Create one with
// [NewRelayActor] and start it with [RelayActor.Run].
type RelayActor struct {
	cfg     RelayActorConfig
	dialer  relayDialer
	recvCh  chan RelayRecvDatagram
	sendCh  chan RelaySendItem
	homeURL *watch.Value[*RelayStatus]

	// metrics is the shared magic-socket counter set, or nil. It is set by the
	// owning MagicConn before the actor runs.
	metrics atomic.Pointer[Metrics]

	mu     sync.Mutex
	active map[string]*activeRelay // key: RelayURL.String()
	home   netaddr.RelayURL
	closed bool

	wg sync.WaitGroup
}

// setMetrics records the counter set frame handlers report into.
func (a *RelayActor) setMetrics(m *Metrics) {
	if a != nil {
		a.metrics.Store(m)
	}
}

// NewRelayActor returns a RelayActor ready to be started with [RelayActor.Run].
func NewRelayActor(cfg RelayActorConfig) *RelayActor {
	dialer := cfg.dialer
	if dialer == nil {
		dialer = defaultRelayDialer
	}
	if cfg.Map == nil {
		cfg.Map = relay.NewMap()
	} else {
		cfg.Map = cfg.Map.Clone()
	}
	return &RelayActor{
		cfg:     cfg,
		dialer:  dialer,
		recvCh:  make(chan RelayRecvDatagram, relayRecvQueueDepth),
		sendCh:  make(chan RelaySendItem, relaySendChannelDepth),
		homeURL: watch.NewValueFunc[*RelayStatus](nil, statusEqual),
		active:  make(map[string]*activeRelay),
	}
}

// Recv returns the queue of datagrams received from relays. A [RelayTransport]
// drains it; the channel is closed when the actor stops.
func (a *RelayActor) Recv() <-chan RelayRecvDatagram { return a.recvCh }

// HomeRelayStatus returns a watcher over the home relay's connection status. The
// value is nil until a home relay is set with [RelayActor.SetHomeRelay].
func (a *RelayActor) HomeRelayStatus() watch.Observer[*RelayStatus] {
	return a.homeURL.Watch()
}

// InsertRelay adds or replaces url's relay configuration, returning the
// previous config when one existed. If there is no home relay, url becomes home.
func (a *RelayActor) InsertRelay(url netaddr.RelayURL, cfg relay.Config) (relay.Config, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return relay.Config{}, false
	}
	cfg.URL = url
	prev, ok := a.cfg.Map.Insert(cfg)
	if a.home.IsZero() {
		a.home = url
		a.homeURL.Set(&RelayStatus{URL: url, State: RelayConnecting})
		a.ensureActiveLocked(url, true)
	}
	return prev, ok
}

// HasRelay reports whether url is currently configured.
func (a *RelayActor) HasRelay(url netaddr.RelayURL) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Map.Contains(url)
}

// RemoveRelay removes url's configuration, returning it when present. Any live
// non-home connection to url is stopped. If url was the home relay, the next
// configured relay (if any) becomes home.
func (a *RelayActor) RemoveRelay(url netaddr.RelayURL) (relay.Config, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return relay.Config{}, false
	}
	prev, ok := a.cfg.Map.Remove(url)
	if !ok {
		return relay.Config{}, false
	}
	if ar := a.active[url.String()]; ar != nil {
		ar.stop()
	}
	if !a.home.Equal(url) {
		return prev, true
	}
	a.home = netaddr.RelayURL{}
	a.homeURL.Set(nil)
	if urls := a.cfg.Map.URLs(); len(urls) > 0 {
		next := urls[0]
		a.home = next
		a.homeURL.Set(&RelayStatus{URL: next, State: RelayConnecting})
		for key, ar := range a.active {
			ar.setHome(key == next.String())
		}
		a.ensureActiveLocked(next, true)
	}
	return prev, true
}

// Send queues item for delivery to its relay. It never blocks: if the queue is
// full the item is dropped (treated as datagram loss so QUIC's loss recovery
// retransmits), matching the Rust non-blocking send invariant
// (iroh/src/socket/transports.rs:1176). Send reports whether the item was
// queued; a false result is a dropped (lost) datagram, not an error.
func (a *RelayActor) Send(item RelaySendItem) bool {
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		return false
	}
	select {
	case a.sendCh <- item:
		return true
	default:
		return false
	}
}

// SetHomeRelay designates url as the home relay, ensuring an [activeRelay] for
// it (which then never idles out) and demoting any previous home relay. A zero
// url clears the home relay. It mirrors the Rust on_network_change /
// set_home_relay path (iroh/src/socket/transports/relay/actor.rs:1126).
func (a *RelayActor) SetHomeRelay(url netaddr.RelayURL) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	if url.IsZero() {
		a.home = netaddr.RelayURL{}
		a.homeURL.Set(nil)
		for _, ar := range a.active {
			ar.setHome(false)
		}
		return
	}
	if a.home.Equal(url) {
		return
	}
	a.home = url
	// Publish Connecting on the URL change; the active actor republishes its
	// real state when it becomes home.
	a.homeURL.Set(&RelayStatus{URL: url, State: RelayConnecting})
	for key, ar := range a.active {
		ar.setHome(key == url.String())
	}
	a.ensureActiveLocked(url, true)
}

// Run drives the actor until ctx is cancelled. It starts active relays on demand
// from queued send items. It blocks; run it in its own goroutine. When it
// returns it has closed the recv channel and stopped all active relays.
func (a *RelayActor) Run(ctx context.Context) {
	defer close(a.recvCh)
	for {
		select {
		case <-ctx.Done():
			a.shutdown()
			return
		case item := <-a.sendCh:
			a.dispatch(ctx, item)
		}
	}
}

// dispatch routes a send item to the active relay for its URL, starting one if
// needed. If no actor exists for the item's URL but another active relay already
// knows a route to the endpoint, that relay is used, matching the Rust
// active_relay_handle_for_endpoint (actor.rs:1173).
func (a *RelayActor) dispatch(ctx context.Context, item RelaySendItem) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	ar, ok := a.active[item.URL.String()]
	if !ok {
		if alt := a.routeForEndpointLocked(item.RemoteEndpoint); alt != nil {
			ar = alt
		} else {
			ar = a.ensureActiveLocked(item.URL, a.home.Equal(item.URL))
		}
	}
	a.mu.Unlock()
	ar.enqueue(item)
}

// routeForEndpointLocked returns an active relay already known to route to eid,
// or nil. a.mu must be held.
func (a *RelayActor) routeForEndpointLocked(eid key.EndpointID) *activeRelay {
	for _, ar := range a.active {
		if ar.hasRoute(eid) {
			return ar
		}
	}
	return nil
}

// ensureActiveLocked returns the active relay for url, starting it if needed.
// a.mu must be held.
func (a *RelayActor) ensureActiveLocked(url netaddr.RelayURL, home bool) *activeRelay {
	key := url.String()
	if ar, ok := a.active[key]; ok {
		if home {
			ar.setHome(true)
		}
		return ar
	}
	ar := newActiveRelay(a, url, home)
	a.active[key] = ar
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ar.run()
		a.mu.Lock()
		if a.active[key] == ar {
			delete(a.active, key)
		}
		a.mu.Unlock()
	}()
	return ar
}

// shutdown stops all active relays and waits for them to exit.
func (a *RelayActor) shutdown() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	actors := make([]*activeRelay, 0, len(a.active))
	for _, ar := range a.active {
		actors = append(actors, ar)
	}
	a.mu.Unlock()
	for _, ar := range actors {
		ar.stop()
	}
	a.wg.Wait()
}

// publishStatus updates the home relay status if url is still the home relay.
// This guards against a demoted relay overwriting a newer home relay's status,
// matching the Rust HomeRelayWatch::set_status (actor.rs:985).
func (a *RelayActor) publishStatus(url netaddr.RelayURL, state RelayConnState, lastErr error) {
	a.mu.Lock()
	isHome := a.home.Equal(url)
	a.mu.Unlock()
	if !isHome {
		return
	}
	a.homeURL.Set(&RelayStatus{URL: url, State: state, LastError: lastErr})
}

// authTokenFor returns the configured auth token for url, if any.
func (a *RelayActor) authTokenFor(url netaddr.RelayURL) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.Map == nil {
		return ""
	}
	if c, ok := a.cfg.Map.Get(url); ok {
		return c.AuthToken
	}
	return ""
}

// statusEqual compares two home relay statuses for the watcher's change
// suppression. Errors are compared by identity so a fresh error always notifies,
// matching the Rust Arc::ptr_eq comparison (actor.rs:931).
func statusEqual(a, b *RelayStatus) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.URL.Equal(b.URL) && a.State == b.State && a.LastError == b.LastError
}

// activeRelay manages the connection to a single relay server. It runs a state
// machine: dial (with exponential backoff) then connected (with ping/pong
// keepalive and idle close for non-home relays). It is the Go analog of the Rust
// ActiveRelayActor (iroh/src/socket/transports/relay/actor.rs:126).
type activeRelay struct {
	parent *RelayActor
	url    netaddr.RelayURL

	sendCh   chan RelaySendItem
	batchBuf []byte
	stopCh   chan struct{}
	stopOnce sync.Once

	mu      sync.Mutex
	isHome  bool
	routes  map[key.EndpointID]struct{}
	lastSrc key.EndpointID
	haveSrc bool
}

// newActiveRelay returns an active relay for url. home marks it the home relay
// (which never idles out).
func newActiveRelay(parent *RelayActor, url netaddr.RelayURL, home bool) *activeRelay {
	return &activeRelay{
		parent: parent,
		url:    url,
		sendCh: make(chan RelaySendItem, perRelaySendDepth),
		stopCh: make(chan struct{}),
		isHome: home,
		routes: make(map[key.EndpointID]struct{}),
	}
}

// enqueue queues item for sending. It never blocks: a full queue drops the item
// (datagram loss; QUIC retransmits).
func (r *activeRelay) enqueue(item RelaySendItem) {
	select {
	case r.sendCh <- item:
	default:
	}
}

// stop signals the active relay to exit.
func (r *activeRelay) stop() {
	r.stopOnce.Do(func() { close(r.stopCh) })
}

// setHome marks (or unmarks) this as the home relay.
func (r *activeRelay) setHome(home bool) {
	r.mu.Lock()
	r.isHome = home
	r.mu.Unlock()
}

func (r *activeRelay) home() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.isHome
}

// hasRoute reports whether eid has been seen on this relay.
func (r *activeRelay) hasRoute(eid key.EndpointID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.routes[eid]
	return ok
}

// noteRoute records that eid is reachable on this relay.
func (r *activeRelay) noteRoute(eid key.EndpointID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.haveSrc && r.lastSrc.Equal(eid) {
		return
	}
	r.lastSrc = eid
	r.haveSrc = true
	r.routes[eid] = struct{}{}
}

// dropRoute removes eid (an EndpointGone frame).
func (r *activeRelay) dropRoute(eid key.EndpointID) {
	r.mu.Lock()
	delete(r.routes, eid)
	r.mu.Unlock()
}

// run is the top-level state machine: it repeatedly dials and serves the
// connection, applying exponential backoff between failed attempts. Backoff is
// reset only after a connection becomes established (a pong was received),
// matching the Rust run loop (actor.rs:325).
func (r *activeRelay) run() {
	delay := backoffMinDelay
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}
		established, err := r.runOnce()
		if err == nil {
			// Clean shutdown (idle timeout or stop).
			return
		}
		r.parent.publishStatus(r.url, RelayDisconnected, err)
		if established {
			// Reset backoff and reconnect immediately.
			delay = backoffMinDelay
			continue
		}
		// Dial or pre-pong failure: back off.
		select {
		case <-r.stopCh:
			return
		case <-time.After(jitter(delay)):
		}
		delay *= 2
		if delay > backoffMaxDelay {
			delay = backoffMaxDelay
		}
	}
}

// runOnce dials the relay and runs the connected loop. It returns whether the
// connection became established (a pong was received) and the error that ended
// it, or (false, nil) for a clean shutdown.
func (r *activeRelay) runOnce() (established bool, err error) {
	r.parent.publishStatus(r.url, RelayConnecting, nil)
	client, ok, derr := r.dial()
	if !ok {
		// Stopped or idled out while dialing: clean shutdown.
		return false, nil
	}
	if derr != nil {
		return false, derr
	}
	defer client.Close()
	r.parent.publishStatus(r.url, RelayConnected, nil)
	return r.runConnected(client)
}

// dial attempts to connect, draining the send queue while it waits so stale
// datagrams are dropped after undeliverableDatagramTimeout. It returns
// (client, true, nil) on success, (nil, false, nil) on a clean stop/idle, and
// (nil, true, err) on a dial failure that should be retried with backoff.
func (r *activeRelay) dial() (relayClient, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	type result struct {
		c   relayClient
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := r.parent.dialer(ctx, r.url, relayclient.Options{
			SecretKey: r.parent.cfg.SecretKey,
			AuthToken: r.parent.authTokenFor(r.url),
		})
		done <- result{c: c, err: err}
	}()

	flush := time.NewTicker(undeliverableDatagramTimeout)
	defer flush.Stop()
	idle := time.NewTimer(relayInactiveCleanupTime)
	defer idle.Stop()

	for {
		select {
		case <-r.stopCh:
			cancel()
			<-done
			return nil, false, nil
		case res := <-done:
			if res.err != nil {
				return nil, true, res.err
			}
			return res.c, true, nil
		case <-flush.C:
			// Drop datagrams that have been waiting through a dial.
			drain(r.sendCh)
		case <-idle.C:
			if !r.home() {
				cancel()
				<-done
				return nil, false, nil
			}
			idle.Reset(relayInactiveCleanupTime)
		}
	}
}

// connectedState is the per-connection mutable state of the connected loop.
type connectedState struct {
	established bool
	pendingPong [8]byte
	havePong    bool
	pingSent    [8]byte
	pingSentAt  time.Time
	awaitingPng bool
	lastRTT     time.Duration
}

// runConnected serves an established connection: it reads frames from the relay,
// sends queued datagrams in batches, sends periodic pings, and detects a stalled
// connection by ping timeout. It returns whether the connection was established
// (a pong arrived) and the error that ended it, or (established, nil) for a
// clean shutdown. It mirrors the Rust run_connected (actor.rs:506).
func (r *activeRelay) runConnected(client relayClient) (bool, error) {
	// Receive loop: read frames in a goroutine and forward them on a channel.
	// relayclient.Client is not concurrent-safe across senders, but one Recv
	// goroutine plus the sends issued from this goroutine is the supported
	// pattern (one reader, one writer).
	recvCtx, recvCancel := context.WithCancel(context.Background())
	defer recvCancel()
	frames := make(chan relayproto.RelayToClientMsg, 16)
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := client.Recv(recvCtx)
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case frames <- msg:
			case <-recvCtx.Done():
				return
			}
		}
	}()

	st := &connectedState{}
	pingTick := time.NewTicker(pingInterval)
	defer pingTick.Stop()
	pingTimeout := time.NewTimer(pingInterval)
	pingTimeout.Stop()
	defer pingTimeout.Stop()
	idle := time.NewTimer(relayInactiveCleanupTime)
	defer idle.Stop()

	// Send an initial ping immediately so we establish liveness.
	if err := r.sendPing(client, st, pingTimeout); err != nil {
		return st.established, err
	}

	sendBuf := make([]RelaySendItem, 0, sendDatagramBatchSize)
	for {
		// Send a pending pong ASAP.
		if st.havePong {
			data := st.pendingPong
			st.havePong = false
			if err := r.send(client, relayproto.ClientToRelayMsg{
				Type: relayproto.FramePong, Ping: data,
			}); err != nil {
				return st.established, err
			}
		}

		select {
		case <-r.stopCh:
			return st.established, nil
		case err := <-recvErr:
			if errors.Is(err, context.Canceled) {
				return st.established, nil
			}
			return st.established, err
		case msg := <-frames:
			wasAwaiting := st.awaitingPng
			r.handleFrame(msg, st)
			// A received message proves liveness; reset the ping interval.
			pingTick.Reset(pingInterval)
			// If this frame was the pong we were waiting for, disarm the
			// ping timeout. The timeout is shorter than pingInterval, so a
			// live connection would otherwise trip it before the next ping
			// re-arms it. Mirrors the Rust PingTracker, which cancels the
			// timeout on pong (actor.rs).
			if wasAwaiting && !st.awaitingPng {
				stopTimer(pingTimeout)
			}
		case <-pingTick.C:
			if err := r.sendPing(client, st, pingTimeout); err != nil {
				return st.established, err
			}
		case <-pingTimeout.C:
			return st.established, errPingTimeout
		case <-idle.C:
			if !r.home() {
				return st.established, nil
			}
			idle.Reset(relayInactiveCleanupTime)
		case first := <-r.sendCh:
			idle.Reset(relayInactiveCleanupTime)
			sendBuf = append(sendBuf[:0], first)
			// Coalesce up to the batch size.
			for len(sendBuf) < sendDatagramBatchSize {
				select {
				case it := <-r.sendCh:
					sendBuf = append(sendBuf, it)
				default:
					goto flush
				}
			}
		flush:
			if err := r.sendDatagrams(client, sendBuf); err != nil {
				return st.established, err
			}
		}
	}
}

// send writes one frame to the relay, bounding the call by the per-send timeout
// (PING_INTERVAL, matching the Rust send timeout, actor.rs:744).
func (r *activeRelay) send(client relayClient, msg relayproto.ClientToRelayMsg) error {
	ctx, cancel := context.WithTimeout(context.Background(), pingInterval)
	defer cancel()
	return client.Send(ctx, msg)
}

// sendPing sends a fresh ping and arms the ping-timeout.
func (r *activeRelay) sendPing(client relayClient, st *connectedState, timeout *time.Timer) error {
	var data [8]byte
	rand.Read(data[:])
	st.pingSent = data
	st.pingSentAt = time.Now()
	st.awaitingPng = true
	stopTimer(timeout)
	timeout.Reset(pingTimeoutDuration(st))
	return r.send(client, relayproto.ClientToRelayMsg{Type: relayproto.FramePing, Ping: data})
}

// stopTimer stops t and drains its channel if the stop lost the race, so a
// stale fire cannot be observed after a subsequent Reset.
func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func pingTimeoutDuration(st *connectedState) time.Duration {
	if st != nil && st.lastRTT > 0 {
		return min(max(st.lastRTT*3, relayPingTimeoutMin), relayPingTimeoutMax)
	}
	return relayPingTimeoutMax
}

// sendDatagrams merges runs of equally sized datagrams to one endpoint into
// DatagramBatch frames, like the GSO batches the Rust client sends.
func (r *activeRelay) sendDatagrams(client relayClient, items []RelaySendItem) error {
	ctx, cancel := context.WithTimeout(context.Background(), pingInterval)
	defer cancel()
	return coalesceDatagrams(items, maxRelayBatch, &r.batchBuf,
		func(m relayproto.ClientToRelayMsg) error { return client.Send(ctx, m) })
}

// coalesceDatagrams calls send once per wire frame. Batched Contents alias
// *buf and are only valid during send.
func coalesceDatagrams(items []RelaySendItem, maxSize int, buf *[]byte, send func(relayproto.ClientToRelayMsg) error) error {
	var scratch []byte
	if buf == nil {
		buf = &scratch
	}
	for i := 0; i < len(items); {
		head := items[i]
		seg := len(head.Datagrams.Contents)
		j := i + 1
		total := seg
		if head.Datagrams.SegmentSize == 0 && seg > 0 {
			for j < len(items) {
				it := items[j]
				n := len(it.Datagrams.Contents)
				if it.RemoteEndpoint != head.RemoteEndpoint || it.Datagrams.SegmentSize != 0 ||
					it.Datagrams.Ecn != head.Datagrams.Ecn || n == 0 || n > seg || total+n > maxSize {
					break
				}
				total += n
				j++
				if n < seg {
					break
				}
			}
		}
		msg := relayproto.ClientToRelayMsg{
			Type:          relayproto.FrameClientToRelayDatagram,
			DstEndpointID: head.RemoteEndpoint,
			Datagrams:     head.Datagrams,
		}
		if j-i > 1 {
			b := (*buf)[:0]
			for _, it := range items[i:j] {
				b = append(b, it.Datagrams.Contents...)
			}
			*buf = b
			msg.Datagrams.SegmentSize = uint16(seg)
			msg.Datagrams.Contents = b
		}
		if err := send(msg); err != nil {
			return err
		}
		i = j
	}
	return nil
}

// handleFrame processes one relay-to-client frame, matching the Rust
// handle_relay_msg (actor.rs:664).
func (r *activeRelay) handleFrame(msg relayproto.RelayToClientMsg, st *connectedState) {
	r.handleFrameAt(msg, st, time.Now())
}

func (r *activeRelay) handleFrameAt(msg relayproto.RelayToClientMsg, st *connectedState, now time.Time) {
	switch msg.Type {
	case relayproto.FrameRelayToClientDatagram, relayproto.FrameRelayToClientDatagramBat:
		r.noteRoute(msg.RemoteEndpointID)
		select {
		case r.parent.recvCh <- RelayRecvDatagram{
			URL: r.url, Src: msg.RemoteEndpointID, Datagrams: msg.Datagrams,
		}:
		default:
			// Recv queue full: drop (loss; QUIC retransmits).
		}
	case relayproto.FrameEndpointGone:
		r.dropRoute(msg.EndpointGone)
	case relayproto.FramePing:
		st.pendingPong = msg.Ping
		st.havePong = true
	case relayproto.FramePong:
		if st.awaitingPng && st.pingSent == msg.Ping {
			st.awaitingPng = false
			if !st.pingSentAt.IsZero() {
				st.lastRTT = now.Sub(st.pingSentAt)
			}
		}
		st.established = true
	case relayproto.FrameStatus:
		// Rate limiting is worth surfacing — the relay is throttling our
		// outbound traffic; other statuses are informational.
		if msg.Status == relayproto.StatusRateLimited {
			if mm := r.parent.metrics.Load(); mm != nil {
				mm.relayRateLimited.Add(1)
			}
		}
	case relayproto.FrameHealth, relayproto.FrameRestarting:
		// Informational; ignored. Status/Health are version-gated by the parser.
	}
}

// errPingTimeout is returned when a ping is not answered within pingInterval.
var errPingTimeout = errors.New("relay: ping timeout")

// jitter returns d scaled by a random factor in [0.5, 1.5), matching the
// jittered exponential backoff in the Rust ExponentialBuilder (actor.rs:356).
func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.5 + mrand.Float64()))
}

// drain removes all currently-queued items from ch without blocking.
func drain[T any](ch chan T) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
