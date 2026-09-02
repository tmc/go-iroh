package iroh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// ProtocolHandler handles connections accepted for a single ALPN
// (Application-Layer Protocol Negotiation) value. A [Router] dispatches each
// incoming connection to the handler registered for its negotiated ALPN.
//
// Accept is called in its own goroutine for every accepted connection; it should
// run for the lifetime of the connection and return when done. A returned error
// is logged. A handler must not panic; a panic is recovered and logged, closing
// only that connection while the router continues accepting. It is the Go
// analog of the Rust ProtocolHandler trait (iroh/src/protocol.rs:228).
type ProtocolHandler interface {
	// Accept handles an accepted connection. ctx is cancelled when the router
	// shuts down.
	Accept(ctx context.Context, conn *Conn) error
}

// ProtocolHandlerFunc adapts a function to [ProtocolHandler].
type ProtocolHandlerFunc func(ctx context.Context, conn *Conn) error

// Accept calls f(ctx, conn).
func (f ProtocolHandlerFunc) Accept(ctx context.Context, conn *Conn) error {
	return f(ctx, conn)
}

// AcceptingHandler is an optional interface a [ProtocolHandler] may implement
// to intercept an incoming connection before it is converted to a verified
// [Conn]. The default behavior is [Accepting.Connection].
type AcceptingHandler interface {
	OnAccepting(ctx context.Context, accepting *Accepting) (*Conn, error)
}

// ShutdownHandler is an optional interface a [ProtocolHandler] may implement to
// run cleanup when its [Router] shuts down. The router calls Shutdown on every
// registered handler that implements it before closing the endpoint, giving
// handlers a chance to close connections gracefully. It mirrors the Rust
// ProtocolHandler::shutdown hook (iroh/src/protocol.rs:284).
type ShutdownHandler interface {
	// Shutdown is called once when the router is shutting down.
	Shutdown(ctx context.Context)
}

// IncomingFilterOutcome is the decision an [IncomingFilter] returns for an
// incoming connection. It mirrors the Rust IncomingFilterOutcome
// (iroh/src/protocol.rs).
type IncomingFilterOutcome int

const (
	// FilterAccept accepts the connection and dispatches it to a handler.
	FilterAccept IncomingFilterOutcome = iota
	// FilterRetry asks the peer to retry. Router evaluates this outcome before
	// qng constructs a connection, so it emits a real QUIC Retry packet.
	FilterRetry
	// FilterReject refuses the connection.
	FilterReject
	// FilterIgnore closes the incoming connection without dispatching it.
	FilterIgnore
)

// IncomingFilter decides whether to accept each incoming connection. Router
// evaluates FilterRetry at QUIC Initial admission time, before ALPN negotiation;
// other outcomes are evaluated in the accept loop after qng has an early
// connection. It mirrors the Rust IncomingFilter (iroh/src/protocol.rs).
type IncomingFilter func(*Incoming) IncomingFilterOutcome

// RouterConfig configures a [Router].
type RouterConfig struct {
	// IncomingFilter is consulted for each incoming connection.
	IncomingFilter IncomingFilter
	// Logger records handler errors and recovered panics. If nil,
	// [slog.Default] is used.
	Logger *slog.Logger
}

// NewRouter registers every handler ALPN on ep, starts the accept loop, and
// returns the running router. The endpoint must not already be listening, so it
// must not have an accept loop of its own; see [Endpoint.Accept].
//
// The router replaces the endpoint's accepted ALPN set with the handler keys.
// Passing [WithALPNs] to [Bind] is therefore only useful as a subset of them:
// NewRouter returns an error naming any ALPN the endpoint was bound with that
// has no handler, rather than negotiating a protocol it cannot dispatch. A
// router with more ALPNs than the endpoint was bound with is fine and widens
// the set.
//
// The rule is about what [Bind] was given, not about what the endpoint accepts
// at the time. [Endpoint.SetALPNs] documents that it replaces the accepted set,
// so a router replacing it again is that contract, not a mistake.
//
// The handlers map is keyed by exact ALPN string. ALPN values are opaque byte
// strings represented as Go strings; printable ASCII protocol names are
// conventional, but binary values compare byte-for-byte. NewRouter copies the
// map before returning.
func NewRouter(ep *Endpoint, handlers map[string]ProtocolHandler, cfg *RouterConfig) (*Router, error) {
	if err := ep.acquireAcceptOwner(acceptOwnerRouter); err != nil {
		return nil, err
	}
	releaseOwner := true
	defer func() {
		if releaseOwner {
			ep.releaseAcceptOwner(acceptOwnerRouter)
		}
	}()

	handlers = maps.Clone(handlers)
	if orphans := alpnsWithoutHandler(ep.boundALPNs(), handlers); len(orphans) > 0 {
		return nil, fmt.Errorf("iroh: new router: endpoint was bound with %s, which no handler serves", strings.Join(orphans, ", "))
	}
	logger := slog.Default()
	filter := IncomingFilter(nil)
	if cfg != nil {
		filter = cfg.IncomingFilter
		logger = cfg.Logger
	}
	if logger == nil {
		logger = slog.Default()
	}

	alpns := make([]string, 0, len(handlers))
	for a := range handlers {
		alpns = append(alpns, a)
	}
	prevVerify := ep.sourceAddressValidation()
	if filter != nil {
		ep.setSourceAddressValidation(func(addr net.Addr) bool {
			if prevVerify != nil && prevVerify(addr) {
				return true
			}
			return filter(&Incoming{ep: ep, remote: addr}) == FilterRetry
		})
	}
	if err := ep.setALPNs(alpns, acceptOwnerRouter); err != nil {
		ep.setSourceAddressValidation(prevVerify)
		return nil, fmt.Errorf("iroh: new router: %w", err)
	}
	for _, h := range handlers {
		if h, ok := h.(streamListenerHandler); ok {
			h.l.addr = net.UDPAddrFromAddrPort(ep.LocalAddr())
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{
		ep:       ep,
		handlers: handlers,
		filter:   filter,
		restoreSourceValidation: func() {
			ep.setSourceAddressValidation(prevVerify)
		},
		logger: logger,
		cancel: cancel,
		ctx:    ctx,
	}
	r.wg.Add(1)
	go r.acceptLoop(ctx)
	releaseOwner = false
	return r, nil
}

// Router accepts incoming connections on an [Endpoint] and dispatches each to
// the [ProtocolHandler] registered for its negotiated ALPN. Start one with
// [NewRouter]; stop it with [Router.Shutdown]. It is the Go analog of the Rust
// Router (iroh/src/protocol.rs:97).
//
// Dispatch is by exact ALPN string. One goroutine runs the accept loop; each
// accepted connection is handled in a child goroutine with a context derived
// from the router's. A panic in a handler goroutine is recovered, logged, and
// stops the accept loop.
type Router struct {
	ep                      *Endpoint
	handlers                map[string]ProtocolHandler
	filter                  IncomingFilter
	restoreSourceValidation func()
	logger                  *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	shutdown bool
}

// Endpoint returns the endpoint the router accepts on.
func (r *Router) Endpoint() *Endpoint { return r.ep }

// IsShutdown reports whether the router has been shut down.
func (r *Router) IsShutdown() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.shutdown
}

// acceptLoop accepts connections until ctx is cancelled or the endpoint closes.
// Each connection is dispatched in a child goroutine.
func (r *Router) acceptLoop(ctx context.Context) {
	defer r.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		in, err := r.ep.acceptIncoming(ctx)
		if err != nil {
			// A cancelled context or a closed endpoint ends the loop cleanly.
			if ctx.Err() != nil || errors.Is(err, ErrEndpointClosed) {
				return
			}
			// A failed accept (e.g. a peer aborting the handshake) is logged and
			// the loop continues. The endpoint surfaces a hard close via the
			// checks above.
			r.logger.Warn("router: accept failed", "err", err)
			continue
		}

		if r.filter != nil {
			switch r.filter(in) {
			case FilterAccept:
			case FilterRetry:
				in.Ignore()
				continue
			case FilterReject:
				in.Refuse()
				continue
			case FilterIgnore:
				in.Ignore()
				continue
			}
		}

		accepting, err := in.Accept()
		if err != nil {
			r.logger.Warn("router: incoming accept failed", "err", err)
			continue
		}

		r.wg.Add(1)
		go func(accepting *Accepting) {
			defer r.wg.Done()
			var alpn string
			defer func() {
				if v := recover(); v != nil {
					accepting.qc.CloseWithError(0, "handler panic")
					r.logger.Error("router: handler panicked", "alpn", alpn, "panic", v)
				}
			}()

			var err error
			alpn, err = accepting.ALPN(ctx)
			if err != nil {
				if !handlerShutdownErr(ctx, err) {
					r.logger.Warn("router: accepting ALPN failed", "err", err)
				}
				return
			}
			handler, ok := r.handlers[alpn]
			if !ok {
				r.logger.Warn("router: no handler for ALPN", "alpn", alpn)
				accepting.qc.CloseWithError(0, "unsupported ALPN")
				return
			}
			var conn *Conn
			if h, ok := handler.(AcceptingHandler); ok {
				conn, err = h.OnAccepting(ctx, accepting)
			} else {
				conn, err = accepting.Connection(ctx)
			}
			if err != nil {
				r.logger.Warn("router: on accepting failed", "alpn", alpn, "err", err)
				return
			}
			if err := handler.Accept(ctx, conn); err != nil && !handlerShutdownErr(ctx, err) {
				r.logger.Warn("router: handler returned error", "alpn", conn.ALPN(), "err", err)
			}
		}(accepting)
	}
}

func handlerShutdownErr(ctx context.Context, err error) bool {
	if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
		return true
	}
	return errors.Is(err, net.ErrClosed)
}

// Shutdown stops the router: it cancels the accept loop and all handler
// contexts, calls Shutdown on every registered handler that implements
// [ShutdownHandler], closes the endpoint, and waits for the accept loop and
// handler goroutines to finish or ctx to be done. It is idempotent and the Go
// analog of the Rust Router::shutdown (iroh/src/protocol.rs:429).
func (r *Router) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	if r.shutdown {
		r.mu.Unlock()
		return nil
	}
	r.shutdown = true
	r.mu.Unlock()
	defer r.ep.releaseAcceptOwner(acceptOwnerRouter)

	if r.restoreSourceValidation != nil {
		r.restoreSourceValidation()
	}

	// Stop accepting and cancel handler contexts.
	r.cancel()

	// Give handlers a chance to close connections gracefully before the endpoint
	// force-closes them. Rust awaits all protocol shutdown futures
	// concurrently; do the same so one slow protocol does not block the rest.
	var shutdownWG sync.WaitGroup
	for _, h := range r.handlers {
		if sh, ok := h.(ShutdownHandler); ok {
			shutdownWG.Add(1)
			go func(sh ShutdownHandler) {
				defer shutdownWG.Done()
				sh.Shutdown(ctx)
			}(sh)
		}
	}
	handlersDone := make(chan struct{})
	go func() {
		shutdownWG.Wait()
		close(handlersDone)
	}()
	select {
	case <-handlersDone:
	case <-ctx.Done():
		return ctx.Err()
	}

	closeErr := r.ep.Shutdown(ctx)

	// Wait for the accept loop and handler goroutines, bounded by ctx.
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return closeErr
}

// alpnsWithoutHandler returns the ALPNs in alpns that handlers does not cover,
// sorted and quoted for an error message. An ALPN with no handler would still
// negotiate, then reach an accept loop with nothing to dispatch it to.
func alpnsWithoutHandler(alpns []string, handlers map[string]ProtocolHandler) []string {
	var orphans []string
	for _, a := range alpns {
		if _, ok := handlers[a]; !ok {
			orphans = append(orphans, strconv.Quote(a))
		}
	}
	slices.Sort(orphans)
	return slices.Compact(orphans)
}
