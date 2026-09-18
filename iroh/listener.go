package iroh

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/tmc/go-iroh/key"
)

// acceptRetryDelay bounds how fast the stream listener retries an accept that
// failed for a reason scoped to one peer.
const acceptRetryDelay = 10 * time.Millisecond

// ListenStreams returns a [net.Listener] view of e that accepts bidirectional
// streams as [net.Conn] values. The endpoint must already be configured with
// the ALPNs it should accept.
//
// The listener consumes e's incoming accept loop. ListenStreams returns
// [ErrEndpointAcceptLoopInUse] if [Endpoint.Accept], [Endpoint.AcceptIncoming],
// another stream listener, or [Router] already owns that loop.
//
// Closing the listener stops accepting new streams but does not close e or any
// net.Conn values already returned by [StreamListener.Accept].
func (e *Endpoint) ListenStreams() (*StreamListener, error) {
	if err := e.acquireAcceptOwner(acceptOwnerListenStreams); err != nil {
		return nil, err
	}
	l := NewStreamListener()
	l.ep = e
	l.addr = net.UDPAddrFromAddrPort(e.LocalAddr())
	l.onClose = func() {
		e.releaseAcceptOwner(acceptOwnerListenStreams)
	}
	go l.run()
	return l, nil
}

// NewStreamListener returns a [net.Listener] that accepts bidirectional streams
// from connections dispatched to its [StreamListener.Handler]. Register the
// handler with a [Router] to serve one ALPN as a net.Listener.
func NewStreamListener() *StreamListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &StreamListener{
		ctx:     ctx,
		cancel:  cancel,
		logger:  slog.Default(),
		streams: make(chan net.Conn),
		done:    make(chan struct{}),
	}
}

// StreamListener accepts bidirectional iroh streams as [net.Conn] values.
//
// Each accepted net.Conn is one bidirectional QUIC stream. Multiple accepted
// net.Conn values may come from the same peer connection. Closing an accepted
// net.Conn closes only that stream; closing the StreamListener closes any peer
// connections it has accepted but does not close the underlying endpoint. An
// accepted net.Conn also exposes RemoteID and Used0RTT methods.
type StreamListener struct {
	ep     *Endpoint
	ctx    context.Context
	cancel context.CancelFunc
	addr   net.Addr
	logger *slog.Logger

	streams chan net.Conn
	done    chan struct{}
	onClose func()

	closeOnce sync.Once
	errMu     sync.Mutex
	err       error
}

// Accept waits for and returns the next accepted bidirectional stream.
func (l *StreamListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.streams:
		return c, nil
	case <-l.done:
		return nil, l.acceptErr()
	}
}

// Close stops accepting new streams. It does not close the underlying endpoint.
func (l *StreamListener) Close() error {
	l.closeOnce.Do(func() {
		l.setErr(net.ErrClosed)
		l.cancel()
		close(l.done)
		if l.onClose != nil {
			l.onClose()
		}
	})
	return nil
}

// Addr returns the endpoint's local UDP address.
func (l *StreamListener) Addr() net.Addr {
	return l.addr
}

// Handler returns a [ProtocolHandler] that dispatches accepted connection
// streams to l.
func (l *StreamListener) Handler() ProtocolHandler {
	return streamListenerHandler{l}
}

func (l *StreamListener) handleConn(ctx context.Context, conn *Conn) error {
	done := make(chan struct{})
	go func() {
		l.acceptStreams(conn)
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		conn.Close()
		<-done
		return ctx.Err()
	case <-l.done:
		conn.Close()
		<-done
		return net.ErrClosed
	}
}

func (l *StreamListener) run() {
	var wg sync.WaitGroup
	defer func() {
		l.cancel()
		wg.Wait()
		l.closeOnce.Do(func() {
			close(l.done)
		})
	}()
	for {
		conn, err := l.ep.accept(l.ctx)
		if err != nil {
			// A cancelled listener, a closed endpoint, or an endpoint that can
			// never accept ends the loop cleanly.
			if l.ctx.Err() != nil || errors.Is(err, ErrEndpointClosed) || errors.Is(err, errNoALPNs) {
				l.setErr(err)
				return
			}
			// A failure scoped to one peer (a handshake rejected by a hook, a
			// peer aborting mid-handshake) drops that peer only. Pause before
			// retrying so an accept that keeps failing does not spin, which
			// also bounds how fast a rejected peer can drive the log.
			l.logger.Warn("iroh: stream listener accept failed", "err", err)
			select {
			case <-time.After(acceptRetryDelay):
			case <-l.ctx.Done():
				l.setErr(l.ctx.Err())
				return
			}
			continue
		}
		wg.Add(1)
		go func(conn *Conn) {
			defer wg.Done()
			l.acceptStreams(conn)
		}(conn)
	}
}

type streamListenerHandler struct {
	l *StreamListener
}

func (h streamListenerHandler) Accept(ctx context.Context, conn *Conn) error {
	return h.l.handleConn(ctx, conn)
}

func (h streamListenerHandler) Shutdown(ctx context.Context) {
	h.l.Close()
}

func (l *StreamListener) acceptStreams(conn *Conn) {
	owner := newListenerConn(conn)
	defer owner.doneAccepting()
	for {
		c, err := conn.AcceptStreamConn(l.ctx)
		if err != nil {
			return
		}
		owner.addStream()
		c = &listenerStreamConn{Conn: c, owner: owner}
		select {
		case l.streams <- c:
		case <-l.done:
			c.Close()
			return
		case <-l.ctx.Done():
			c.Close()
			return
		}
	}
}

type listenerConn struct {
	conn *Conn

	mu        sync.Mutex
	active    int
	accepting bool
	closed    bool
}

func newListenerConn(conn *Conn) *listenerConn {
	return &listenerConn{conn: conn, accepting: true}
}

func (c *listenerConn) addStream() {
	c.mu.Lock()
	c.active++
	c.mu.Unlock()
}

func (c *listenerConn) releaseStream() {
	c.mu.Lock()
	if c.active > 0 {
		c.active--
	}
	c.closeIfIdleLocked()
	c.mu.Unlock()
}

func (c *listenerConn) doneAccepting() {
	c.mu.Lock()
	c.accepting = false
	c.closeIfIdleLocked()
	c.mu.Unlock()
}

func (c *listenerConn) closeIfIdleLocked() {
	if c.closed || c.accepting || c.active != 0 {
		return
	}
	c.closed = true
	c.conn.Close()
}

type listenerStreamConn struct {
	net.Conn
	owner *listenerConn
	once  sync.Once
}

func (c *listenerStreamConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.owner.releaseStream)
	return err
}

func (c *listenerStreamConn) RemoteID() key.EndpointID {
	return c.Conn.(interface{ RemoteID() key.EndpointID }).RemoteID()
}

func (c *listenerStreamConn) Used0RTT() bool {
	return c.Conn.(interface{ Used0RTT() bool }).Used0RTT()
}

func (l *StreamListener) setErr(err error) {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	if l.err != nil {
		return
	}
	if l.ctx.Err() != nil || errors.Is(err, context.Canceled) {
		err = net.ErrClosed
	}
	l.err = err
}

func (l *StreamListener) acceptErr() error {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	if l.err != nil {
		return l.err
	}
	return net.ErrClosed
}
