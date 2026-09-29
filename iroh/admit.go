package iroh

import (
	"container/list"
	"context"
	"errors"
	"sync"

	quic "github.com/tmc/go-iroh/internal/qng"
)

// maxAdmitting bounds the incoming connections an endpoint admits at once:
// those whose handshake or [EndpointHooks.AfterHandshake] hooks have not
// finished. Upstream Rust iroh has no such bound of its own; its QUIC stack
// allows 65536 incoming connections.
const maxAdmitting = 1024

// errAdmissionAbandoned is the cause of an admission abandoned to make room
// for a newer one.
var errAdmissionAbandoned = errors.New("iroh: handshake abandoned for a newer one")

// admissions tracks the incoming connections an endpoint is admitting, oldest
// first. Endpoint.Accept, StreamListener, and Router all admit through it.
//
// When full, admit abandons the oldest admission instead of waiting for one
// to finish: it cancels that admission's context and closes its connection.
// A peer that stalls its handshake, or is held in a hook, can then delay a
// new peer by nothing, however many such peers there are; the cost is that
// a flood of new handshakes can crowd out a slow legitimate one.
type admissions struct {
	mu   sync.Mutex
	max  int
	list list.List // of *admission
}

type admission struct {
	abandon   func() // closes the connection
	cancel    context.CancelCauseFunc
	elem      *list.Element // nil once removed
	abandoned bool
}

// admit registers qc and returns the context under which to finish its
// handshake and run its hooks, and a func to call once that is done. The
// func reports errAdmissionAbandoned if the admission was abandoned, in which
// case qc is already closed or being closed and the caller must not use the
// connection. It may be called more than once.
func (a *admissions) admit(ctx context.Context, qc *quic.Conn) (context.Context, func() error) {
	return a.add(ctx, func() { qc.CloseWithError(0, "handshake abandoned") })
}

// add is admit with abandon in place of closing a connection.
func (a *admissions) add(ctx context.Context, abandon func()) (context.Context, func() error) {
	ctx, cancel := context.WithCancelCause(ctx)
	ad := &admission{abandon: abandon, cancel: cancel}
	a.mu.Lock()
	var oldest *admission
	if a.list.Len() >= a.max {
		oldest = a.list.Remove(a.list.Front()).(*admission)
		oldest.elem = nil
		// Record the abandonment before unlocking: the oldest's finisher
		// may run before the cancel below and must see it.
		oldest.abandoned = true
	}
	ad.elem = a.list.PushBack(ad)
	a.mu.Unlock()
	if oldest != nil {
		oldest.abandon()
		oldest.cancel(errAdmissionAbandoned)
	}
	return ctx, func() error {
		a.mu.Lock()
		if ad.elem != nil {
			a.list.Remove(ad.elem)
			ad.elem = nil
		}
		abandoned := ad.abandoned
		a.mu.Unlock()
		cancel(nil)
		if abandoned {
			return errAdmissionAbandoned
		}
		return nil
	}
}

// len returns the number of connections being admitted.
func (a *admissions) len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.list.Len()
}
