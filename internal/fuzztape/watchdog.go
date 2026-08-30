package fuzztape

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// stallDefault is how long a bubbled run may complete no input before
// the watchdog reports it. It is far above any plausible legitimate
// pause and far below the ten-minute default of go test -timeout.
const stallDefault = 30 * time.Second

// A watchdog aborts a run that has stopped making progress.
//
// Bubble makes one stall undetectable from inside. A goroutine blocked
// on something outside its bubble — a real read, a channel made in the
// enclosing test — is not durably blocked, so [testing/synctest.Wait]
// never returns, and the goroutine waiting on it is the one that would
// otherwise notice. Every in-bubble block is already caught the moment
// it happens, by the runtime's own deadlock check; this covers the case
// that check cannot see.
//
// The watchdog therefore runs outside the bubble, on real time, and
// watches a counter the run increments as it completes inputs. A nil
// *watchdog is a working no-op, so a caller that does not want one
// passes nil rather than branching.
type watchdog struct {
	n    atomic.Uint64
	done chan struct{}
}

// startWatchdog returns a watchdog for the run, or nil if the machine
// does not want one. It must be called from outside any bubble, which
// for every caller means before the first input runs.
func (m Machine[S]) startWatchdog() *watchdog {
	if !m.Bubble || m.Stall < 0 {
		return nil
	}
	d := m.Stall
	if d == 0 {
		d = stallDefault
	}
	w := &watchdog{done: make(chan struct{})}
	go w.watch(d)
	return w
}

// tick records that an input finished, whatever its verdict. A failing
// input is progress; only one that never returns is not.
func (w *watchdog) tick() {
	if w != nil {
		w.n.Add(1)
	}
}

// stop retires the watchdog.
func (w *watchdog) stop() {
	if w != nil {
		close(w.done)
	}
}

// watch reports the run if it completes no input for d at a stretch.
// Detection can take up to twice d: a stall that begins just after a
// tick is not visible until the tick after next.
func (w *watchdog) watch(d time.Duration) {
	tick := time.NewTicker(d)
	defer tick.Stop()
	last := w.n.Load()
	for {
		select {
		case <-w.done:
			return
		case <-tick.C:
			if n := w.n.Load(); n != last {
				last = n
				continue
			}
			w.report(d)
		}
	}
}

// report names the goroutine that wedged the run and takes the process
// down.
//
// Aborting is not a choice. A goroutine blocked outside its bubble
// cannot be released, so there is nothing to fail and return from:
// reporting on the test would leave the run hanging exactly as before.
// What the watchdog buys is the diagnosis and the promptness, not a
// gentler ending.
//
// The diagnosis goes to stderr before the panic, because the panic
// prints its own traceback on top of it.
func (w *watchdog) report(d time.Duration) {
	msg := fmt.Sprintf("fuzztape: no input completed in %v", d)
	if stuck := stalledBubbleStacks(); stuck != "" {
		msg += ", and a goroutine in a bubble is blocked on something outside it.\n" +
			"Ops must not touch real I/O or channels made outside the bubble.\n\n" + stuck
	} else {
		msg += ", and every bubbled goroutine is durably blocked, so the stall is elsewhere.\n\n" + bubbleStacks()
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", msg)
	panic("fuzztape: run stalled")
}

// stalledBubbleStacks returns the stacks of the goroutines that are in a
// synctest bubble but not durably blocked, which are the ones capable of
// wedging [testing/synctest.Wait].
//
// The runtime marks the distinction for us: it suffixes a bubbled
// goroutine's wait reason with "(durable)" when the goroutine can only
// be woken from inside its own bubble. One that lacks the suffix is
// either running or waiting on the outside world, and in a run that has
// made no progress for many seconds it is not running.
func stalledBubbleStacks() string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var keep []string
	for g := range strings.SplitSeq(string(buf), "\n\n") {
		// Only the header line carries the bubble and the wait reason;
		// the frames below it are ordinary code and may say anything.
		header, _, _ := strings.Cut(g, "\n")
		if strings.Contains(header, "synctest bubble") && !strings.Contains(header, "(durable)") {
			keep = append(keep, g)
		}
	}
	return strings.Join(keep, "\n\n")
}
