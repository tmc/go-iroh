package fuzztape

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestWatchdogNamesTheStalledGoroutine covers the one stall a bubble
// cannot report itself. The op starts a goroutine that blocks on a
// channel made outside the bubble, so it is never durably blocked, the
// bubble never quiesces, and the runtime's deadlock check never fires.
// Before the watchdog this ran until go test timed out ten minutes
// later and printed every goroutine in the process.
//
// The child must abort, and its output must name the culprit rather
// than merely report a stall.
func TestWatchdogNamesTheStalledGoroutine(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		outside := make(chan struct{}) // deliberately not made in the bubble
		m := Machine[*bool]{
			Bubble: true,
			Stall:  time.Second,
			Init:   func(t *T) *bool { return new(bool) },
			Ops: []Op[*bool]{{
				Name: "wedge",
				// Once only, so the report below has exactly one
				// goroutine to name and the count means something.
				When:  func(wedged *bool) bool { return !*wedged },
				Apply: func(t *T, wedged *bool) { *wedged = true; go func() { <-outside }() },
			}},
		}
		m.Run(t, 50)
		return
	}
	out, err := runChild(t, "^TestWatchdogNamesTheStalledGoroutine$")
	if err == nil {
		t.Fatalf("the stalled run did not abort; output:\n%s", out)
	}
	wantAll(t, out,
		"no input completed in 1s",
		"blocked on something outside it",
		// The culprit's own frame, not merely some bubbled goroutine.
		"TestWatchdogNamesTheStalledGoroutine",
	)
	// The durable filter earning its keep: of the bubbled goroutines,
	// report the one that can wedge the bubble and none of the several
	// that are correctly parked inside it.
	if n := strings.Count(out, "synctest bubble"); n != 1 {
		t.Errorf("reported %d bubbled goroutines, want 1; output:\n%s", n, out)
	}
	if strings.Contains(out, "(durable)") {
		t.Errorf("reported a durably blocked goroutine, which cannot be the culprit; output:\n%s", out)
	}
}

// TestWatchdogStaysOutOfTheWay is the negative control. A machine that
// completes its inputs must never trip the watchdog, even with a stall
// bound far below the time the whole run takes, and even while its ops
// sleep for hours of the bubble's virtual time.
func TestWatchdogStaysOutOfTheWay(t *testing.T) {
	m := Machine[*int]{
		Bubble: true,
		Stall:  100 * time.Millisecond,
		Init:   func(t *T) *int { return new(int) },
		Ops: []Op[*int]{
			{Name: "sleep", Apply: func(t *T, s *int) {
				time.Sleep(time.Hour)
				*s++
			}},
		},
	}
	m.Run(t, 300)
}

// TestStartWatchdog checks when a run gets a watchdog at all. Without a
// bubble there is no synctest.Wait to wedge, and a hang is an ordinary
// hung test that go test -timeout already reports.
func TestStartWatchdog(t *testing.T) {
	tests := []struct {
		name   string
		bubble bool
		stall  time.Duration
		want   bool
	}{
		{"bubbled, default stall", true, 0, true},
		{"bubbled, explicit stall", true, time.Second, true},
		{"bubbled, disabled", true, -1, false},
		{"not bubbled", false, 0, false},
		{"not bubbled, stall set", false, time.Second, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Machine[int]{Bubble: tt.bubble, Stall: tt.stall}
			w := m.startWatchdog()
			defer w.stop()
			if got := w != nil; got != tt.want {
				t.Errorf("startWatchdog() != nil = %v, want %v", got, tt.want)
			}
		})
	}
}
