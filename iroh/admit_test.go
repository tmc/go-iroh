package iroh

import (
	"context"
	"testing"
)

// TestAdmissionsAbandonedBeforeCancel pins that an admission abandoned to
// make room reports so even when its finisher runs after the abandonment is
// decided but before its context is cancelled.
func TestAdmissionsAbandonedBeforeCancel(t *testing.T) {
	a := &admissions{max: 1}
	var finish func() error
	var got error
	_, finish = a.add(context.Background(), func() { got = finish() })
	_, done := a.add(context.Background(), func() {})
	defer done()
	if got != errAdmissionAbandoned {
		t.Fatalf("finisher during abandonment = %v, want %v", got, errAdmissionAbandoned)
	}
	if err := finish(); err != errAdmissionAbandoned {
		t.Fatalf("finisher after abandonment = %v, want %v", err, errAdmissionAbandoned)
	}
	if n := a.len(); n != 1 {
		t.Fatalf("admitting %d, want 1", n)
	}
}
