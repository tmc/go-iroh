package splice_test

import (
	"bytes"
	"testing"

	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/fuzztape/splice"
)

// The machine under test is a counter with one unconditional op, so
// Splits offsets are fully predictable: one selector byte per op for
// selectors 0–3, nine bytes for uniform selectors.
var counter = fuzztape.Machine[*int]{
	Init: func(t *fuzztape.T) *int { return new(int) },
	Ops: []fuzztape.Op[*int]{
		{Name: "inc", Apply: func(t *fuzztape.T, n *int) { *n++ }},
	},
}

func TestCrossAgainstSplits(t *testing.T) {
	// a: three one-byte ops. b: one nine-byte op (0xff selector + 8
	// payload bytes).
	a := []byte{1, 2, 3}
	b := append([]byte{0xff}, bytes.Repeat([]byte{0xee}, 8)...)
	aSplits := counter.Splits(t, a)
	bSplits := counter.Splits(t, b)
	if want := []int{0, 1, 2, 3}; !equal(aSplits, want) {
		t.Fatalf("Splits(a) = %v, want %v", aSplits, want)
	}
	if want := []int{0, 9}; !equal(bSplits, want) {
		t.Fatalf("Splits(b) = %v, want %v", bSplits, want)
	}

	got := splice.Cross(a, aSplits, b, bSplits)
	// Every output must be a's prefix at an op boundary followed by
	// b's suffix at an op boundary, with degenerates omitted.
	want := [][]byte{
		b[:0],                                    // a[:0]+b[9:] is empty — omitted; a[:0]+b[0:] is all of b — omitted
		a[:1],                                    // a[:1]+b[9:]
		append(append([]byte{}, a[:1]...), b...), // a[:1]+b[0:]
		a[:2],
		append(append([]byte{}, a[:2]...), b...),
		// a[:3]+b[9:] is all of a — omitted.
		append(append([]byte{}, a[:3]...), b...),
	}
	// Drop the placeholder empty entry from want.
	want = want[1:]
	if len(got) != len(want) {
		t.Fatalf("Cross returned %d inputs, want %d: %x", len(got), len(want), got)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if bytes.Equal(g, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Cross missing %x", w)
		}
	}
	for _, g := range got {
		if len(g) == 0 {
			t.Error("Cross produced an empty input")
		}
		if bytes.Equal(g, b) {
			t.Errorf("Cross produced all of b: %x", g)
		}
	}
}

func TestCrossDedup(t *testing.T) {
	// Identical inputs: every crossover of x with itself at matching
	// boundaries collapses; no duplicates may survive.
	x := []byte{1, 2}
	xs := counter.Splits(t, x)
	got := splice.Cross(x, xs, x, xs)
	seen := map[string]bool{}
	for _, g := range got {
		if seen[string(g)] {
			t.Errorf("duplicate output %x", g)
		}
		seen[string(g)] = true
	}
}

func TestDelete(t *testing.T) {
	data := []byte{1, 2, 3}
	splits := counter.Splits(t, data)
	if got := splice.Delete(data, splits, 1, 2); !bytes.Equal(got, []byte{1, 3}) {
		t.Errorf("Delete(1, 2) = %x, want 0103", got)
	}
	if got := splice.Delete(data, splits, 0, 3); len(got) != 0 {
		t.Errorf("Delete(all) = %x, want empty", got)
	}
}

// TestSplitsNoPhantomBoundary pins the fix for the gated-op case: when
// every op's When is false, no boundary may be recorded for the op
// that never decodes.
func TestSplitsNoPhantomBoundary(t *testing.T) {
	gated := fuzztape.Machine[*int]{
		Init: func(t *fuzztape.T) *int { return new(int) },
		Ops: []fuzztape.Op[*int]{
			{Name: "never", When: func(*int) bool { return false },
				Apply: func(t *fuzztape.T, n *int) {}},
		},
	}
	splits := gated.Splits(t, []byte{1, 2, 3})
	if want := []int{0}; !equal(splits, want) {
		t.Errorf("Splits with no enabled ops = %v, want %v", splits, want)
	}
}

func equal(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
