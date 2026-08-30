package stats_test

import (
	"strings"
	"testing"

	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/fuzztape/stats"
)

func TestWrap(t *testing.T) {
	ops := []fuzztape.Op[*int]{
		{Name: "inc", Apply: func(t *fuzztape.T, n *int) { *n++ }},
		{Name: "full", Apply: func(t *fuzztape.T, n *int) { t.Reject("full") }},
		{Name: "gated", When: func(*int) bool { return false },
			Apply: func(t *fuzztape.T, n *int) {}},
	}
	wrapped, report := stats.Wrap(ops)
	m := fuzztape.Machine[*int]{
		Init: func(t *fuzztape.T) *int { return new(int) },
		Ops:  wrapped,
	}
	m.Run(t, 30)

	missing := report.Missing()
	if len(missing) != 2 {
		t.Fatalf("Missing() = %v, want [full gated]", missing)
	}
	for _, want := range []string{"full", "gated"} {
		found := false
		for _, name := range missing {
			if name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("Missing() = %v, does not include %q", missing, want)
		}
	}
	s := report.String()
	if !strings.Contains(s, "inc:") || !strings.Contains(s, "gated:0/0") {
		t.Errorf("String() = %q", s)
	}
	if strings.Contains(s, "full:0/0") {
		t.Errorf("String() = %q; rejections of %q not counted", s, "full")
	}
	report.Log(t)
}

// TestWrapPreservesEncoding pins that wrapping does not change how the
// tape decodes: the wrapped and unwrapped machines apply the same
// sequence for the same input.
func TestWrapPreservesEncoding(t *testing.T) {
	build := func(ops []fuzztape.Op[*int]) fuzztape.Machine[*int] {
		return fuzztape.Machine[*int]{
			Init: func(t *fuzztape.T) *int { return new(int) },
			Ops:  ops,
		}
	}
	ops := []fuzztape.Op[*int]{
		{Name: "a", Weight: 2, Apply: func(t *fuzztape.T, n *int) { *n += t.IntN(10) }},
		{Name: "b", Apply: func(t *fuzztape.T, n *int) { *n *= 2 }},
	}
	wrapped, _ := stats.Wrap(ops)
	data := []byte{4, 9, 9, 9, 9, 9, 9, 9, 9, 4, 1, 0, 2, 3}
	plain := build(ops).Splits(t, data)
	instr := build(wrapped).Splits(t, data)
	if len(plain) != len(instr) {
		t.Fatalf("splits diverge: %v vs %v", plain, instr)
	}
	for i := range plain {
		if plain[i] != instr[i] {
			t.Fatalf("splits diverge: %v vs %v", plain, instr)
		}
	}
}

