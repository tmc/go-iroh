//go:build go1.27

package fuzztape_test

import (
	"testing"

	"github.com/tmc/go-iroh/internal/fuzztape"
)

// TestGenericMethods checks the go1.27 method spellings against their
// free-function counterparts. It runs only under a 1.27 toolchain:
//
//	GOTOOLCHAIN=go1.27rc1 go test ./internal/fuzztape/
func TestGenericMethods(t *testing.T) {
	tape := fuzztape.New(nil)
	double := fuzztape.Const(21).Map(func(n int) int { return 2 * n })
	if got := tape.Draw(double); got != 42 {
		t.Errorf("Draw(Const(21).Map(double)) = %d, want 42", got)
	}
	if got := tape.Pick([]string{"a", "b"}); got != "a" {
		t.Errorf("Pick = %q, want %q", got, "a")
	}
	if got := tape.OneOf(fuzztape.Const(1), fuzztape.Const(2)); got != 1 {
		t.Errorf("OneOf = %d, want 1 (first generator on a zero tape)", got)
	}
}

// TestGenericMethodPromotion answers the design doc's open question:
// whether a generic method promotes through embedding, which the
// proposed fuzztape.T (embedding *Tape) depends on.
func TestGenericMethodPromotion(t *testing.T) {
	type embeds struct{ *fuzztape.Tape }
	e := embeds{fuzztape.New(nil)}
	if got := e.Draw(fuzztape.Const(7)); got != 7 {
		t.Errorf("promoted Draw = %d, want 7", got)
	}
}
