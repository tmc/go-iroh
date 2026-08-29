package faults_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/fuzztape/faults"
)

var errInjected = errors.New("injected")

type buffer struct{ bytes.Buffer }

func newRW() *faults.ReadWriter {
	return &faults.ReadWriter{RW: new(buffer)}
}

func TestReadWriterPassthrough(t *testing.T) {
	f := newRW()
	if _, err := f.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if err != nil || string(got) != "hi" {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
}

func TestFailReadOnce(t *testing.T) {
	f := newRW()
	f.RW.(*buffer).WriteString("data")
	f.FailRead(errInjected)
	if _, err := f.Read(make([]byte, 4)); !errors.Is(err, errInjected) {
		t.Fatalf("first Read err = %v, want injected", err)
	}
	n, err := f.Read(make([]byte, 4))
	if err != nil || n != 4 {
		t.Fatalf("second Read = %d, %v; fault not disarmed", n, err)
	}
}

func TestFailWriteOnce(t *testing.T) {
	f := newRW()
	f.FailWrite(errInjected)
	if _, err := f.Write([]byte("x")); !errors.Is(err, errInjected) {
		t.Fatalf("first Write err = %v, want injected", err)
	}
	if _, err := f.Write([]byte("y")); err != nil {
		t.Fatalf("second Write err = %v; fault not disarmed", err)
	}
	if got := f.RW.(*buffer).String(); got != "y" {
		t.Fatalf("buffer = %q, want %q", got, "y")
	}
}

func TestDrop(t *testing.T) {
	f := newRW()
	f.Drop(2)
	for _, s := range []string{"a", "b", "c"} {
		if n, err := f.Write([]byte(s)); n != 1 || err != nil {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
	}
	if got := f.RW.(*buffer).String(); got != "c" {
		t.Fatalf("buffer = %q, want %q (first two writes dropped)", got, "c")
	}
}

type sut struct{ rw *faults.ReadWriter }

func TestOps(t *testing.T) {
	s := &sut{rw: newRW()}
	get := func(s *sut) *faults.ReadWriter { return s.rw }

	// A zero tape picks the first error.
	other := errors.New("other")
	op := faults.FailReadOp("fail-read", get, errInjected, other)
	if op.Name != "fail-read" {
		t.Errorf("Name = %q", op.Name)
	}
	op.Apply(fuzztape.NewT(t, nil), s)
	if _, err := s.rw.Read(nil); !errors.Is(err, errInjected) {
		t.Fatalf("armed err = %v, want first of errs on zero tape", err)
	}

	// Selector 2 forces IntN's n-1 boundary: the last error.
	op.Apply(fuzztape.NewT(t, []byte{2}), s)
	if _, err := s.rw.Read(nil); !errors.Is(err, other) {
		t.Fatalf("armed err = %v, want last of errs", err)
	}

	faults.FailWriteOp("fail-write", get, errInjected).Apply(fuzztape.NewT(t, nil), s)
	if _, err := s.rw.Write(nil); !errors.Is(err, errInjected) {
		t.Fatalf("write err = %v", err)
	}

	// DropOp arms 1 to max drops; selector 2 forces max.
	faults.DropOp("drop", get, 3).Apply(fuzztape.NewT(t, []byte{2}), s)
	for range 3 {
		s.rw.Write([]byte("z"))
	}
	s.rw.Write([]byte("kept"))
	if got := s.rw.RW.(*buffer).String(); got != "kept" {
		t.Fatalf("buffer = %q, want %q", got, "kept")
	}
}

func TestFailReadOpNoErrsPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("FailReadOp with no errors did not panic")
		}
	}()
	faults.FailReadOp("bad", func(s *sut) *faults.ReadWriter { return nil })
}

// TestSleepOpBubble runs SleepOp inside a Bubble machine: hour-scale
// sleeps must cost no real time and leave nothing blocked.
func TestSleepOpBubble(t *testing.T) {
	m := fuzztape.Machine[*sut]{
		Bubble: true,
		Init:   func(t *fuzztape.T) *sut { return &sut{rw: newRW()} },
		Ops: []fuzztape.Op[*sut]{
			faults.SleepOp[*sut]("sleep", 3600e9),
		},
	}
	m.Run(t, 20)
}
