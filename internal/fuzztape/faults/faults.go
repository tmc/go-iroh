// Package faults provides tape-driven fault injection for fuzztape
// machines.
//
// A [ReadWriter] wraps the I/O endpoint a system under test reads and
// writes through; the op constructors return [fuzztape.Op] values that
// arm it with errors and drops drawn from the tape. Because faults come
// off the same tape as regular ops, a shrunk failing input answers
// which single fault, at which point in which sequence, breaks the
// invariant.
package faults

import (
	"io"
	"sync"
	"time"

	"github.com/tmc/go-iroh/internal/fuzztape"
)

// A ReadWriter wraps an io.ReadWriter with armed, one-shot faults.
// The zero value is not usable; set RW.
type ReadWriter struct {
	// RW is the wrapped endpoint.
	RW io.ReadWriter

	mu       sync.Mutex
	readErr  error
	writeErr error
	drop     int
}

// Read returns the armed read error, if any, and disarms it;
// otherwise it reads from RW.
func (f *ReadWriter) Read(p []byte) (int, error) {
	f.mu.Lock()
	err := f.readErr
	f.readErr = nil
	f.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return f.RW.Read(p)
}

// Write silently discards the write if drops are armed, returns the
// armed write error, if any, and disarms it; otherwise it writes to RW.
func (f *ReadWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	if f.drop > 0 {
		f.drop--
		f.mu.Unlock()
		return len(p), nil
	}
	err := f.writeErr
	f.writeErr = nil
	f.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return f.RW.Write(p)
}

// FailRead arms err to be returned by the next Read.
func (f *ReadWriter) FailRead(err error) {
	f.mu.Lock()
	f.readErr = err
	f.mu.Unlock()
}

// FailWrite arms err to be returned by the next Write.
func (f *ReadWriter) FailWrite(err error) {
	f.mu.Lock()
	f.writeErr = err
	f.mu.Unlock()
}

// Drop arms the next n Writes to be silently discarded.
func (f *ReadWriter) Drop(n int) {
	f.mu.Lock()
	f.drop = n
	f.mu.Unlock()
}

// FailReadOp returns an op that arms the ReadWriter selected by get
// with one of errs on its next Read. It panics if errs is empty.
func FailReadOp[S any](name string, get func(S) *ReadWriter, errs ...error) fuzztape.Op[S] {
	mustErrs(errs)
	return fuzztape.Op[S]{
		Name: name,
		Apply: func(t *fuzztape.T, s S) {
			get(s).FailRead(fuzztape.Pick(t.Tape, errs))
		},
	}
}

// FailWriteOp returns an op that arms the ReadWriter selected by get
// with one of errs on its next Write. It panics if errs is empty.
func FailWriteOp[S any](name string, get func(S) *ReadWriter, errs ...error) fuzztape.Op[S] {
	mustErrs(errs)
	return fuzztape.Op[S]{
		Name: name,
		Apply: func(t *fuzztape.T, s S) {
			get(s).FailWrite(fuzztape.Pick(t.Tape, errs))
		},
	}
}

// DropOp returns an op that arms the ReadWriter selected by get to
// silently discard its next 1 to max Writes.
func DropOp[S any](name string, get func(S) *ReadWriter, max int) fuzztape.Op[S] {
	return fuzztape.Op[S]{
		Name: name,
		Apply: func(t *fuzztape.T, s S) {
			get(s).Drop(1 + t.IntN(max))
		},
	}
}

// SleepOp returns an op that sleeps for up to max, exercising timeout
// paths. It is intended for machines with Bubble set, where the sleep
// advances virtual time and costs nothing.
func SleepOp[S any](name string, max time.Duration) fuzztape.Op[S] {
	nap := fuzztape.Duration(0, max)
	return fuzztape.Op[S]{
		Name: name,
		Apply: func(t *fuzztape.T, s S) {
			time.Sleep(nap(t.Tape))
		},
	}
}

func mustErrs(errs []error) {
	if len(errs) == 0 {
		panic("faults: op constructed with no errors")
	}
}
