package trace_test

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/fuzztape/trace"
)

type counter struct{ n int }

var machine = fuzztape.Machine[*counter]{
	Init: func(t *fuzztape.T) *counter { return new(counter) },
	Ops: []fuzztape.Op[*counter]{
		{Name: "inc", Apply: func(t *fuzztape.T, c *counter) { c.n++ }},
		{Name: "dec", When: func(c *counter) bool { return c.n > 0 },
			Apply: func(t *fuzztape.T, c *counter) { c.n-- }},
	},
}

func TestReproParses(t *testing.T) {
	data := []byte{0x00, 0x01, 0xff, '"', '\\', '\n'}
	ops := machine.Trace(t, data)
	if len(ops) == 0 {
		t.Fatal("machine decoded no ops; the test would prove nothing")
	}
	src := trace.File("mypkg", "TestQueueRepro", "machine", data, ops)

	if _, err := parser.ParseFile(token.NewFileSet(), "repro_test.go", src, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v\n%s", err, src)
	}
	for _, want := range []string{"package mypkg", "func TestQueueRepro(t *testing.T)", "machine.Replay(t, data)"} {
		if !strings.Contains(src, want) {
			t.Errorf("generated source missing %q:\n%s", want, src)
		}
	}
	// The op sequence is what makes the file legible without running it.
	for _, op := range ops {
		if !strings.Contains(src, "//\t"+op) {
			t.Errorf("generated source does not record op %q:\n%s", op, src)
		}
	}
}

// TestReproEscapesData covers the bytes that would break a naive
// generator: quotes, backslashes, newlines, and non-UTF-8.
func TestReproEscapesData(t *testing.T) {
	data := []byte{0x00, '"', '\\', '\n', 0xff, 0xfe, '`'}
	src := trace.File("p", "TestX", "m", data, nil)
	if _, err := parser.ParseFile(token.NewFileSet(), "x_test.go", src, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v\n%s", err, src)
	}
}

func TestReproNoOps(t *testing.T) {
	src := trace.Repro("TestX", "m", nil, nil)
	if !strings.Contains(src, "no ops") {
		t.Errorf("empty trace not described:\n%s", src)
	}
}

// TestGeneratedFileCompilesAndRuns is the claim the package doc makes,
// checked rather than asserted: the generated file is built and run by
// a real toolchain, against this module, with no network access.
func TestGeneratedFileCompilesAndRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module in a temporary directory")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool in PATH")
	}
	data := []byte{0x00, 0x01, 0x02, 0x00}
	ops := machine.Trace(t, data)
	dir := t.TempDir()

	repoRoot, err := repoRoot()
	if err != nil {
		t.Skip(err.Error())
	}

	// The generated test needs a machine to replay against, so the
	// throwaway module carries the same one this test uses.
	write(t, filepath.Join(dir, "go.mod"), `module github.com/tmc/go-iroh/internal/repro

go 1.26

require github.com/tmc/go-iroh v0.0.0

replace github.com/tmc/go-iroh => `+repoRoot+"\n")
	write(t, filepath.Join(dir, "machine.go"), `package repro

import "github.com/tmc/go-iroh/internal/fuzztape"

type counter struct{ n int }

var machine = fuzztape.Machine[*counter]{
	Init: func(t *fuzztape.T) *counter { return new(counter) },
	Ops: []fuzztape.Op[*counter]{
		{Name: "inc", Apply: func(t *fuzztape.T, c *counter) { c.n++ }},
	},
}
`)
	write(t, filepath.Join(dir, "repro_test.go"), trace.File("repro", "TestRepro", "machine", data, ops))

	cmd := exec.Command(goTool, "test", "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated test did not build and pass: %v\n%s", err, out)
	}
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// trace is in <repo>/internal/fuzztape/trace, so repo root is 3 levels up
	return filepath.Dir(filepath.Dir(filepath.Dir(dir))), nil
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
