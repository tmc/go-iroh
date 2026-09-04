package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMerge(t *testing.T) {
	base := writeTree(t, map[string]string{
		"untouched.go": "package quic\n\nfunc A() {}\n",
		"taken.go":     "package quic\n\nfunc B() {}\n",
		"merged.go":    "package quic\n\nfunc C() {}\n\nfunc D() {}\n",
		"conflict.go":  "package quic\n\nfunc E() {}\n",
		"removed.go":   "package quic\n",
		"orphaned.go":  "package quic\n",
		"dropped.go":   "package quic\n\nfunc F() {}\n",
	})
	theirs := writeTree(t, map[string]string{
		"untouched.go": "package quic\n\nfunc A() {}\n",
		"taken.go":     "package quic\n\nfunc B(x int) {}\n",
		"merged.go":    "package quic\n\nfunc C() {}\n\nfunc D(x int) {}\n",
		"conflict.go":  "package quic\n\nfunc E(x int) {}\n",
		"dropped.go":   "package quic\n\nfunc F(x int) {}\n",
		"added.go":     "package quic\n\nfunc G() {}\n",
	})
	fork := writeTree(t, map[string]string{
		"untouched.go": "package quic\n\nfunc A() {}\n",
		"taken.go":     "package quic\n\nfunc B() {}\n",
		"merged.go":    "package quic\n\nfunc C() { go-iroh }\n\nfunc D() {}\n",
		"conflict.go":  "package quic\n\nfunc E(y string) {}\n",
		"removed.go":   "package quic\n",
		"orphaned.go":  "package quic\n\nfunc H() {}\n",
		"own.go":       "package quic\n\nfunc Own() {}\n",
	})

	res, err := merge(fork, base, theirs)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		got  []string
		want []string
	}{
		{"taken", res.taken, []string{"taken.go"}},
		{"merged", res.merged, []string{"merged.go"}},
		{"conflicted", res.conflicted, []string{"conflict.go"}},
		{"added", res.added, []string{"added.go"}},
		{"removed", res.removed, []string{"removed.go"}},
		{"orphaned", res.orphaned, []string{"orphaned.go"}},
		{"dropped", res.dropped, []string{"dropped.go"}},
	} {
		if !slices.Equal(slices.Sorted(slices.Values(tc.got)), tc.want) {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}

	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(fork, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got, want := read("taken.go"), "func B(x int) {}"; !strings.Contains(got, want) {
		t.Errorf("taken.go = %q, want it to contain %q", got, want)
	}
	// A clean merge keeps both sides.
	got := read("merged.go")
	for _, want := range []string{"func C() { go-iroh }", "func D(x int) {}"} {
		if !strings.Contains(got, want) {
			t.Errorf("merged.go = %q, want it to contain %q", got, want)
		}
	}
	if got := read("conflict.go"); !strings.Contains(got, "<<<<<<< go-iroh") {
		t.Errorf("conflict.go = %q, want conflict markers", got)
	}
	// A file the fork added on its own is left alone.
	if got, want := read("own.go"), "package quic\n\nfunc Own() {}\n"; got != want {
		t.Errorf("own.go = %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(fork, "removed.go")); !os.IsNotExist(err) {
		t.Errorf("removed.go still exists: %v", err)
	}
	if got, want := read("orphaned.go"), "func H() {}"; !strings.Contains(got, want) {
		t.Errorf("orphaned.go = %q, want the fork's edit kept", got)
	}
}

func TestReplaceOnce(t *testing.T) {
	tests := []struct {
		name    string
		content string
		prefix  string
		line    string
		want    string
	}{{
		name:    "readme version",
		content: "## Forked version\n\nquic-go **v0.62.0**.\n",
		prefix:  "quic-go **",
		line:    "quic-go **v0.63.0**.",
		want:    "## Forked version\n\nquic-go **v0.63.0**.\n",
	}, {
		name:    "notice version",
		content: "copied from quic-go\n(https://github.com/quic-go/quic-go) at v0.62.0, used under the MIT\nlicense.\n",
		prefix:  "(https://github.com/quic-go/quic-go) at ",
		line:    "(https://github.com/quic-go/quic-go) at v0.63.0, used under the MIT",
		want:    "copied from quic-go\n(https://github.com/quic-go/quic-go) at v0.63.0, used under the MIT\nlicense.\n",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "f")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := replaceOnce(path, tt.prefix, tt.line); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", b, tt.want)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("no version here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceOnce(path, "quic-go **", "x"); err == nil {
		t.Error("replaceOnce succeeded on a file with no version line")
	}
}
