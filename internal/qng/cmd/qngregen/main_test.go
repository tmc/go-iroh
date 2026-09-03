package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree writes files, given as a map of slash-separated path to content,
// under a new directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCompare(t *testing.T) {
	base := writeTree(t, map[string]string{
		"kept.go":          "package quic\n",
		"edited.go":        "package quic\n\nfunc A() {}\n",
		"internal/gone.go": "package internal\n",
	})
	fork := writeTree(t, map[string]string{
		"kept.go":            "package quic\n",
		"edited.go":          "package quic\n\nfunc A() { B() }\n",
		"added.go":           "package quic\n\nfunc B() {}\n",
		"added_test.go":      "package quic\n",
		"internal/added.go":  "package internal\n",
		"internal/added.txt": "reference material\n",
	})

	d, err := compare(base, fork)
	if err != nil {
		t.Fatal(err)
	}
	if d.empty() {
		t.Fatal("compare reported no delta between differing trees")
	}
	want := map[string][]string{
		"modified": {"edited.go"},
		"added":    {"added.go", "internal/added.go", "internal/added.txt"},
		"tests":    {"added_test.go"},
		"removed":  {"internal/gone.go"},
	}
	got := map[string][]string{
		"modified": d.modified,
		"added":    d.added,
		"tests":    d.tests,
		"removed":  d.removed,
	}
	for name, want := range want {
		if strings.Join(got[name], ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, want %v", name, got[name], want)
		}
	}
	// The one edited line and the line it replaced.
	if n := d.changed["edited.go"]; n != 2 {
		t.Errorf("changed[edited.go] = %d, want 2", n)
	}
	if n := d.changed["added.go"]; n != 3 {
		t.Errorf("changed[added.go] = %d, want 3", n)
	}
}

func TestCompareIdenticalTrees(t *testing.T) {
	files := map[string]string{"kept.go": "package quic\n"}
	d, err := compare(writeTree(t, files), writeTree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if !d.empty() {
		t.Errorf("identical trees reported a delta: %s", d.summary())
	}
}
