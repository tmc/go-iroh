package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBaoCellsMatchCorpus(t *testing.T) {
	files, err := filepath.Glob("../vectors/corpus/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpora: %v", err)
	}
	for _, file := range files {
		corpus, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range baoCells(corpus, "1.3", "sha256:abc", 1, "rust-driver", 0) {
			if c.Result != Pass {
				t.Errorf("%s: %s = %s: %s %v", filepath.Base(file), c.Scenario, c.Result, c.Detail, c.Evidence)
			}
		}
	}
}

func TestBaoChunkRanges(t *testing.T) {
	for _, tt := range []struct {
		name       string
		boundaries []uint64
		want       string
		ok         bool
	}{
		{"span", []uint64{5, 7}, "[{5 7}]", true},
		{"two spans", []uint64{1, 2, 4, 6}, "[{1 2} {4 6}]", true},
		{"open", []uint64{3}, "[]", true},
		{"span then open", []uint64{1, 2, 4}, "", false},
	} {
		got, ok := baoChunkRanges(tt.boundaries)
		if ok != tt.ok {
			t.Errorf("%s: ok = %v, want %v", tt.name, ok, tt.ok)
			continue
		}
		if ok && fmt.Sprint(got.Ranges()) != tt.want {
			t.Errorf("%s: ranges = %v, want %s", tt.name, got.Ranges(), tt.want)
		}
	}
}
