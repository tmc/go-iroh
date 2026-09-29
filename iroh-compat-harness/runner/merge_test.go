package runner

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrain(t *testing.T) {
	for _, tt := range []struct {
		version, want string
	}{
		{"1.3.0", "1.3"},
		{"1.10.2", "1.10"},
		{"2.0.0", "2.0"},
	} {
		got, err := Train(tt.version)
		if err != nil || got != tt.want {
			t.Errorf("Train(%q) = %q, %v, want %q", tt.version, got, err, tt.want)
		}
	}
	for _, version := range []string{"", "1.3", "1.3.0-rc.1", "v1.3.0"} {
		if _, err := Train(version); err == nil {
			t.Errorf("Train(%q) succeeded, want error", version)
		}
	}
}

func run(version, commit string, generated time.Time) Report {
	train, _ := Train(version)
	return Report{
		Schema:    Schema,
		Generated: generated,
		GoIroh:    GoIroh{Version: "main", Commit: commit},
		Pins:      []Pin{{Key: train, Train: train, Version: version, Kind: "release"}},
		Cells: []Cell{{
			Scenario: "vectors/keys", Description: "A pass proves keys.", Tier: "stable",
			Counterpart: "Rust test driver", Iroh: train, Result: Fail, Expected: Fail,
		}},
	}
}

func TestMergeOrdersReleasesOldestFirst(t *testing.T) {
	early := time.Date(2026, 9, 29, 1, 0, 0, 0, time.UTC)
	late := early.Add(time.Minute)
	merged, err := Merge([]Report{run("1.10.0", "abc", early), run("1.2.0", "abc", late), run("1.3.0", "abc", early)})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, pin := range merged.Pins {
		keys = append(keys, pin.Key)
	}
	if got := strings.Join(keys, " "); got != "1.2 1.3 1.10" {
		t.Errorf("pins = %s, want 1.2 1.3 1.10", got)
	}
	if len(merged.Cells) != 3 {
		t.Errorf("merged %d cells, want 3", len(merged.Cells))
	}
	if !merged.Generated.Equal(late) {
		t.Errorf("Generated = %v, want the latest run's %v", merged.Generated, late)
	}
	if err := merged.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMergeRejectsDifferentCommits(t *testing.T) {
	now := time.Now()
	if _, err := Merge([]Report{run("1.2.0", "abc", now), run("1.3.0", "def", now)}); err == nil {
		t.Fatal("merged runs of different go-iroh commits")
	}
}

func TestMergeRejectsDuplicateRelease(t *testing.T) {
	now := time.Now()
	merged, err := Merge([]Report{run("1.3.0", "abc", now), run("1.3.0", "abc", now)})
	if err == nil {
		err = merged.Validate()
	}
	if err == nil {
		t.Fatal("merged two runs of the same release")
	}
}

func TestRunRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs", "iroh-1.3.0.json")
	want := run("1.3.0", "abc", time.Date(2026, 9, 29, 1, 0, 0, 0, time.UTC))
	if err := want.WriteRun(path); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRun(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pins[0] != want.Pins[0] || len(got.Cells) != 1 || got.Cells[0].Scenario != want.Cells[0].Scenario || got.Cells[0].Iroh != want.Cells[0].Iroh {
		t.Errorf("ReadRun = %+v, want %+v", got, want)
	}
}

func TestBadgeCountsEveryRelease(t *testing.T) {
	now := time.Now()
	merged, err := Merge([]Report{run("1.2.0", "abc", now), run("1.3.0", "abc", now)})
	if err != nil {
		t.Fatal(err)
	}
	merged.Cells[1].Result = Pass
	got := string(merged.Badge())
	if want := `"message":"1/2 expected vs iroh 1.2.0, 1.3.0"`; !strings.Contains(got, want) {
		t.Errorf("Badge() = %s, want %s", got, want)
	}
}
