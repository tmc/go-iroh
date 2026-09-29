package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Train returns the minor release train of an upstream version: 1.3 for
// 1.3.0. Scenario expectations are keyed by train.
func Train(version string) (string, error) {
	if _, err := parseVersion(version); err != nil {
		return "", err
	}
	major, rest, _ := strings.Cut(version, ".")
	minor, _, _ := strings.Cut(rest, ".")
	return major + "." + minor, nil
}

func parseVersion(version string) ([3]int, error) {
	var v [3]int
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("upstream version %q is not MAJOR.MINOR.PATCH", version)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("upstream version %q is not MAJOR.MINOR.PATCH", version)
		}
		v[i] = n
	}
	return v, nil
}

// WriteRun writes the cells measured against one upstream release to path.
// A run file is an input to Merge, not a report: it carries no envelopes and
// its expected verdicts are not enforced until the merge.
func (r *Report) WriteRun(path string) error {
	if len(r.Pins) != 1 {
		return fmt.Errorf("run has %d upstream pins, want 1", len(r.Pins))
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encode run: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create run directory: %w", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write run: %w", err)
	}
	return nil
}

// ReadRun reads a run file written by WriteRun.
func ReadRun(path string) (Report, error) {
	var r Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, fmt.Errorf("read run: %w", err)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("decode run %s: %w", path, err)
	}
	return r, nil
}

// Merge combines runs against different upstream releases of the same
// go-iroh commit into one report, with one column per release, oldest first.
func Merge(runs []Report) (Report, error) {
	if len(runs) == 0 {
		return Report{}, errors.New("no runs to merge")
	}
	merged := Report{Schema: runs[0].Schema, GoIroh: runs[0].GoIroh}
	for _, run := range runs {
		if run.Schema != merged.Schema {
			return Report{}, fmt.Errorf("runs mix schemas %q and %q", merged.Schema, run.Schema)
		}
		if run.GoIroh != merged.GoIroh {
			return Report{}, fmt.Errorf("runs measured different go-iroh commits %s and %s", merged.GoIroh.Commit, run.GoIroh.Commit)
		}
		if len(run.Pins) != 1 {
			return Report{}, fmt.Errorf("run has %d upstream pins, want 1", len(run.Pins))
		}
		if _, err := parseVersion(run.Pins[0].Version); err != nil {
			return Report{}, err
		}
		if run.Generated.After(merged.Generated) {
			merged.Generated = run.Generated
		}
		merged.Pins = append(merged.Pins, run.Pins[0])
		merged.Cells = append(merged.Cells, run.Cells...)
	}
	slices.SortFunc(merged.Pins, func(a, b Pin) int {
		va, _ := parseVersion(a.Version)
		vb, _ := parseVersion(b.Version)
		return slices.Compare(va[:], vb[:])
	})
	return merged, nil
}
