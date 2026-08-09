package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyExpectedRequiresDescription(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"scenarios":[{"name":"x","expected":{"1.0.3":"pass"}}]}`)
	if err := os.WriteFile(filepath.Join(dir, "test.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cells := []Cell{{Scenario: "x", Iroh: "1.0.3"}}
	err := ApplyExpected(dir, "1.0.3", cells)
	if err == nil || !strings.Contains(err.Error(), "lacks description") {
		t.Fatalf("ApplyExpected() error = %v, want missing description", err)
	}
}

func TestApplyExpectedCopiesDescription(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"scenarios":[{"name":"x","description":"A pass proves x.","expected":{"1.0.3":"pass"}}]}`)
	if err := os.WriteFile(filepath.Join(dir, "test.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cells := []Cell{{Scenario: "x", Iroh: "1.0.3"}}
	if err := ApplyExpected(dir, "1.0.3", cells); err != nil {
		t.Fatal(err)
	}
	if cells[0].Description != "A pass proves x." {
		t.Fatalf("description = %q", cells[0].Description)
	}
}
