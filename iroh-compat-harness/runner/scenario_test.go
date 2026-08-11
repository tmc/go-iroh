package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyExpectedRequiresDescription(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"scenarios":[{"name":"x","counterpart":"upstream CLI","expected":{"1.0.3":"pass"}}]}`)
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
	data := []byte(`{"scenarios":[{"name":"x","description":"A pass proves x.","tier":"stable","counterpart":"upstream CLI","expected":{"1.0.3":"pass"}}]}`)
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
	if cells[0].Counterpart != "upstream CLI" {
		t.Fatalf("counterpart = %q", cells[0].Counterpart)
	}
	if cells[0].Tier != "stable" {
		t.Fatalf("tier = %q", cells[0].Tier)
	}
}

func TestApplyExpectedRequiresCounterpart(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"scenarios":[{"name":"x","description":"A pass proves x.","tier":"stable","expected":{"1.0.3":"pass"}}]}`)
	if err := os.WriteFile(filepath.Join(dir, "test.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cells := []Cell{{Scenario: "x", Iroh: "1.0.3"}}
	err := ApplyExpected(dir, "1.0.3", cells)
	if err == nil || !strings.Contains(err.Error(), "invalid counterpart") {
		t.Fatalf("ApplyExpected() error = %v, want invalid counterpart", err)
	}
}

func TestApplyExpectedRequiresTier(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"scenarios":[{"name":"x","description":"A pass proves x.","counterpart":"upstream CLI","expected":{"1.0":"pass"}}]}`)
	if err := os.WriteFile(filepath.Join(dir, "test.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	err := ApplyExpected(dir, "1.0", []Cell{{Scenario: "x", Iroh: "1.0"}})
	if err == nil || !strings.Contains(err.Error(), "invalid tier") {
		t.Fatalf("ApplyExpected() error = %v, want invalid tier", err)
	}
}

func TestLoadEnvelopes(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"envelopes":[{"surface":"CustomAddr endpoint tickets","tier":"experimental","upstream_version":"1.0","status":"observed-incompatible","detail":"Observed in both directions."}]}`)
	if err := os.WriteFile(filepath.Join(dir, "envelopes.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	envelopes, err := LoadEnvelopes(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelopes) != 1 || envelopes[0].Status != "observed-incompatible" {
		t.Fatalf("envelopes = %#v", envelopes)
	}
}
