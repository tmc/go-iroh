// Package runner executes cross-implementation compatibility scenarios.
package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const Schema = "go-iroh-parity/1"

type Verdict string

const (
	Pass        Verdict = "pass"
	Fail        Verdict = "fail"
	Unsupported Verdict = "unsupported"
	SetupError  Verdict = "setup-error"
)

type Report struct {
	Schema    string    `json:"schema"`
	Generated time.Time `json:"generated"`
	GoIroh    GoIroh    `json:"go_iroh"`
	Cells     []Cell    `json:"cells"`
}

type GoIroh struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type Cell struct {
	Scenario   string   `json:"scenario"`
	Iroh       string   `json:"iroh"`
	Tier       string   `json:"tier"`
	Peer       string   `json:"peer,omitempty"`
	PeerPID    int      `json:"peer_pid,omitempty"`
	PeerDigest string   `json:"peer_digest,omitempty"`
	Result     Verdict  `json:"result"`
	Expected   Verdict  `json:"expected"`
	DurationMS int64    `json:"duration_ms"`
	Artifacts  []string `json:"artifacts,omitempty"`
	Detail     string   `json:"detail,omitempty"`
}

func (c Cell) Validate() error {
	if c.Scenario == "" || c.Iroh == "" {
		return errors.New("cell is missing scenario or iroh version")
	}
	if c.Tier != "A" && c.Tier != "B" {
		return fmt.Errorf("cell %s: invalid tier %q", c.Scenario, c.Tier)
	}
	if c.Result == Pass && (c.Peer == "" || c.PeerPID <= 0 || c.PeerDigest == "") {
		return fmt.Errorf("cell %s: pass lacks real Rust peer evidence", c.Scenario)
	}
	return nil
}

func (r *Report) Validate() error {
	if r.Schema != Schema {
		return fmt.Errorf("schema %q, want %q", r.Schema, Schema)
	}
	for _, c := range r.Cells {
		if err := c.Validate(); err != nil {
			return err
		}
		if c.Expected == "" {
			return fmt.Errorf("cell %s: expected verdict is missing", c.Scenario)
		}
	}
	return nil
}

func (r *Report) Unexpected() error {
	var mismatches []string
	for _, c := range r.Cells {
		if c.Result != c.Expected {
			mismatches = append(mismatches, fmt.Sprintf("%s@%s=%s, want %s", c.Scenario, c.Iroh, c.Result, c.Expected))
		}
	}
	if len(mismatches) != 0 {
		return fmt.Errorf("unexpected parity verdicts: %s", strings.Join(mismatches, "; "))
	}
	return nil
}

func (r *Report) Write(dir, root string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create results directory: %w", err)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encode results: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(dir, "results.json"), b, 0o644); err != nil {
		return fmt.Errorf("write results: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "badge.json"), r.Badge(), 0o644); err != nil {
		return fmt.Errorf("write badge: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "COMPATIBILITY.md"), r.Markdown(), 0o644); err != nil {
		return fmt.Errorf("write compatibility: %w", err)
	}
	return r.Unexpected()
}

func (r *Report) Badge() []byte {
	pass, total, version := 0, 0, ""
	for _, c := range r.Cells {
		if version == "" || c.Iroh > version {
			version = c.Iroh
		}
		if c.Iroh == version {
			total++
			if c.Result == Pass {
				pass++
			}
		}
	}
	b, _ := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"label":         "parity",
		"message":       fmt.Sprintf("%d/%d vs iroh %s", pass, total, version),
		"color":         map[bool]string{true: "brightgreen", false: "yellow"}[pass == total && total != 0],
	})
	return append(b, '\n')
}

func (r *Report) Markdown() []byte {
	cells := append([]Cell(nil), r.Cells...)
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].Scenario == cells[j].Scenario {
			return cells[i].Iroh < cells[j].Iroh
		}
		return cells[i].Scenario < cells[j].Scenario
	})
	var b strings.Builder
	b.WriteString("# Iroh wire compatibility\n\n")
	b.WriteString("go-iroh is an independent Go implementation of iroh wire v1. This matrix records observed interoperability with real, pinned Rust iroh peers; unsupported cells are not compatibility claims.\n\n")
	b.WriteString("Go-client↔Go-relay pairings contain no Rust peer, so they are outside this matrix's scope; that path is covered by the standard test suite.\n\n")
	fmt.Fprintf(&b, "Generated from commit `%s` at %s. A pass requires a recorded Rust process and binary digest; setup errors and unsupported cells never count as passes.\n\n", r.GoIroh.Commit, r.Generated.Format(time.RFC3339))
	b.WriteString("| Scenario | Rust iroh | Rust counterpart | Result | Peer |\n|---|---:|---|:---:|---|\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", c.Scenario, c.Iroh, rustCounterpart(c), c.Result, c.Peer)
	}
	return []byte(b.String())
}

func rustCounterpart(c Cell) string {
	switch c.Tier {
	case "A":
		return "upstream CLI"
	case "B":
		return "Rust test driver"
	default:
		return c.Tier
	}
}
