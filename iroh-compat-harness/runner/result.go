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

const Schema = "go-iroh-parity/3"

type Verdict string

const (
	Pass        Verdict = "pass"
	Fail        Verdict = "fail"
	Unsupported Verdict = "unsupported"
	SetupError  Verdict = "setup-error"
)

type Report struct {
	Schema    string     `json:"schema"`
	Generated time.Time  `json:"generated"`
	GoIroh    GoIroh     `json:"go_iroh"`
	Cells     []Cell     `json:"cells"`
	Envelopes []Envelope `json:"envelopes"`
}

type GoIroh struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type Envelope struct {
	Surface         string `json:"surface"`
	UpstreamVersion string `json:"upstream_version"`
	Status          string `json:"status"`
	Detail          string `json:"detail"`
}

type Cell struct {
	Scenario    string         `json:"scenario"`
	Description string         `json:"description"`
	Counterpart string         `json:"counterpart"`
	Iroh        string         `json:"iroh"`
	Peer        string         `json:"peer,omitempty"`
	PeerPID     int            `json:"peer_pid,omitempty"`
	PeerDigest  string         `json:"peer_digest,omitempty"`
	Result      Verdict        `json:"result"`
	Expected    Verdict        `json:"expected"`
	DurationMS  int64          `json:"duration_ms"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Artifacts   []string       `json:"artifacts,omitempty"`
	Detail      string         `json:"detail,omitempty"`
}

func (c Cell) Validate() error {
	if c.Scenario == "" || c.Iroh == "" {
		return errors.New("cell is missing scenario or iroh version")
	}
	if strings.TrimSpace(c.Description) == "" {
		return fmt.Errorf("cell %s: description is missing", c.Scenario)
	}
	if c.Counterpart != "upstream CLI" && c.Counterpart != "Rust test driver" {
		return fmt.Errorf("cell %s: invalid counterpart %q", c.Scenario, c.Counterpart)
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
	for _, envelope := range r.Envelopes {
		if envelope.Surface == "" || envelope.UpstreamVersion == "" || envelope.Detail == "" {
			return errors.New("compatibility envelope is incomplete")
		}
		switch envelope.Status {
		case "interop-verified", "predicted-incompatible", "untested":
		default:
			return fmt.Errorf("compatibility envelope %s has invalid status %q", envelope.Surface, envelope.Status)
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
	b.WriteString("## How to read this table\n\n")
	b.WriteString("- `pass` means the implementations interoperated in the observed scenario.\n")
	b.WriteString("- `fail` means the scenario ran and observed a wire incompatibility. A predicted failure is a successful harness result.\n")
	b.WriteString("- `unsupported` means go-iroh lacks the feature, not that the feature is broken.\n")
	b.WriteString("- `setup-error` means the environment could not run the scenario, so it makes no compatibility claim.\n\n")
	b.WriteString("The Rust counterpart is either an **upstream CLI**, an unmodified program shipped by upstream iroh, or a **Rust test driver**, a purpose-built peer linked to the pinned upstream libraries. CLI results have the strongest black-box provenance; test-driver results cover protocol behavior that upstream CLIs do not expose.\n\n")
	b.WriteString("The **Peer** value names the Rust executable and its SHA-256 digest. The full machine-readable result also records the peer process ID, so a pass cannot be emitted without evidence of a real Rust process.\n\n")
	b.WriteString("## Compatibility envelope\n\n")
	b.WriteString("| Surface | Upstream version range | Status | Detail |\n|---|---|---|---|\n")
	for _, envelope := range r.Envelopes {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", envelope.Surface, envelope.UpstreamVersion, envelope.Status, envelope.Detail)
	}
	b.WriteString("\n")
	b.WriteString("## Compatibility matrix\n\n")
	b.WriteString("| Scenario | Rust iroh | Rust counterpart | Result | Peer |\n|---|---:|---|:---:|---|\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", c.Scenario, c.Iroh, c.Counterpart, c.Result, c.Peer)
	}
	b.WriteString("\n## Scenario definitions\n\n")
	b.WriteString("| Scenario | What a pass proves |\n|---|---|\n")
	last := ""
	for _, c := range cells {
		if c.Scenario == last {
			continue
		}
		fmt.Fprintf(&b, "| %s | %s |\n", c.Scenario, c.Description)
		last = c.Scenario
	}
	b.WriteString("\n## Reproduce\n\n")
	b.WriteString("```sh\ncd iroh-compat-harness\nmake parity\n```\n\n")
	b.WriteString("See the [harness README](iroh-compat-harness/README.md) for prerequisites, the [scenario declarations](iroh-compat-harness/scenarios/) for predicted verdicts and definitions, and [results.json](iroh-compat-harness/results/results.json) for the machine-readable report.\n")
	return []byte(b.String())
}
