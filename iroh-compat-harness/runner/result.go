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

const Schema = "go-iroh-parity/4"

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
	Pins      []Pin      `json:"pins"`
	Cells     []Cell     `json:"cells"`
	Envelopes []Envelope `json:"envelopes"`
}

type GoIroh struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Pin identifies one upstream version column. New release trains add pins;
// patch releases update an existing train's pin.
type Pin struct {
	Key     string `json:"key"`
	Train   string `json:"train"`
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
	Kind    string `json:"kind"`
}

type Envelope struct {
	Surface         string `json:"surface"`
	Tier            string `json:"tier"`
	UpstreamVersion string `json:"upstream_version"`
	Status          string `json:"status"`
	Detail          string `json:"detail"`
}

type Cell struct {
	Scenario    string         `json:"scenario"`
	Description string         `json:"description"`
	Tier        string         `json:"tier"`
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
	if c.Tier != "stable" && c.Tier != "experimental" {
		return fmt.Errorf("cell %s: invalid stability tier %q", c.Scenario, c.Tier)
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
	pins := make(map[string]bool)
	for _, pin := range r.Pins {
		if pin.Key == "" || pin.Train == "" {
			return errors.New("upstream pin is incomplete")
		}
		if pin.Kind != "release" && pin.Kind != "pre-release" {
			return fmt.Errorf("upstream pin %s has invalid kind %q", pin.Key, pin.Kind)
		}
		if pin.Kind == "release" && pin.Version == "" {
			return fmt.Errorf("release pin %s has no version", pin.Key)
		}
		if pin.Kind == "pre-release" && pin.Commit == "" {
			return fmt.Errorf("pre-release pin %s has no commit", pin.Key)
		}
		if pins[pin.Key] {
			return fmt.Errorf("duplicate upstream pin %s", pin.Key)
		}
		pins[pin.Key] = true
	}
	cellKeys := make(map[string]bool)
	usedPins := make(map[string]bool)
	type scenarioMetadata struct {
		description string
		tier        string
		counterpart string
	}
	metadata := make(map[string]scenarioMetadata)
	for _, c := range r.Cells {
		if err := c.Validate(); err != nil {
			return err
		}
		if c.Expected == "" {
			return fmt.Errorf("cell %s: expected verdict is missing", c.Scenario)
		}
		if !pins[c.Iroh] {
			return fmt.Errorf("cell %s references unknown upstream pin %q", c.Scenario, c.Iroh)
		}
		key := c.Scenario + "\x00" + c.Iroh
		if cellKeys[key] {
			return fmt.Errorf("duplicate cell %s at upstream pin %s", c.Scenario, c.Iroh)
		}
		cellKeys[key] = true
		usedPins[c.Iroh] = true
		got := scenarioMetadata{description: c.Description, tier: c.Tier, counterpart: c.Counterpart}
		if want, ok := metadata[c.Scenario]; ok && got != want {
			return fmt.Errorf("scenario %s metadata differs across upstream pins", c.Scenario)
		}
		metadata[c.Scenario] = got
	}
	for _, pin := range r.Pins {
		if !usedPins[pin.Key] {
			return fmt.Errorf("upstream pin %s has no executed cells", pin.Key)
		}
	}
	for _, envelope := range r.Envelopes {
		if envelope.Surface == "" || envelope.UpstreamVersion == "" || envelope.Detail == "" {
			return errors.New("compatibility envelope is incomplete")
		}
		if envelope.Tier != "stable" && envelope.Tier != "experimental" {
			return fmt.Errorf("compatibility envelope %s has invalid tier %q", envelope.Surface, envelope.Tier)
		}
		switch envelope.Status {
		case "verified-interop", "observed-incompatible", "predicted-interop", "predicted-incompatible", "unsupported", "untested":
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
	matched, total, version, key := 0, 0, "", ""
	for _, pin := range r.Pins {
		if pin.Kind == "release" {
			key = pin.Key
			version = pin.Version
			break
		}
	}
	for _, c := range r.Cells {
		if c.Iroh == key {
			total++
			if c.Result == c.Expected {
				matched++
			}
		}
	}
	b, _ := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"label":         "parity",
		"message":       fmt.Sprintf("%d/%d expected vs iroh %s", matched, total, version),
		"color":         map[bool]string{true: "brightgreen", false: "yellow"}[matched == total && total != 0],
	})
	return append(b, '\n')
}

func (r *Report) Markdown() []byte {
	cells := append([]Cell(nil), r.Cells...)
	pinOrder := make(map[string]int, len(r.Pins))
	for i, pin := range r.Pins {
		pinOrder[pin.Key] = i
	}
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].Scenario == cells[j].Scenario {
			return pinOrder[cells[i].Iroh] < pinOrder[cells[j].Iroh]
		}
		return cells[i].Scenario < cells[j].Scenario
	})
	type peer struct {
		name   string
		pin    string
		digest string
	}
	var peers []peer
	peerRefs := make(map[string]int)
	for _, c := range cells {
		if c.Peer == "" || c.PeerDigest == "" {
			continue
		}
		key := c.Peer + "\x00" + c.Iroh
		if peerRefs[key] != 0 {
			continue
		}
		name := strings.SplitN(c.Peer, "@", 2)[0]
		peerRefs[key] = len(peers) + 1
		peers = append(peers, peer{name: name, pin: r.pinLabel(c.Iroh), digest: strings.TrimPrefix(c.PeerDigest, "sha256:")})
	}
	var b strings.Builder
	b.WriteString("# Iroh wire compatibility\n\n")
	b.WriteString("go-iroh is an independent Go implementation of iroh wire v1. This matrix records observed interoperability with real, pinned Rust iroh peers; unsupported cells are not compatibility claims.\n\n")
	b.WriteString("Go-client↔Go-relay pairings contain no Rust peer, so they are outside this matrix's scope; that path is covered by the standard test suite.\n\n")
	fmt.Fprintf(&b, "Generated from commit `%s` at %s. A pass requires a recorded Rust process and binary digest; setup errors, unsupported cells, and untested cells never count as passes.\n\n", r.GoIroh.Commit, r.Generated.Format(time.RFC3339))
	b.WriteString("## How to read this table\n\n")
	b.WriteString("- `pass` means the implementations interoperated in the observed scenario and matched the expected verdict.\n")
	b.WriteString("- `fail (expected)` means the scenario ran, observed a wire incompatibility, and matched the expected verdict.\n")
	b.WriteString("- `FAIL (unexpected)` or `PASS (unexpected)` means the observation disagreed with the expected verdict.\n")
	b.WriteString("- `unsupported` means go-iroh lacks the feature, not that the feature is broken.\n")
	b.WriteString("- `setup-error` means the environment could not run the scenario, so it makes no compatibility claim.\n")
	b.WriteString("- `—` means the scenario was not run for that version.\n\n")
	b.WriteString("Released columns are compatibility claims against a pinned Rust release. A `-pre` column is expected-enforced evidence against a pinned upstream commit, not a claim about a shipped version. The `tip` column is a moving, advisory signal refreshed nightly and is never a committed compatibility claim. Experimental rows may change wire format to track upstream without a major go-iroh version bump.\n\n")
	b.WriteString("The Rust counterpart is either an **upstream CLI**, an unmodified program shipped by upstream iroh, or a **Rust test driver**, a purpose-built peer linked to the pinned upstream libraries. CLI results have the strongest black-box provenance; test-driver results cover protocol behavior that upstream CLIs do not expose.\n\n")
	b.WriteString("Matrix cells reference the **Peers** table below. Each peer entry records the Rust executable and its SHA-256 digest. The machine-readable result also records the peer process ID, so a pass cannot be emitted without evidence of a real Rust process.\n\n")
	b.WriteString("## Compatibility envelope\n\n")
	b.WriteString("| Surface | Tier | Upstream train | Status | Detail |\n|---|---|---|---|---|\n")
	for _, envelope := range r.Envelopes {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", envelope.Surface, envelope.Tier, envelope.UpstreamVersion, envelope.Status, envelope.Detail)
	}
	b.WriteString("\n")
	b.WriteString("## Compatibility matrix\n\n")
	b.WriteString("| Scenario | Tier | Rust counterpart |")
	for _, pin := range r.Pins {
		fmt.Fprintf(&b, " %s |", pin.label())
	}
	b.WriteString(" tip (advisory) |\n|---|---|---|")
	for range r.Pins {
		b.WriteString(":---:|")
	}
	b.WriteString(":---:|\n")
	byScenario := make(map[string]map[string]Cell)
	firstCell := make(map[string]Cell)
	var scenarios []string
	for _, c := range cells {
		if byScenario[c.Scenario] == nil {
			byScenario[c.Scenario] = make(map[string]Cell)
			firstCell[c.Scenario] = c
			scenarios = append(scenarios, c.Scenario)
		}
		byScenario[c.Scenario][c.Iroh] = c
	}
	for _, scenario := range scenarios {
		first := firstCell[scenario]
		fmt.Fprintf(&b, "| %s | %s | %s |", scenario, first.Tier, first.Counterpart)
		for _, pin := range r.Pins {
			cell, ok := byScenario[scenario][pin.Key]
			if !ok {
				b.WriteString(" — |")
				continue
			}
			fmt.Fprintf(&b, " %s |", formatAdjudication(cell, peerRefs[cell.Peer+"\x00"+cell.Iroh]))
		}
		b.WriteString(" — |\n")
	}
	b.WriteString("\nThe pinned 1.1-pre column currently exercises the bidirectional CustomAddr wire-vector suite in blocking CI; the full pinned matrix runs when the train is re-pinned to a release. The `tip` column is populated only in the nightly [advisory report](COMPATIBILITY-tip.md).\n")
	b.WriteString("\n### Peers\n\n| Ref | Rust peer | Pin | SHA-256 digest |\n|---:|---|---|---|\n")
	for i, peer := range peers {
		fmt.Fprintf(&b, "| [%d] | %s | %s | `%s` |\n", i+1, peer.name, peer.pin, peer.digest)
	}
	b.WriteString("\n### Observed incompatibility evidence\n\n")
	for _, c := range cells {
		if c.Result == Fail {
			fmt.Fprintf(&b, "- `%s` at %s: %s.\n", c.Scenario, r.pinLabel(c.Iroh), strings.TrimSuffix(c.Detail, "."))
		}
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

func (p Pin) label() string {
	if p.Kind == "pre-release" {
		return fmt.Sprintf("%s-pre @ %.7s", p.Train, p.Commit)
	}
	return fmt.Sprintf("%s (%s)", p.Train, p.Version)
}

func (r *Report) pinLabel(key string) string {
	for _, pin := range r.Pins {
		if pin.Key == key {
			return pin.label()
		}
	}
	return key
}

func formatAdjudication(cell Cell, peerRef int) string {
	var verdict string
	if cell.Result == cell.Expected {
		if cell.Result == Fail {
			verdict = "fail (expected)"
		} else {
			verdict = string(cell.Result)
		}
	} else {
		verdict = strings.ToUpper(string(cell.Result)) + " (unexpected)"
	}
	if peerRef != 0 {
		verdict += fmt.Sprintf(" [%d]", peerRef)
	}
	return verdict
}
