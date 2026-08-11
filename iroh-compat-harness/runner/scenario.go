package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type scenarioFile struct {
	Scenarios []scenario `json:"scenarios"`
	Envelopes []Envelope `json:"envelopes"`
}

type scenario struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Tier        string             `json:"tier"`
	Counterpart string             `json:"counterpart"`
	Expected    map[string]Verdict `json:"expected"`
}

func LoadEnvelopes(dir string) ([]Envelope, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("find compatibility envelopes: %w", err)
	}
	var envelopes []Envelope
	for _, path := range matches {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read compatibility envelopes: %w", err)
		}
		var file scenarioFile
		if err := json.Unmarshal(b, &file); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		envelopes = append(envelopes, file.Envelopes...)
	}
	return envelopes, nil
}

func ApplyExpected(dir, version string, cells []Cell) error {
	return applyExpected(dir, version, cells, true)
}

// ApplyExpectedSubset applies predictions to a deliberately partial scenario
// run, such as the upstream-main wire drift canary.
func ApplyExpectedSubset(dir, version string, cells []Cell) error {
	return applyExpected(dir, version, cells, false)
}

func applyExpected(dir, version string, cells []Cell, requireAll bool) error {
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return fmt.Errorf("find scenarios: %w", err)
	}
	want := make(map[string]scenario)
	for _, path := range matches {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read scenarios: %w", err)
		}
		var file scenarioFile
		if err := json.Unmarshal(b, &file); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
		for _, s := range file.Scenarios {
			if strings.TrimSpace(s.Description) == "" {
				return fmt.Errorf("scenario %s lacks description", s.Name)
			}
			if s.Tier != "stable" && s.Tier != "experimental" {
				return fmt.Errorf("scenario %s has invalid tier %q", s.Name, s.Tier)
			}
			if s.Counterpart != "upstream CLI" && s.Counterpart != "Rust test driver" {
				return fmt.Errorf("scenario %s has invalid counterpart %q", s.Name, s.Counterpart)
			}
			_, ok := s.Expected[version]
			if requireAll && !ok {
				return fmt.Errorf("scenario %s lacks expected verdict for iroh %s", s.Name, version)
			}
			if _, dup := want[s.Name]; dup {
				return fmt.Errorf("duplicate scenario %s", s.Name)
			}
			want[s.Name] = s
		}
	}
	for i := range cells {
		s, ok := want[cells[i].Scenario]
		if !ok {
			return fmt.Errorf("cell %s has no scenario declaration", cells[i].Scenario)
		}
		expected, ok := s.Expected[version]
		if !ok {
			return fmt.Errorf("scenario %s lacks expected verdict for iroh %s", s.Name, version)
		}
		cells[i].Expected = expected
		cells[i].Description = s.Description
		cells[i].Tier = s.Tier
		cells[i].Counterpart = s.Counterpart
		delete(want, cells[i].Scenario)
	}
	if requireAll && len(want) != 0 {
		return fmt.Errorf("declared scenarios were not executed: %v", want)
	}
	return nil
}
