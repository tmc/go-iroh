package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type scenarioFile struct {
	Scenarios []scenario `json:"scenarios"`
}

type scenario struct {
	Name     string             `json:"name"`
	Expected map[string]Verdict `json:"expected"`
}

func ApplyExpected(dir, version string, cells []Cell) error {
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return fmt.Errorf("find scenarios: %w", err)
	}
	want := make(map[string]Verdict)
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
			v, ok := s.Expected[version]
			if !ok {
				return fmt.Errorf("scenario %s lacks expected verdict for iroh %s", s.Name, version)
			}
			if _, dup := want[s.Name]; dup {
				return fmt.Errorf("duplicate scenario %s", s.Name)
			}
			want[s.Name] = v
		}
	}
	for i := range cells {
		v, ok := want[cells[i].Scenario]
		if !ok {
			return fmt.Errorf("cell %s has no scenario declaration", cells[i].Scenario)
		}
		cells[i].Expected = v
		delete(want, cells[i].Scenario)
	}
	if len(want) != 0 {
		return fmt.Errorf("declared scenarios were not executed: %v", want)
	}
	return nil
}
