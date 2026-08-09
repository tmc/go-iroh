package runner

import "testing"

func TestExtendedCellsFailClosed(t *testing.T) {
	cells := ExtendedCells("1.0.3")
	if len(cells) != 17 {
		t.Fatalf("extended cells = %d, want 17", len(cells))
	}
	for _, c := range cells {
		if c.Result != Unsupported || c.Expected != Unsupported {
			t.Fatalf("%s = %s/%s, want unsupported", c.Scenario, c.Result, c.Expected)
		}
		if c.Detail == "" {
			t.Fatalf("%s lacks unsupported reason", c.Scenario)
		}
	}
}
