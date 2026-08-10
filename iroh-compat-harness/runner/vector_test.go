package runner

import "testing"

func TestVectorCorpusVersionBoundary(t *testing.T) {
	cells := RunVectorCorpus("", "", "1.0.0")
	for _, c := range cells {
		if c.Result != Unsupported {
			t.Fatalf("%s = %s, want unsupported", c.Scenario, c.Result)
		}
	}
}
