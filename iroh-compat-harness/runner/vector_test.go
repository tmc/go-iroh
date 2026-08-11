package runner

import "testing"

func TestVectorCorpusRequiresPeer(t *testing.T) {
	cells := RunVectorCorpus("", "", "1.0")
	for _, c := range cells {
		if c.Result != SetupError {
			t.Fatalf("%s = %s, want setup-error", c.Scenario, c.Result)
		}
	}
}
