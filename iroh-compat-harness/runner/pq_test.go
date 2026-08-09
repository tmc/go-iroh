package runner

import (
	"os"
	"testing"
)

func TestPQMatrixLive(t *testing.T) {
	bin := os.Getenv("RUST_PQ_BIN")
	if bin == "" {
		t.Skip("RUST_PQ_BIN is not set")
	}
	digest, err := FileDigest(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range RunPQMatrix(bin, "1.0.3", digest) {
		if cell.Result != Pass {
			t.Errorf("%s = %s: %s", cell.Scenario, cell.Result, cell.Detail)
		}
	}
}
