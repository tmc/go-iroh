package metrics_test

import (
	"fmt"
	"os"

	"github.com/tmc/go-iroh/metrics"
)

type requests struct{ n uint64 }

func (r requests) Snapshot() metrics.Snapshot {
	return metrics.Snapshot{"requests": r.n}
}

func ExampleRegistry() {
	registry := metrics.NewRegistry()
	if err := registry.Register("server", requests{n: 3}); err != nil {
		panic(err)
	}
	if err := registry.WriteOpenMetrics(os.Stdout); err != nil {
		panic(err)
	}
	fmt.Println("done")
	// Output:
	// # TYPE server_requests counter
	// server_requests_total 3
	// # EOF
	// done
}
