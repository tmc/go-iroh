package mdns_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/iroh/mdns"
	"github.com/tmc/go-iroh/key"
)

func ExampleDiscovery() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sk, err := key.GenerateSecretKey()
	if err != nil {
		panic(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	discovery := mdns.New(sk.Public().EndpointID(), mdns.WithLogger(logger))
	go func() { _ = discovery.Start(ctx) }()

	var services iroh.AddressLookupServices
	services.AddPublisher(discovery)
	services.AddResolver(discovery)

	fmt.Println(discovery != nil)
	// Output:
	// true
}
