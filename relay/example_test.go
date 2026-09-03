package relay_test

import (
	"context"
	"fmt"
	"time"

	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

func ExampleMap_Nearest() {
	near, err := netaddr.ParseRelayURL("https://near.example")
	if err != nil {
		panic(err)
	}
	far, err := netaddr.ParseRelayURL("https://far.example")
	if err != nil {
		panic(err)
	}
	m := relay.MapFromURLs(far, near)
	got, err := m.Nearest(context.Background(), func(_ context.Context, u netaddr.RelayURL) (time.Duration, error) {
		if u.Equal(near) {
			return time.Millisecond, nil
		}
		return 10 * time.Millisecond, nil
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(got)
	// Output: https://near.example/
}
