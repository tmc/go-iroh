package relay

import (
	"sync"
	"testing"

	"github.com/tmc/go-iroh/netaddr"
)

// TestMapConcurrentAccess exercises the map from several goroutines at once:
// an endpoint hands the same Map to the relay actor, which mutates it, and to
// net_report, which reads it from a background goroutine.
func TestMapConcurrentAccess(t *testing.T) {
	urls := make([]netaddr.RelayURL, 8)
	for i := range urls {
		u, err := netaddr.ParseRelayURL("https://relay" + string(rune('a'+i)) + ".example.com")
		if err != nil {
			t.Fatal(err)
		}
		urls[i] = u
	}
	m := MapFromURLs(urls...)

	const iters = 500
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go func(u netaddr.RelayURL) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				m.Remove(u)
				m.Insert(Config{URL: u, QUIC: &QUICConfig{Port: DefaultQUICPort}})
			}
		}(u)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				m.Configs()
				m.URLs()
				m.Len()
				m.IsEmpty()
				m.Contains(urls[0])
				m.Get(urls[1])
				m.Clone()
				_ = m.String()
			}
		}()
	}
	wg.Wait()
}
