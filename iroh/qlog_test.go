package iroh

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// TestQLOGDIRWritesTraces pins the tracing documented in the package doc and
// the README: setting QLOGDIR records one sqlog per connection end, named
// <odcid>_client.sqlog and <odcid>_server.sqlog, with no code change.
func TestQLOGDIRWritesTraces(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("QLOGDIR", dir)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := Bind(ctx, WithALPNs("iroh-qlog-test/0"), WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	accepted := make(chan error, 1)
	go func() {
		_, err := server.Accept(ctx)
		accepted <- err
	}()
	client, err := Bind(ctx, WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(context.Background())

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, "iroh-qlog-test/0")
	if err != nil {
		t.Fatal(err)
	}
	// Close on every path out of the test, including a t.Fatal below; the
	// second close is a no-op.
	defer conn.CloseWithError(0, "")
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	// The traces are written through a buffer that is flushed when the
	// connection ends, so close first and then wait for the flush to land.
	if err := conn.CloseWithError(0, ""); err != nil {
		t.Fatal(err)
	}

	var client0, server0 string
	var b []byte
	for {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		client0, server0 = "", ""
		for _, e := range entries {
			switch {
			case strings.HasSuffix(e.Name(), "_client.sqlog"):
				client0 = strings.TrimSuffix(e.Name(), "_client.sqlog")
			case strings.HasSuffix(e.Name(), "_server.sqlog"):
				server0 = strings.TrimSuffix(e.Name(), "_server.sqlog")
			}
		}
		if client0 != "" && server0 != "" {
			b, err = os.ReadFile(filepath.Join(dir, client0+"_client.sqlog"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), `"vantage_point":{"type":"client"}`) {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("QLOGDIR=%s holds %v, want a flushed _client.sqlog and _server.sqlog: %v", dir, entries, ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if client0 != server0 {
		t.Errorf("trace ids differ: client %q, server %q; the two ends share the original destination connection id", client0, server0)
	}
}
