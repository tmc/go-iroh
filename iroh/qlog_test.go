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
	defer conn.CloseWithError(0, "")
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var client0, server0 string
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), "_client.sqlog"):
			client0 = strings.TrimSuffix(e.Name(), "_client.sqlog")
		case strings.HasSuffix(e.Name(), "_server.sqlog"):
			server0 = strings.TrimSuffix(e.Name(), "_server.sqlog")
		}
	}
	if client0 == "" || server0 == "" {
		t.Fatalf("QLOGDIR=%s holds %v, want a _client.sqlog and a _server.sqlog", dir, entries)
	}
	if client0 != server0 {
		t.Errorf("trace ids differ: client %q, server %q; the two ends share the original destination connection id", client0, server0)
	}
	b, err := os.ReadFile(filepath.Join(dir, client0+"_client.sqlog"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"vantage_point":{"type":"client"}`) {
		t.Errorf("client trace does not declare a client vantage point")
	}
}
