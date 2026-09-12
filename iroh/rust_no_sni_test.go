package iroh

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestLiveRustClientNoSNI checks the Rust 1.2.0 client's default TLS behavior.
// Build testdata/rust-no-sni and set GO_IROH_RUST_NO_SNI_BIN to its binary.
func TestLiveRustClientNoSNI(t *testing.T) {
	bin := os.Getenv("GO_IROH_RUST_NO_SNI_BIN")
	if bin == "" {
		t.Skip("set GO_IROH_RUST_NO_SNI_BIN to the Rust 1.2.0 test client")
	}
	var err error
	bin, err = filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server, err := Bind(ctx, WithALPNs("go-iroh/no-sni/1"), WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	cmd := exec.CommandContext(ctx, bin, server.ID().String(), server.LocalAddr().String())
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = cmd.Wait()
		}
	}()
	conn, err := server.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := conn.qc.ConnectionState().TLS.ServerName; got != "" {
		t.Fatalf("Rust ClientHello ServerName = %q, want no SNI", got)
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	message, err := io.ReadAll(io.LimitReader(stream, 1024))
	if err != nil {
		t.Fatal(err)
	}
	if string(message) != "no-sni round trip" {
		t.Fatalf("Rust message = %q", message)
	}
	if _, err := stream.Write(message); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("Rust client: %v\n%s", err, &output)
	}
	if !bytes.Contains(output.Bytes(), []byte("echo verified")) {
		t.Fatalf("Rust output: %s", &output)
	}
	t.Log("Rust client completed handshake with empty SNI and verified echo")
}
