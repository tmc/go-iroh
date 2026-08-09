package runner

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tmc/go-iroh/internal/relayclient"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func RunRelayMatrix(goRelay, rustRelay, rustClient, version, relayDigest, rustClientDigest string) []Cell {
	return []Cell{
		runGoRelayClient(rustRelay, true, version, relayDigest, "relay/go-client-rust-relay"),
		runRustRelayClient(goRelay, false, rustClient, version, rustClientDigest, "relay/rust-client-go-relay"),
		runRustRelayClient(rustRelay, true, rustClient, version, rustClientDigest, "relay/rust-client-rust-relay"),
		runGoRelayClient(rustRelay, true, version, relayDigest, "relay/websocket-upgrade"),
		runGoRelayClient(rustRelay, true, version, relayDigest, "relay/ping-pong"),
		runRelayEstablishTimeout(rustRelay, version, relayDigest),
	}
}

func runGoRelayClient(bin string, rust bool, version, digest, scenario string) (cell Cell) {
	cell = relayCell(scenario, version, digest)
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := startRelayServer(ctx, bin, rust)
	if err != nil {
		return finishCell(cell, SetupError, err.Error())
	}
	defer server.close()
	cell.PeerPID = server.cmd.Process.Pid

	if err := runGoRelayClientAgainst(ctx, server.addr); err != nil {
		return finishCell(cell, Fail, err.Error()+": "+server.output.String())
	}
	return finishCell(cell, Pass, "Go client negotiated relay protocol 2 and received the Rust pong")
}

func runGoRelayClientAgainst(ctx context.Context, addr string) error {
	u, err := netaddr.ParseRelayURL("http://" + addr)
	if err != nil {
		return fmt.Errorf("parse relay URL: %w", err)
	}
	sk := key.NewSecretKey([key.SeedSize]byte{0x31})
	client, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: sk})
	if err != nil {
		return fmt.Errorf("Go client WebSocket/auth: %w", err)
	}
	defer client.Close()
	var ping [8]byte
	copy(ping[:], "parity42")
	if err := client.Send(ctx, relayproto.ClientToRelayMsg{Type: relayproto.FramePing, Ping: ping}); err != nil {
		return fmt.Errorf("send ping: %w", err)
	}
	msg, err := client.Recv(ctx)
	if err != nil {
		return fmt.Errorf("receive pong: %w", err)
	}
	if msg.Type != relayproto.FramePong || msg.Ping != ping {
		return fmt.Errorf("pong = %#v", msg)
	}
	return nil
}

func runRustRelayClient(relayBin string, rustRelay bool, rustClient, version, digest, scenario string) (cell Cell) {
	cell = relayCell(scenario, version, digest)
	cell.Tier = "B"
	cell.Peer = "rust-driver@" + digest
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := startRelayServer(ctx, relayBin, rustRelay)
	if err != nil {
		return finishCell(cell, SetupError, err.Error())
	}
	defer server.close()

	cmd := exec.CommandContext(ctx, rustClient, "relay-ping", "http://"+server.addr)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("start Rust relay client: %v", err))
	}
	cell.PeerPID = cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("Rust relay client: %v: %s", err, out.String()))
	}
	if !strings.Contains(out.String(), "relay pong") {
		return finishCell(cell, Fail, "Rust driver did not report a successful relay ping: "+out.String())
	}
	return finishCell(cell, Pass, "Tier B Rust client negotiated the upstream relay protocol and received a pong")
}

func runRelayEstablishTimeout(bin, version, digest string) (cell Cell) {
	cell = relayCell("relay/idle-timeout", version, digest)
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	server, err := startRelayServer(ctx, bin, true)
	if err != nil {
		return finishCell(cell, SetupError, err.Error())
	}
	defer server.close()
	cell.PeerPID = server.cmd.Process.Pid

	conn, err := net.DialTimeout("tcp", server.addr, 3*time.Second)
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("dial Rust relay: %v", err))
	}
	defer conn.Close()
	wait := time.Now()
	if err := conn.SetReadDeadline(time.Now().Add(40 * time.Second)); err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("set read deadline: %v", err))
	}
	var b [1]byte
	_, err = conn.Read(b[:])
	elapsed := time.Since(wait)
	if err == nil {
		return finishCell(cell, Fail, "idle pre-WebSocket connection unexpectedly received data")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return finishCell(cell, Fail, "Rust relay did not enforce its 30-second establish timeout")
	}
	if elapsed < 25*time.Second || elapsed > 40*time.Second {
		return finishCell(cell, Fail, fmt.Sprintf("Rust relay closed idle connection after %s, want about 30s", elapsed.Round(time.Millisecond)))
	}
	return finishCell(cell, Pass, fmt.Sprintf("Rust relay closed an idle pre-WebSocket connection after %s", elapsed.Round(time.Millisecond)))
}

func relayCell(scenario, version, digest string) Cell {
	return Cell{Scenario: scenario, Iroh: version, Tier: "A", Expected: Pass, Peer: "iroh-relay@" + digest, PeerDigest: digest}
}

type relayProcess struct {
	cmd     *exec.Cmd
	addr    string
	output  bytes.Buffer
	cleanup func()
}

func startRelayServer(ctx context.Context, bin string, rust bool) (*relayProcess, error) {
	addr, err := unusedTCPAddr()
	if err != nil {
		return nil, fmt.Errorf("reserve relay address: %w", err)
	}
	var cmd *exec.Cmd
	var cleanup func()
	if rust {
		dir, err := parityTempDir("rust-relay.")
		if err != nil {
			return nil, fmt.Errorf("create Rust relay config directory: %w", err)
		}
		cleanup = func() { os.RemoveAll(dir) }
		config := filepath.Join(dir, "relay.toml")
		text := fmt.Sprintf("http_bind_addr = %q\nenable_metrics = false\n", addr)
		if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
			cleanup()
			return nil, fmt.Errorf("write Rust relay config: %w", err)
		}
		cmd = exec.CommandContext(ctx, bin, "--dev", "--config-path", config)
	} else {
		cleanup = func() {}
		cmd = exec.CommandContext(ctx, bin, "-addr", addr)
	}
	p := &relayProcess{cmd: cmd, addr: addr, cleanup: cleanup}
	cmd.Stdout, cmd.Stderr = &p.output, &p.output
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, fmt.Errorf("start relay server: %w", err)
	}
	if err := waitForTCP(ctx, addr); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cleanup()
		return nil, fmt.Errorf("relay readiness: %w: %s", err, p.output.String())
	}
	return p, nil
}

// close terminates a relay process. Temporary configuration is removed by the
// command context or the process-specific cleanup registered in startRelayServer.
func (p *relayProcess) close() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
	if p.cleanup != nil {
		p.cleanup()
	}
}

func unusedTCPAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	err = ln.Close()
	return addr, err
}

func waitForTCP(ctx context.Context, addr string) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			return conn.Close()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func parityTempDir(pattern string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	base := filepath.Join(home, "tmp")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, pattern)
}
