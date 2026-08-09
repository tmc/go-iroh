package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tmc/go-iroh/iroh"
)

const pqALPN = "go-iroh-compat/pq/1"

func RunPQMatrix(bin, version, digest string) []Cell {
	return []Cell{
		runPQPolicy(bin, version, digest, "handshake/pq-only", "only", iroh.KeyExchangePQOnly, true),
		runPQPolicy(bin, version, digest, "handshake/prefer-pq", "prefer", iroh.KeyExchangePreferPQ, false),
	}
}

func runPQPolicy(bin, version, digest, scenario, rustPolicy string, goPolicy iroh.KeyExchangePolicy, refusal bool) (cell Cell) {
	cell = Cell{Scenario: scenario, Iroh: version, Tier: "B", Expected: Pass, Peer: "rust-driver@" + digest, PeerDigest: digest}
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var evidence strings.Builder
	pid, group, output, err := runGoClientRustPQServer(ctx, bin, rustPolicy, goPolicy)
	cell.PeerPID = pid
	fmt.Fprintf(&evidence, "go-client-rust-server: group=%s\n%s\n", group, output)
	if err != nil {
		return finishCell(cell, Fail, err.Error())
	}
	group, output, err = runRustClientGoPQServer(ctx, bin, rustPolicy, goPolicy)
	fmt.Fprintf(&evidence, "rust-client-go-server: group=%s\n%s\n", group, output)
	if err != nil {
		return finishCell(cell, Fail, err.Error())
	}
	if refusal {
		output, err = runPQRefusal(ctx, bin)
		fmt.Fprintf(&evidence, "pq-only refusal:\n%s\n", output)
		if err != nil {
			return finishCell(cell, Fail, err.Error())
		}
	}
	artifact, err := writePQArtifact(version, scenario, evidence.String())
	if err != nil {
		return finishCell(cell, SetupError, err.Error())
	}
	cell.Artifacts = []string{artifact}
	return finishCell(cell, Pass, "both directions negotiated X25519MLKEM768; artifact records Rust and Go evidence")
}

func runGoClientRustPQServer(ctx context.Context, bin, rustPolicy string, goPolicy iroh.KeyExchangePolicy) (int, string, string, error) {
	peer, err := startTransportPeerCommand(ctx, bin, "pq-server", rustPolicy)
	if err != nil {
		return 0, "", "", err
	}
	defer peer.close()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), irohRelayDisabled(), iroh.WithKeyExchangePolicy(goPolicy))
	if err != nil {
		return peer.cmd.Process.Pid, "", peer.output.String(), fmt.Errorf("bind Go PQ client: %w", err)
	}
	defer ep.Shutdown(context.Background())
	conn, err := ep.Connect(ctx, peer.endpointAddr(), pqALPN)
	if err != nil {
		return peer.cmd.Process.Pid, "", peer.output.String(), fmt.Errorf("connect Rust PQ server: %w", err)
	}
	group := conn.KeyExchangeGroup()
	if group != "X25519MLKEM768" {
		return peer.cmd.Process.Pid, group, peer.output.String(), fmt.Errorf("Go negotiated group %q", group)
	}
	if err := pqEcho(ctx, conn); err != nil {
		return peer.cmd.Process.Pid, group, peer.output.String(), err
	}
	_ = conn.Close()
	if err := peer.waitFor("pq-ok group=X25519MLKEM768"); err != nil {
		return peer.cmd.Process.Pid, group, peer.output.String(), err
	}
	return peer.cmd.Process.Pid, group, peer.output.String(), nil
}

func runRustClientGoPQServer(ctx context.Context, bin, rustPolicy string, goPolicy iroh.KeyExchangePolicy) (string, string, error) {
	ep, err := iroh.Bind(ctx, iroh.WithALPNs(pqALPN), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), irohRelayDisabled(), iroh.WithKeyExchangePolicy(goPolicy))
	if err != nil {
		return "", "", fmt.Errorf("bind Go PQ server: %w", err)
	}
	defer ep.Shutdown(context.Background())
	cmd := exec.CommandContext(ctx, bin, "pq-client", rustPolicy, ep.ID().String(), ep.LocalAddr().String())
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return "", out.String(), fmt.Errorf("start Rust PQ client: %w", err)
	}
	conn, err := ep.Accept(ctx)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", out.String(), fmt.Errorf("accept Rust PQ client: %w", err)
	}
	group := conn.KeyExchangeGroup()
	stream, err := conn.AcceptStream(ctx)
	if err == nil {
		var data []byte
		data, err = io.ReadAll(stream)
		if err == nil {
			_, err = stream.Write(data)
		}
		if closeErr := stream.Close(); err == nil {
			err = closeErr
		}
	}
	waitErr := cmd.Wait()
	_ = conn.Close()
	if err != nil || waitErr != nil || group != "X25519MLKEM768" || !strings.Contains(out.String(), "pq-ok group=X25519MLKEM768") {
		return group, out.String(), fmt.Errorf("Rust client exchange: group=%q serve=%v peer=%v: %s", group, err, waitErr, out.String())
	}
	return group, out.String(), nil
}

func runPQRefusal(ctx context.Context, bin string) (string, error) {
	peer, err := startTransportPeerCommand(ctx, bin, "pq-server", "only")
	if err != nil {
		return "", err
	}
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), irohRelayDisabled(), iroh.WithKeyExchangePolicy(iroh.KeyExchangeClassical))
	if err != nil {
		peer.close()
		return "", err
	}
	_, goErr := ep.Connect(ctx, peer.endpointAddr(), pqALPN)
	_ = ep.Shutdown(context.Background())
	peer.close()
	if goErr == nil {
		return "", fmt.Errorf("classical Go unexpectedly connected to PQ-only Rust")
	}

	peer, err = startTransportPeerCommand(ctx, bin, "pq-server", "only")
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, bin, "pq-client", "classical", peer.id.String(), peer.addr.String())
	var rustOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &rustOut, &rustOut
	rustErr := cmd.Run()
	peer.close()
	if rustErr == nil {
		return rustOut.String(), fmt.Errorf("classical Rust unexpectedly connected to PQ-only Rust")
	}
	return fmt.Sprintf("go-classical error: %v\nrust-classical error: %v\n%s", goErr, rustErr, rustOut.String()), nil
}

func pqEcho(ctx context.Context, conn *iroh.Conn) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err := stream.Write([]byte("pq-ping")); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	got, err := io.ReadAll(stream)
	if err != nil || string(got) != "pq-ping" {
		return fmt.Errorf("PQ echo = %q, err %v", got, err)
	}
	return nil
}

func startTransportPeerCommand(ctx context.Context, bin string, args ...string) (*transportPeer, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	return startTransportPeerProcess(cmd)
}

func writePQArtifact(version, scenario, evidence string) (string, error) {
	root, err := harnessRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "results", "artifacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create PQ artifact directory: %w", err)
	}
	name := strings.ReplaceAll(scenario, "/", "-") + "-" + version + ".log"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(evidence), 0o644); err != nil {
		return "", fmt.Errorf("write PQ artifact: %w", err)
	}
	return filepath.ToSlash(filepath.Join("results", "artifacts", name)), nil
}

func harnessRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "scenarios", "handshake.json")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("compatibility harness root not found")
		}
		dir = parent
	}
}
