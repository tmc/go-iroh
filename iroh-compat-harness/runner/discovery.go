package runner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/pkarr"
)

func RunDiscovery(goDNS, rustDNS, rustRelay, rustClient, version, dnsDigest, relayDigest, clientDigest string) []Cell {
	return []Cell{
		runGoPublishRustDNS(rustDNS, version, dnsDigest),
		runRustPublishGoDNS(goDNS, rustClient, version, clientDigest),
		runRelayURLAgreement(rustRelay, rustClient, version, relayDigest, clientDigest),
	}
}

func runGoPublishRustDNS(bin, version, digest string) (cell Cell) {
	cell = Cell{Scenario: "discovery/go-publish-rust-dns", Iroh: version, Tier: "A", Expected: Pass, Peer: "iroh-dns-server@" + digest, PeerDigest: digest}
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server, err := startDNSServer(ctx, bin, true)
	if err != nil {
		return finishCell(cell, SetupError, err.Error())
	}
	defer server.close()
	cell.PeerPID = server.cmd.Process.Pid
	sk := key.NewSecretKey([key.SeedSize]byte{0x44})
	packet, err := pkarr.FromTxtStrings(sk, "_iroh", []string{"relay=https://relay.example/", "addr=127.0.0.1:4433"}, 30)
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("create Go pkarr packet: %v", err))
	}
	if err := putPacket(ctx, server.addr, sk.Public().EndpointID().Z32(), packet.RelayPayload()); err != nil {
		return finishCell(cell, Fail, err.Error()+": "+server.output.String())
	}
	got, err := getPacket(ctx, server.addr, sk.Public().EndpointID().Z32())
	if err != nil || !bytes.Equal(got, packet.RelayPayload()) {
		return finishCell(cell, Fail, fmt.Sprintf("observe Go packet from Rust server: %v", err))
	}
	return finishCell(cell, Pass, "upstream Rust DNS server stored and returned a Go-signed pkarr packet")
}

func runRustPublishGoDNS(goDNS, rustClient, version, digest string) (cell Cell) {
	cell = Cell{Scenario: "discovery/rust-publish-go-dns", Iroh: version, Tier: "B", Expected: Pass, Peer: "rust-driver@" + digest, PeerDigest: digest}
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server, err := startDNSServer(ctx, goDNS, false)
	if err != nil {
		return finishCell(cell, SetupError, err.Error())
	}
	defer server.close()
	cmd := exec.CommandContext(ctx, rustClient, "dns-publish", server.addr)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("start Rust pkarr publisher: %v", err))
	}
	cell.PeerPID = cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("Rust pkarr publisher: %v: %s", err, out.String()))
	}
	var published struct {
		Key     string `json:"key"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(out.Bytes(), &published); err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("decode Rust publication evidence: %v: %s", err, out.String()))
	}
	want, err := hex.DecodeString(published.Payload)
	if err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("decode Rust relay payload: %v", err))
	}
	got, err := getPacket(ctx, server.addr, published.Key)
	if err != nil || !bytes.Equal(got, want) {
		return finishCell(cell, Fail, fmt.Sprintf("observe Rust packet from Go server: %v", err))
	}
	return finishCell(cell, Pass, "Go DNS server stored and returned a Tier B Rust-signed pkarr packet")
}

func runRelayURLAgreement(relayBin, rustClient, version, relayDigest, clientDigest string) (cell Cell) {
	cell = Cell{Scenario: "discovery/relay-urls", Iroh: version, Tier: "A", Expected: Pass, Peer: "iroh-relay@" + relayDigest, PeerDigest: relayDigest}
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server, err := startRelayServer(ctx, relayBin, true)
	if err != nil {
		return finishCell(cell, SetupError, err.Error())
	}
	defer server.close()
	cell.PeerPID = server.cmd.Process.Pid
	goCell := runGoRelayClientAgainst(ctx, server.addr)
	if goCell != nil {
		return finishCell(cell, Fail, goCell.Error())
	}
	cmd := exec.CommandContext(ctx, rustClient, "relay-ping", "http://"+server.addr)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil || !strings.Contains(out.String(), "relay pong") {
		return finishCell(cell, Fail, fmt.Sprintf("Tier B Rust relay URL probe (%s): %v: %s", clientDigest, err, out.String()))
	}
	return finishCell(cell, Pass, "Go and Tier B Rust clients both resolved and reached the same upstream relay URL")
}

func putPacket(ctx context.Context, addr, key string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://"+addr+"/pkarr/"+key, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("publish pkarr packet: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("publish pkarr packet: status %s", resp.Status)
	}
	return nil
}

func getPacket(ctx context.Context, addr, key string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/pkarr/"+key, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET pkarr packet: status %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

type dnsProcess struct {
	cmd     *exec.Cmd
	addr    string
	output  bytes.Buffer
	cleanup func()
}

func startDNSServer(ctx context.Context, bin string, rust bool) (*dnsProcess, error) {
	addr, err := unusedTCPAddr()
	if err != nil {
		return nil, fmt.Errorf("reserve DNS HTTP address: %w", err)
	}
	var cmd *exec.Cmd
	cleanup := func() {}
	if rust {
		dir, err := parityTempDir("rust-dns.")
		if err != nil {
			return nil, err
		}
		cleanup = func() { _ = os.RemoveAll(dir) }
		_, port, _ := strings.Cut(addr, ":")
		config := fmt.Sprintf("data_dir = %q\nhttp = { port = %s, bind_addr = \"127.0.0.1\" }\ndns = { port = 0, bind_addr = \"127.0.0.1\", origins = [\".\"], default_soa = \"localhost hostmaster.localhost 0 10800 3600 604800 3600\", default_ttl = 30 }\nmetrics = { disabled = true }\nmainline = { enabled = false }\n", filepath.Join(dir, "data"), port)
		path := filepath.Join(dir, "dns.toml")
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			cleanup()
			return nil, err
		}
		cmd = exec.CommandContext(ctx, bin, "--config", path)
	} else {
		cmd = exec.CommandContext(ctx, bin, "-addr", addr)
	}
	p := &dnsProcess{cmd: cmd, addr: addr, cleanup: cleanup}
	cmd.Stdout, cmd.Stderr = &p.output, &p.output
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, fmt.Errorf("start DNS server: %w", err)
	}
	if err := waitForTCP(ctx, addr); err != nil {
		p.close()
		return nil, fmt.Errorf("DNS readiness: %w: %s", err, p.output.String())
	}
	return p, nil
}

func (p *dnsProcess) close() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
	p.cleanup()
}
