package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

var ordinaryVectorScenarios = []string{
	"vectors/keys-z32-sign",
	"vectors/postcard-varints",
	"vectors/endpoint-ticket-roundtrip",
	"vectors/pkarr-txt",
}

var customAddrScenarios = []string{
	"vectors/custom-addr-ticket-rust-to-go",
	"vectors/custom-addr-ticket-go-to-rust",
}

var vectorScenarios = append(append([]string(nil), ordinaryVectorScenarios...), customAddrScenarios...)

func RunVectorCorpus(bin, corpus, version string) []Cell {
	if bin == "" {
		return vectorCells(version, SetupError, "RUST_VECTOR_BIN is not set", "", 0, "")
	}
	digest, err := FileDigest(bin)
	if err != nil {
		return vectorCells(version, SetupError, err.Error(), "", 0, "")
	}
	want, err := os.ReadFile(corpus)
	if err != nil {
		return vectorCells(version, SetupError, fmt.Sprintf("read vector corpus: %v", err), "", 0, "")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return vectorCells(version, SetupError, fmt.Sprintf("start Rust vector peer: %v", err), digest, 0, "")
	}
	pid := cmd.Process.Pid
	err = cmd.Wait()
	duration := time.Since(start).Milliseconds()
	peer := "rust-driver@" + digest
	if err != nil {
		return vectorCells(version, Fail, fmt.Sprintf("Rust vector peer: %v: %s", err, stderr.String()), digest, pid, peer)
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		return vectorCells(version, Fail, "fresh Rust vectors differ from committed corpus", digest, pid, peer)
	}
	cells := vectorCellsFor(ordinaryVectorScenarios, version, Pass, "fresh Rust output is byte-identical to the Go-verified corpus", digest, pid, peer)
	for i := range cells {
		cells[i].DurationMS = duration
	}
	cells = append(cells, customAddrCells(bin, want, version, digest, pid, peer, duration)...)
	return cells
}

// RunCustomAddrLive runs only the bidirectional CustomAddr ticket vectors.
// It is used by the upstream-main drift canary, where no released golden
// corpus exists yet.
func RunCustomAddrLive(bin, version string) []Cell {
	if bin == "" {
		return vectorCellsFor(customAddrScenarios, version, SetupError, "RUST_VECTOR_BIN is not set", "", 0, "")
	}
	digest, err := FileDigest(bin)
	if err != nil {
		return vectorCellsFor(customAddrScenarios, version, SetupError, err.Error(), "", 0, "")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "custom-addr-vectors")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return vectorCellsFor(customAddrScenarios, version, SetupError, fmt.Sprintf("start Rust CustomAddr vector peer: %v", err), digest, 0, "")
	}
	pid := cmd.Process.Pid
	peer := "rust-driver@" + digest
	if err := cmd.Wait(); err != nil {
		return vectorCellsFor(customAddrScenarios, version, SetupError, fmt.Sprintf("Rust CustomAddr vector peer: %v: %s", err, stderr.String()), digest, pid, peer)
	}
	return customAddrCells(bin, stdout.Bytes(), version, digest, pid, peer, time.Since(start).Milliseconds())
}

func vectorCells(version string, result Verdict, detail, digest string, pid int, peer string) []Cell {
	return vectorCellsFor(vectorScenarios, version, result, detail, digest, pid, peer)
}

func vectorCellsFor(scenarios []string, version string, result Verdict, detail, digest string, pid int, peer string) []Cell {
	cells := make([]Cell, len(scenarios))
	for i, scenario := range scenarios {
		cells[i] = Cell{
			Scenario: scenario, Iroh: version, Result: result,
			Detail: detail, Peer: peer, PeerPID: pid, PeerDigest: digest,
		}
	}
	return cells
}

type customAddrCorpus struct {
	Tickets []customAddrTicket `json:"custom_addr_tickets"`
}

type customAddrTicket struct {
	Length  int    `json:"length"`
	Encoded string `json:"encoded"`
}

func customAddrCells(bin string, corpus []byte, version, digest string, corpusPID int, peer string, duration int64) []Cell {
	var vectors customAddrCorpus
	if err := json.Unmarshal(corpus, &vectors); err != nil || len(vectors.Tickets) == 0 {
		return vectorCellsFor(customAddrScenarios, version, SetupError, "decode CustomAddr vectors", digest, corpusPID, peer)
	}

	rustAccepted := 0
	for _, vector := range vectors.Tickets {
		ticket, err := endpointticket.Parse(vector.Encoded)
		if err == nil && customAddrMatches(ticket, vector.Length) {
			rustAccepted++
		}
	}
	rustResult := Fail
	if rustAccepted == len(vectors.Tickets) {
		rustResult = Pass
	}
	rustToGo := Cell{
		Scenario: "vectors/custom-addr-ticket-rust-to-go", Iroh: version, Result: rustResult,
		Detail: fmt.Sprintf("Go accepted %d/%d Rust CustomAddr tickets", rustAccepted, len(vectors.Tickets)),
		Peer:   peer, PeerPID: corpusPID, PeerDigest: digest, DurationMS: duration,
		Evidence: map[string]any{"accepted": rustAccepted, "lengths": customAddrLengths(vectors.Tickets)},
	}

	requests := make([]customAddrTicket, len(vectors.Tickets))
	for i, vector := range vectors.Tickets {
		requests[i] = customAddrTicket{Length: vector.Length, Encoded: goCustomAddrTicket(vector.Length).String()}
	}
	input, err := json.Marshal(requests)
	if err != nil {
		return []Cell{rustToGo, customSetupCell("encode Go CustomAddr tickets", version, digest, peer)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "custom-addr-decode")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return []Cell{rustToGo, customSetupCell(fmt.Sprintf("start Rust CustomAddr decoder: %v", err), version, digest, peer)}
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		cell := customSetupCell(fmt.Sprintf("Rust CustomAddr decoder: %v: %s", err, stderr.String()), version, digest, peer)
		cell.PeerPID = pid
		return []Cell{rustToGo, cell}
	}
	var accepted []bool
	if err := json.Unmarshal(stdout.Bytes(), &accepted); err != nil || len(accepted) != len(requests) {
		cell := customSetupCell("decode Rust CustomAddr results", version, digest, peer)
		cell.PeerPID = pid
		return []Cell{rustToGo, cell}
	}
	acceptedCount := 0
	for _, ok := range accepted {
		if ok {
			acceptedCount++
		}
	}
	goResult := Fail
	if acceptedCount == len(accepted) {
		goResult = Pass
	}
	goToRust := Cell{
		Scenario: "vectors/custom-addr-ticket-go-to-rust", Iroh: version, Result: goResult,
		Detail: fmt.Sprintf("Rust accepted %d/%d Go CustomAddr tickets", acceptedCount, len(accepted)),
		Peer:   peer, PeerPID: pid, PeerDigest: digest, DurationMS: time.Since(start).Milliseconds(),
		Evidence: map[string]any{"accepted": acceptedCount, "lengths": customAddrLengths(vectors.Tickets)},
	}
	return []Cell{rustToGo, goToRust}
}

func customSetupCell(detail, version, digest, peer string) Cell {
	return Cell{
		Scenario: "vectors/custom-addr-ticket-go-to-rust", Iroh: version, Result: SetupError,
		Detail: detail, Peer: peer, PeerDigest: digest,
	}
}

func customAddrLengths(vectors []customAddrTicket) []int {
	lengths := make([]int, len(vectors))
	for i, vector := range vectors {
		lengths[i] = vector.Length
	}
	return lengths
}

func goCustomAddrTicket(length int) endpointticket.Ticket {
	var seed [key.SeedSize]byte
	for i := range seed {
		seed[i] = 0x2a
	}
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(i)
	}
	addr := netaddr.NewEndpointAddr(
		key.NewSecretKey(seed).Public().EndpointID(),
		netaddr.NewCustomAddr(42, data),
	)
	return endpointticket.New(addr)
}

func customAddrMatches(ticket endpointticket.Ticket, length int) bool {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(i)
	}
	for _, addr := range ticket.Addr().Addrs() {
		if custom, ok := addr.(netaddr.CustomAddr); ok && custom.ID() == 42 && bytes.Equal(custom.Data(), data) {
			return true
		}
	}
	return false
}
