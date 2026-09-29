package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

var ordinaryVectorScenarios = []string{
	"vectors/keys-z32-sign",
	"vectors/postcard-varints",
	"vectors/postcard-8bit",
	"vectors/endpoint-ticket-roundtrip",
	"vectors/pkarr-txt",
}

var customAddrScenarios = []string{
	"vectors/custom-addr-ticket-rust-to-go",
	"vectors/custom-addr-ticket-go-to-rust",
}

var ipTicketScenarios = []string{
	"vectors/ip-ticket-rust-to-go",
	"vectors/ip-ticket-go-to-rust",
}

const canonicalScenario = "vectors/postcard-varint-strictness"

var vectorScenarios = slices.Concat(ordinaryVectorScenarios, customAddrScenarios, ipTicketScenarios, []string{canonicalScenario})

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
	cells = append(cells, ipTicketCells(bin, want, version, digest, pid, peer, duration)...)
	cells = append(cells, canonicalVarintCell(bin, want, version, digest, peer))
	return cells
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

type ipTicketCorpus struct {
	Tickets []ipTicket `json:"ip_tickets"`
}

type ipTicket struct {
	Name    string   `json:"name"`
	Addrs   []string `json:"addrs"`
	Relay   string   `json:"relay"`
	Encoded string   `json:"encoded"`
	Bytes   string   `json:"bytes"`
}

type ipTicketDecodeRequest struct {
	Name    string `json:"name"`
	Encoded string `json:"encoded"`
}

type ipTicketDecodeResult struct {
	Name   string   `json:"name"`
	Error  *string  `json:"error"`
	Addrs  []string `json:"addrs"`
	Relays []string `json:"relays"`
	Bytes  string   `json:"bytes"`
}

// ipTicketCells checks endpoint tickets carrying IPv6 addresses in both
// directions. Rust to Go: go-iroh decodes each corpus ticket to the same
// addresses and relay. Go to Rust: Rust decodes each Go-encoded ticket to the
// same addresses and relay and re-encodes it to Go's bytes.
func ipTicketCells(bin string, corpus []byte, version, digest string, corpusPID int, peer string, duration int64) []Cell {
	var vectors ipTicketCorpus
	if err := json.Unmarshal(corpus, &vectors); err != nil || len(vectors.Tickets) == 0 {
		return vectorCellsFor(ipTicketScenarios, version, SetupError, "decode IP ticket vectors", digest, corpusPID, peer)
	}
	names := make([]string, len(vectors.Tickets))
	for i, v := range vectors.Tickets {
		names[i] = v.Name
	}

	var goRejected []string
	for _, v := range vectors.Tickets {
		ticket, err := endpointticket.Parse(v.Encoded)
		if err != nil || !ipTicketMatches(ticket.Addr(), v) {
			goRejected = append(goRejected, v.Name)
		}
	}
	rustToGo := Cell{
		Scenario: ipTicketScenarios[0], Iroh: version, Result: verdictFor(goRejected),
		Detail: fmt.Sprintf("Go decoded %d/%d Rust IP tickets to the same addresses", len(vectors.Tickets)-len(goRejected), len(vectors.Tickets)),
		Peer:   peer, PeerPID: corpusPID, PeerDigest: digest, DurationMS: duration,
		Evidence: map[string]any{"names": names, "mismatched": goRejected},
	}
	setup := func(detail string, pid int) []Cell {
		return []Cell{rustToGo, {Scenario: ipTicketScenarios[1], Iroh: version, Result: SetupError, Detail: detail, Peer: peer, PeerPID: pid, PeerDigest: digest}}
	}

	requests := make([]ipTicketDecodeRequest, len(vectors.Tickets))
	goBytes := make([]string, len(vectors.Tickets))
	for i, v := range vectors.Tickets {
		ticket, err := goIPTicket(v)
		if err != nil {
			return setup(fmt.Sprintf("build Go IP ticket %s: %v", v.Name, err), 0)
		}
		requests[i] = ipTicketDecodeRequest{Name: v.Name, Encoded: ticket.String()}
		goBytes[i] = fmt.Sprintf("%x", ticket.EncodeBytes())
	}
	input, err := json.Marshal(requests)
	if err != nil {
		return setup("encode Go IP tickets", 0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "ip-ticket-decode")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return setup(fmt.Sprintf("start Rust IP ticket decoder: %v", err), 0)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		return setup(fmt.Sprintf("Rust IP ticket decoder: %v: %s", err, stderr.String()), pid)
	}
	var results []ipTicketDecodeResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil || len(results) != len(requests) {
		return setup("decode Rust IP ticket results", pid)
	}
	var rustRejected []string
	rustErrors := map[string]string{}
	for i, r := range results {
		v := vectors.Tickets[i]
		switch {
		case r.Error != nil:
			rustErrors[v.Name] = *r.Error
			rustRejected = append(rustRejected, v.Name)
		case r.Bytes != goBytes[i] || !slices.Equal(r.Addrs, slices.Sorted(slices.Values(v.Addrs))) || !slices.Equal(r.Relays, wantRelays(v)):
			rustRejected = append(rustRejected, v.Name)
		}
	}
	goToRust := Cell{
		Scenario: ipTicketScenarios[1], Iroh: version, Result: verdictFor(rustRejected),
		Detail: fmt.Sprintf("Rust decoded %d/%d Go IP tickets to the same addresses and bytes", len(results)-len(rustRejected), len(results)),
		Peer:   peer, PeerPID: pid, PeerDigest: digest, DurationMS: time.Since(start).Milliseconds(),
		Evidence: map[string]any{"names": names, "mismatched": rustRejected, "errors": rustErrors},
	}
	return []Cell{rustToGo, goToRust}
}

func verdictFor(mismatched []string) Verdict {
	if len(mismatched) == 0 {
		return Pass
	}
	return Fail
}

func wantRelays(v ipTicket) []string {
	if v.Relay == "" {
		return []string{}
	}
	return []string{v.Relay}
}

func goIPTicket(v ipTicket) (endpointticket.Ticket, error) {
	var seed [key.SeedSize]byte
	for i := range seed {
		seed[i] = 0x2a
	}
	addr := netaddr.NewEndpointAddr(key.NewSecretKey(seed).Public().EndpointID())
	for _, s := range v.Addrs {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return endpointticket.Ticket{}, err
		}
		addr = addr.WithIP(ap)
	}
	if v.Relay != "" {
		u, err := netaddr.ParseRelayURL(v.Relay)
		if err != nil {
			return endpointticket.Ticket{}, err
		}
		addr = addr.WithRelayURL(u)
	}
	return endpointticket.New(addr), nil
}

func ipTicketMatches(addr netaddr.EndpointAddr, v ipTicket) bool {
	addrs := []string{}
	for _, ap := range addr.IPAddrs() {
		addrs = append(addrs, ap.String())
	}
	relays := []string{}
	for _, u := range addr.RelayURLs() {
		relays = append(relays, u.String())
	}
	return slices.Equal(slices.Sorted(slices.Values(addrs)), slices.Sorted(slices.Values(v.Addrs))) && slices.Equal(relays, wantRelays(v))
}
