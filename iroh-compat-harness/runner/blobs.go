package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
)

// blobsScenarios maps each request the Rust driver's blobs-get command makes
// to the scenario that reports it.
var blobsScenarios = map[string]string{
	"sendme-all-last-chunk": "blobs/rust-get-sendme",
	"per-child":             "blobs/rust-get-per-child",
}

var blobsScenarioOrder = []string{"sendme-all-last-chunk", "per-child"}

// blobSizes must match BLOB_SIZES in the Rust driver.
var blobSizes = []uint64{0, 1024, 16384, 17408, 100_000}

// RunBlobs serves a hash sequence of blobSizes blobs from a go-iroh provider
// and has the Rust driver fetch it with iroh-blobs' get client.
func RunBlobs(bin, version, digest string) []Cell {
	peer := "rust-driver@" + digest
	cells := func(result Verdict, detail string, pid int) []Cell {
		out := make([]Cell, len(blobsScenarioOrder))
		for i, name := range blobsScenarioOrder {
			out[i] = Cell{Scenario: blobsScenarios[name], Iroh: version, Result: result, Detail: detail, Peer: peer, PeerPID: pid, PeerDigest: digest}
		}
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	store, err := blobs.NewMemStore()
	if err != nil {
		return cells(SetupError, fmt.Sprintf("create Go blob store: %v", err), 0)
	}
	var hashes []blobs.Hash
	for _, size := range blobSizes {
		h, err := store.Add(baoData(size))
		if err != nil {
			return cells(SetupError, fmt.Sprintf("add Go blob: %v", err), 0)
		}
		hashes = append(hashes, h)
	}
	root, err := store.Add(blobs.NewHashSequence(hashes).Bytes())
	if err != nil {
		return cells(SetupError, fmt.Sprintf("add Go hash sequence: %v", err), 0)
	}

	ep, err := iroh.Bind(ctx, iroh.WithALPNs(blobs.ALPN), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), irohRelayDisabled())
	if err != nil {
		return cells(SetupError, fmt.Sprintf("bind Go blobs endpoint: %v", err), 0)
	}
	handler := blobsHandler{store: store}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{blobs.ALPN: handler}, nil)
	if err != nil {
		return cells(SetupError, fmt.Sprintf("start Go blobs router: %v", err), 0)
	}
	defer router.Shutdown(context.Background())
	cmd := exec.CommandContext(ctx, bin, "blobs-get", ep.ID().String(), ep.LocalAddr().String(), root.String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return cells(SetupError, fmt.Sprintf("start Rust blobs client: %v", err), 0)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		return cells(SetupError, fmt.Sprintf("Rust blobs client: %v: %s", err, stderr.String()), pid)
	}
	duration := time.Since(start).Milliseconds()
	var results []struct {
		Name  string  `json:"name"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil || len(results) != len(blobsScenarioOrder) {
		return cells(SetupError, fmt.Sprintf("decode Rust blobs results: %v: %s", err, stdout.String()), pid)
	}
	out := make([]Cell, len(results))
	for i, r := range results {
		scenario, ok := blobsScenarios[r.Name]
		if !ok || r.Name != blobsScenarioOrder[i] {
			return cells(SetupError, "unexpected Rust blobs result "+r.Name, pid)
		}
		out[i] = Cell{Scenario: scenario, Iroh: version, Result: Pass, Detail: "iroh-blobs verified every blob the Go provider sent", Peer: peer, PeerPID: pid, PeerDigest: digest, DurationMS: duration}
		if r.Error != nil {
			out[i].Result, out[i].Detail = Fail, "iroh-blobs rejected the Go provider's response: "+*r.Error
		}
	}
	return out
}

type blobsHandler struct {
	store blobs.Store
}

func (h blobsHandler) Accept(ctx context.Context, conn *iroh.Conn) error {
	err := blobs.ServeBlobStreams(ctx, func(ctx context.Context) (blobs.BidiStream, error) {
		return conn.AcceptStream(ctx)
	}, h.store)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
