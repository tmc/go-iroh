// Gobulk is a bulk-transfer benchmark driver shaped to match the upstream
// iroh bench binary (iroh/bench/src/bin/bulk.rs) in both wire protocol and
// timer coverage.
//
// It runs one process containing both endpoints, so client and server share a
// single Go scheduler, and it times a fixed-size transfer from connect
// initiation through the last byte observed by the receiver. The Go testing
// benchmarks time a b.N write loop on an already-open stream and stop the
// timer before the receiver drains, which is not the same measurement; see
// design/crossimpl-surface-prereg.md.
//
// The wire protocol is the one in iroh/bench/src/iroh.rs: the client opens a
// bidirectional stream, sends the upload, finishes its send side, and reads
// the server's response to EOF; the response length is the server's
// configured download size and is not negotiated. The ALPN is the upstream
// one, so gobulk's client and server interoperate with the Rust bench across
// arms.
//
// Usage:
//
//	gobulk [flags]
//
// The flags are:
//
//	-streams n
//		Number of concurrent streams (default 1).
//	-download-size bytes
//		Bytes the server sends on each stream (default 64 MiB).
//	-upload-size bytes
//		Bytes the client sends on each stream (default 0).
//	-mode both|client|server
//		Run both endpoints in this process (default), or only one for
//		cross-arm calibration against the Rust bench.
//	-addr host:port
//		Server address to dial in client mode.
//	-node id
//		Server node ID to dial in client mode.
//	-timeout d
//		Overall deadline (default 5m).
//	-json
//		Emit one JSON object instead of the text summary.
//	-diag path
//		Write a JSON snapshot of diagnostic counters at transfer end.
//
// Parallelism is set by GOMAXPROCS, which is the swept axis on the Go side.
// Gobulk performs no relay setup: endpoints bind to 127.0.0.1 and transfers
// are direct-path.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// alpn matches iroh/bench/src/iroh.rs:18 so the arms can be crossed.
const alpn = "n0/iroh-bench/0"

var (
	streams      = flag.Int("streams", 1, "number of concurrent streams")
	downloadSize = flag.Int64("download-size", 64<<20, "bytes the server sends on each stream")
	uploadSize   = flag.Int64("upload-size", 0, "bytes the client sends on each stream")
	mode         = flag.String("mode", "both", "both, client, or server")
	addrFlag     = flag.String("addr", "", "server address to dial in client mode")
	nodeFlag     = flag.String("node", "", "server node ID to dial in client mode")
	timeout      = flag.Duration("timeout", 5*time.Minute, "overall deadline")
	jsonOut      = flag.Bool("json", false, "emit a single JSON object")
	diagPath     = flag.String("diag", "", "path to write diagnostic counters snapshot at transfer end")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("gobulk: ")
	flag.Parse()
	if *streams < 1 {
		log.Fatal("streams must be at least 1")
	}
	if *downloadSize < 0 || *uploadSize < 0 {
		log.Fatal("transfer sizes must not be negative")
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

type result struct {
	Streams      int     `json:"streams"`
	DownloadSize int64   `json:"download_size"`
	UploadSize   int64   `json:"upload_size"`
	TotalBytes   int64   `json:"total_bytes"`
	GOMAXPROCS   int     `json:"gomaxprocs"`
	ConnectSec   float64 `json:"connect_seconds"`
	ElapsedSec   float64 `json:"elapsed_seconds"`
	MiBPerSec    float64 `json:"mib_per_sec"`
	// DownloadSec covers the receive alone, from the moment the send side is
	// finished to the last byte read, so it lines up with the download window
	// the Rust bench reports (iroh/bench/src/iroh.rs drain_stream) rather than
	// with the whole-transfer window above.
	DownloadSec       float64 `json:"download_seconds"`
	DownloadMiBPerSec float64 `json:"download_mib_per_sec"`
}

// DiagSnapshot holds a complete snapshot of diagnostic counters and config.
type DiagSnapshot struct {
	Mode         string          `json:"mode"`
	GOMAXPROCS   int             `json:"gomaxprocs"`
	Streams      int             `json:"streams"`
	DownloadSize int64           `json:"download_size"`
	UploadSize   int64           `json:"upload_size"`
	Roles        []RoleDiagStats `json:"roles"`
}

// PathDiagSnapshot formats PathInfo with clean JSON serialization.
type PathDiagSnapshot struct {
	ID               uint32        `json:"id"`
	Validated        bool          `json:"validated"`
	Addr             string        `json:"addr,omitempty"`
	RTT              time.Duration `json:"rtt,omitempty"`
	BytesInFlight    uint64        `json:"bytes_in_flight,omitempty"`
	BytesSent        uint64        `json:"bytes_sent,omitempty"`
	BytesReceived    uint64        `json:"bytes_received,omitempty"`
	CongestionWindow uint64        `json:"congestion_window,omitempty"`
	LostPackets      uint64        `json:"lost_packets,omitempty"`
	LostBytes        uint64        `json:"lost_bytes,omitempty"`
	Selected         bool          `json:"selected"`
	Relayed          bool          `json:"relayed"`
}

// RoleDiagStats holds counters for one role (client or server).
type RoleDiagStats struct {
	Role            string             `json:"role"`
	Stats           iroh.ConnStats     `json:"conn_stats"`
	Paths           []PathDiagSnapshot `json:"paths"`
	MaxDatagramSize int                `json:"max_datagram_size,omitempty"`
	Used0RTT        bool               `json:"used_0rtt"`
	Multipath       bool               `json:"multipath"`
	KeyExchange     string             `json:"key_exchange"`
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	switch *mode {
	case "both":
		return runBoth(ctx)
	case "server":
		return runServer(ctx)
	case "client":
		return runClient(ctx)
	}
	return fmt.Errorf("unknown mode %q", *mode)
}

func transportConfig() iroh.Option {
	return iroh.WithTransportConfig(&iroh.QUICTransportConfig{
		InitialPacketSize:  1200,
		MaxIncomingStreams: int64(*streams) + 8,
	})
}

func bindServer(ctx context.Context) (*iroh.Endpoint, error) {
	srvKey, err := key.GenerateSecretKey()
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(srvKey), iroh.WithALPNs(alpn), transportConfig(),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		return nil, fmt.Errorf("bind server: %w", err)
	}
	return ep, nil
}

func runBoth(ctx context.Context) error {
	srvEP, err := bindServer(ctx)
	if err != nil {
		return err
	}
	defer srvEP.Shutdown(context.Background())

	clientEP, err := iroh.Bind(ctx, transportConfig(),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		return fmt.Errorf("bind client: %w", err)
	}
	defer clientEP.Shutdown(context.Background())

	type serverOutcome struct {
		diag RoleDiagStats
		err  error
	}
	serve := make(chan serverOutcome, 1)
	go func() {
		diag, srvErr := serveOne(ctx, srvEP)
		serve <- serverOutcome{diag: diag, err: srvErr}
	}()

	addr := netaddr.NewEndpointAddr(srvEP.ID()).WithIP(srvEP.LocalAddr())
	res, clientDiag, err := transfer(ctx, clientEP, addr)
	if err != nil {
		return err
	}
	sRes := <-serve
	if sRes.err != nil && !errors.Is(sRes.err, context.Canceled) {
		return fmt.Errorf("server: %w", sRes.err)
	}

	if *diagPath != "" {
		snap := DiagSnapshot{
			Mode:         "both",
			GOMAXPROCS:   runtime.GOMAXPROCS(0),
			Streams:      *streams,
			DownloadSize: *downloadSize,
			UploadSize:   *uploadSize,
			Roles:        []RoleDiagStats{clientDiag, sRes.diag},
		}
		if err := writeDiag(snap, *diagPath); err != nil {
			return fmt.Errorf("write diag: %w", err)
		}
	}

	return report(res)
}

func runServer(ctx context.Context) error {
	ep, err := bindServer(ctx)
	if err != nil {
		return err
	}
	defer ep.Shutdown(context.Background())
	fmt.Printf("node %s\naddr %s\n", ep.ID(), ep.LocalAddr())
	os.Stdout.Sync()
	diag, err := serveOne(ctx, ep)
	if err != nil {
		return err
	}
	if *diagPath != "" {
		snap := DiagSnapshot{
			Mode:         "server",
			GOMAXPROCS:   runtime.GOMAXPROCS(0),
			Streams:      *streams,
			DownloadSize: *downloadSize,
			UploadSize:   *uploadSize,
			Roles:        []RoleDiagStats{diag},
		}
		if err := writeDiag(snap, *diagPath); err != nil {
			return fmt.Errorf("write diag: %w", err)
		}
	}
	return nil
}

func runClient(ctx context.Context) error {
	if *addrFlag == "" || *nodeFlag == "" {
		return errors.New("client mode needs -addr and -node")
	}
	id, err := key.ParseEndpointID(*nodeFlag)
	if err != nil {
		return fmt.Errorf("parse node: %w", err)
	}
	ap, err := netip.ParseAddrPort(*addrFlag)
	if err != nil {
		return fmt.Errorf("parse addr: %w", err)
	}
	ep, err := iroh.Bind(ctx, transportConfig(),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		return fmt.Errorf("bind client: %w", err)
	}
	defer ep.Shutdown(context.Background())
	res, clientDiag, err := transfer(ctx, ep, netaddr.NewEndpointAddr(id).WithIP(ap))
	if err != nil {
		return err
	}
	if *diagPath != "" {
		snap := DiagSnapshot{
			Mode:         "client",
			GOMAXPROCS:   runtime.GOMAXPROCS(0),
			Streams:      *streams,
			DownloadSize: *downloadSize,
			UploadSize:   *uploadSize,
			Roles:        []RoleDiagStats{clientDiag},
		}
		if err := writeDiag(snap, *diagPath); err != nil {
			return fmt.Errorf("write diag: %w", err)
		}
	}
	return report(res)
}

func writeDiag(snap DiagSnapshot, path string) error {
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func snapshotRoleStats(role string, conn *iroh.Conn) RoleDiagStats {
	if conn == nil {
		return RoleDiagStats{Role: role}
	}
	maxDgram, _ := conn.MaxDatagramSize()
	rawPaths := conn.Paths()
	paths := make([]PathDiagSnapshot, len(rawPaths))
	for i, p := range rawPaths {
		addrStr := ""
		if p.HasAddr && p.Addr != nil {
			addrStr = p.Addr.String()
		}
		paths[i] = PathDiagSnapshot{
			ID:               p.ID,
			Validated:        p.Validated,
			Addr:             addrStr,
			RTT:              p.RTT,
			BytesInFlight:    p.BytesInFlight,
			BytesSent:        p.BytesSent,
			BytesReceived:    p.BytesReceived,
			CongestionWindow: p.CongestionWindow,
			LostPackets:      p.LostPackets,
			LostBytes:        p.LostBytes,
			Selected:         p.Selected,
			Relayed:          p.Relayed,
		}
	}
	return RoleDiagStats{
		Role:            role,
		Stats:           conn.Stats(),
		Paths:           paths,
		MaxDatagramSize: maxDgram,
		Used0RTT:        conn.Used0RTT(),
		Multipath:       conn.MultipathNegotiated(),
		KeyExchange:     conn.KeyExchangeGroup(),
	}
}

// transfer opens the timed window at connect initiation and closes it once
// every stream has been drained to EOF, matching bulk.rs.
func transfer(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr) (result, RoleDiagStats, error) {
	start := time.Now()
	conn, err := ep.Connect(ctx, addr, alpn)
	if err != nil {
		return result{}, RoleDiagStats{}, fmt.Errorf("connect: %w", err)
	}
	defer conn.CloseWithError(0, "")
	connected := time.Now()

	type outcome struct {
		n          int64
		begin, end time.Time
		err        error
	}
	done := make(chan outcome, *streams)
	for i := 0; i < *streams; i++ {
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return result{}, RoleDiagStats{}, fmt.Errorf("open stream: %w", err)
		}
		go func(s *iroh.Stream) {
			n, begin, end, err := clientStream(s)
			done <- outcome{n: n, begin: begin, end: end, err: err}
		}(s)
	}
	var read int64
	var firstErr error
	var first, last time.Time
	for i := 0; i < *streams; i++ {
		o := <-done
		read += o.n
		if o.err != nil && firstErr == nil {
			firstErr = o.err
		}
		if first.IsZero() || o.begin.Before(first) {
			first = o.begin
		}
		if o.end.After(last) {
			last = o.end
		}
	}
	elapsed := time.Since(start)
	download := last.Sub(first)
	diag := snapshotRoleStats("client", conn)

	if firstErr != nil {
		return result{}, diag, firstErr
	}
	if want := *downloadSize * int64(*streams); read != want {
		return result{}, diag, fmt.Errorf("received %d bytes, want %d", read, want)
	}
	return result{
		Streams:      *streams,
		DownloadSize: *downloadSize,
		UploadSize:   *uploadSize,
		TotalBytes:   read,
		GOMAXPROCS:   runtime.GOMAXPROCS(0),
		ConnectSec:   connected.Sub(start).Seconds(),
		ElapsedSec:   elapsed.Seconds(),
		MiBPerSec:    float64(read) / (1 << 20) / elapsed.Seconds(),

		DownloadSec:       download.Seconds(),
		DownloadMiBPerSec: float64(read) / (1 << 20) / download.Seconds(),
	}, diag, nil
}

// clientStream sends the upload, finishes the send side, and drains the
// response to EOF. The returned times bound the download alone.
func clientStream(s *iroh.Stream) (n int64, begin, end time.Time, err error) {
	if err := sendData(s, *uploadSize); err != nil {
		return 0, begin, end, fmt.Errorf("upload: %w", err)
	}
	if err := s.Close(); err != nil {
		return 0, begin, end, fmt.Errorf("finish send side: %w", err)
	}
	begin = time.Now()
	n, err = io.Copy(io.Discard, s)
	end = time.Now()
	if err != nil {
		return n, begin, end, fmt.Errorf("download: %w", err)
	}
	return n, begin, end, nil
}

// serveOne accepts one connection and answers every stream on it, then
// reports the server's own view of the transfer. Two independent views of one
// physical transfer is what the endpoint-agreement check compares: an
// interaction statistic cannot see a timer-coverage error attached to one
// role, because such an error lands in a main effect.
func serveOne(ctx context.Context, ep *iroh.Endpoint) (RoleDiagStats, error) {
	conn, err := ep.Accept(ctx)
	if err != nil {
		return RoleDiagStats{}, err
	}
	// The connection is not closed here: the client is still draining when the
	// last server write returns, and closing would abort its read.
	type sent struct {
		begin, end time.Time
		err        error
	}
	errs := make(chan sent, *streams)
	for i := 0; i < *streams; i++ {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return snapshotRoleStats("server", conn), err
		}
		go func(s *iroh.Stream) {
			begin, end, err := serverStream(s)
			errs <- sent{begin: begin, end: end, err: err}
		}(s)
	}
	var first, last time.Time
	var streamErr error
	for i := 0; i < *streams; i++ {
		o := <-errs
		if o.err != nil && streamErr == nil {
			streamErr = o.err
		}
		if o.begin.IsZero() || o.end.IsZero() {
			continue
		}
		if first.IsZero() || o.begin.Before(first) {
			first = o.begin
		}
		if o.end.After(last) {
			last = o.end
		}
	}
	bytes := *downloadSize * int64(*streams)
	secs := last.Sub(first).Seconds()
	view := struct {
		Bytes     int64   `json:"server_bytes"`
		Seconds   float64 `json:"server_send_seconds"`
		MiBPerSec float64 `json:"server_mib_per_sec"`
	}{bytes, secs, float64(bytes) / (1 << 20) / secs}

	diag := snapshotRoleStats("server", conn)

	// The view is reported even when a stream errored on teardown, since the
	// send window is already measured by then and a withheld view would look
	// exactly like a server that never sent.
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(view); err != nil {
			return diag, err
		}
	} else {
		fmt.Printf("server-send %.6fs server-throughput %.1f MiB/s\n", view.Seconds, view.MiBPerSec)
	}
	return diag, streamErr
}

// serverStream drains the upload, then sends the configured download size.
// The returned times bound the send alone, so the server's window matches the
// download window the client reports.
func serverStream(s *iroh.Stream) (begin, end time.Time, err error) {
	if _, err := io.Copy(io.Discard, s); err != nil {
		return begin, end, fmt.Errorf("drain upload: %w", err)
	}
	begin = time.Now()
	if err := sendData(s, *downloadSize); err != nil {
		return begin, end, fmt.Errorf("send download: %w", err)
	}
	end = time.Now()
	// The peer may tear the connection down as soon as it has the last byte,
	// which can leave Close waiting on a flush that will never be
	// acknowledged. The send window is already bounded, so a stuck Close must
	// not hold the report.
	s.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = s.Close()
	return begin, end, err
}

func sendData(s *iroh.Stream, size int64) error {
	buf := make([]byte, 64<<10)
	for size > 0 {
		n := int64(len(buf))
		if n > size {
			n = size
		}
		if _, err := s.Write(buf[:n]); err != nil {
			return err
		}
		size -= n
	}
	return nil
}

func report(res result) error {
	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(res)
	}
	fmt.Printf("streams %d download-size %d gomaxprocs %d\n", res.Streams, res.DownloadSize, res.GOMAXPROCS)
	fmt.Printf("connect %.6fs elapsed %.6fs throughput %.1f MiB/s\n", res.ConnectSec, res.ElapsedSec, res.MiBPerSec)
	fmt.Printf("download %.6fs download-throughput %.1f MiB/s\n", res.DownloadSec, res.DownloadMiBPerSec)
	return nil
}
