package runner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

const doctorALPN = "n0/doctor/1"

var doctorConnectLine = regexp.MustCompile(`iroh-doctor connect ([0-9a-f]{64})(?:.*?--remote-endpoint ['\"]?([^'\" ]+))`)

func RunDoctorEcho(bin, version, digest string) []Cell {
	return []Cell{
		runRustClientGoServer(bin, version, digest),
		runGoClientRustServer(bin, version, digest),
		runDoctorNegative(bin, version, digest, "handshake/alpn-mismatch", true),
		runDoctorNegative(bin, version, digest, "handshake/wrong-endpoint-id", false),
	}
}

func runDoctorNegative(bin, version, digest, scenario string, wrongALPN bool) (cell Cell) {
	cell = Cell{Scenario: scenario, Iroh: version, Peer: "iroh-doctor@" + digest, PeerDigest: digest}
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "accept", "--secret-key", strings.Repeat("2a", 32), "--size", "1", "--iterations", "1", "--disable-address-lookup", "--socket-addr", "127.0.0.1:0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("Rust peer stdout: %v", err))
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("Rust peer stderr: %v", err))
	}
	if err := cmd.Start(); err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("start Rust peer: %v", err))
	}
	cell.PeerPID = cmd.Process.Pid
	var output lockedBuffer
	ready := make(chan doctorReady, 1)
	var scans sync.WaitGroup
	scans.Add(2)
	go scanDoctor(stdout, &output, ready, &scans)
	go scanDoctor(stderr, &output, ready, &scans)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		scans.Wait()
	}()

	var r doctorReady
	select {
	case r = <-ready:
	case <-ctx.Done():
		return finishCell(cell, Fail, "Rust server readiness: "+ctx.Err().Error())
	}
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), irohRelayDisabled())
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("bind Go client: %v", err))
	}
	defer ep.Shutdown(context.Background())
	id := r.id
	alpn := doctorALPN
	if wrongALPN {
		alpn = "n0/not-doctor/1"
	} else {
		other := key.NewSecretKey([key.SeedSize]byte{1})
		id = other.Public().EndpointID()
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	conn, err := ep.Connect(dialCtx, netaddr.NewEndpointAddr(id).WithIP(r.addr), alpn)
	if err == nil {
		_ = conn.Close()
		return finishCell(cell, Fail, "negative dial unexpectedly connected")
	}
	return finishCell(cell, Pass, "dial rejected cleanly: "+err.Error())
}

func runRustClientGoServer(bin, version, digest string) (cell Cell) {
	cell = Cell{Scenario: "handshake/rust-client-go-server", Iroh: version, Peer: "iroh-doctor@" + digest, PeerDigest: digest}
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	ep, err := iroh.Bind(ctx, iroh.WithALPNs(doctorALPN), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), irohRelayDisabled())
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("bind Go server: %v", err))
	}
	defer ep.Shutdown(ctx)

	cmd := exec.CommandContext(ctx, bin, "connect", ep.ID().String(), "--remote-endpoint", ep.LocalAddr().String(), "--disable-address-lookup")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("start Rust peer: %v", err))
	}
	cell.PeerPID = cmd.Process.Pid
	conn, err := ep.Accept(ctx)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return finishCell(cell, Fail, fmt.Sprintf("accept Rust peer: %v: %s", err, out.String()))
	}
	n, err := runDoctorActive(ctx, conn, 1024)
	_ = conn.CloseWithError(0, "done")
	werr := cmd.Wait()
	if err != nil || n != 3 || werr != nil {
		return finishCell(cell, Fail, fmt.Sprintf("doctor exchange streams=%d serve=%v peer=%v: %s", n, err, werr, out.String()))
	}
	return finishCell(cell, Pass, "three doctor send/receive/echo streams completed")
}

func runGoClientRustServer(bin, version, digest string) (cell Cell) {
	cell = Cell{Scenario: "handshake/go-client-rust-server", Iroh: version, Peer: "iroh-doctor@" + digest, PeerDigest: digest}
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "accept", "--secret-key", strings.Repeat("2a", 32), "--size", "1024", "--iterations", "1", "--disable-address-lookup", "--socket-addr", "127.0.0.1:0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("Rust peer stdout: %v", err))
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("Rust peer stderr: %v", err))
	}
	if err := cmd.Start(); err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("start Rust peer: %v", err))
	}
	cell.PeerPID = cmd.Process.Pid
	var output lockedBuffer
	ready := make(chan doctorReady, 1)
	var scans sync.WaitGroup
	scans.Add(2)
	go scanDoctor(stdout, &output, ready, &scans)
	go scanDoctor(stderr, &output, ready, &scans)

	var r doctorReady
	select {
	case r = <-ready:
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		scans.Wait()
		return finishCell(cell, Fail, "Rust server readiness: "+ctx.Err().Error()+": "+output.String())
	}

	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), irohRelayDisabled())
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return finishCell(cell, SetupError, fmt.Sprintf("bind Go client: %v", err))
	}
	defer ep.Shutdown(ctx)
	addr := netaddr.NewEndpointAddr(r.id).WithIP(r.addr)
	conn, err := ep.Connect(ctx, addr, doctorALPN)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		scans.Wait()
		return finishCell(cell, Fail, fmt.Sprintf("dial Rust peer: %v: %s", err, output.String()))
	}
	n, serveErr := serveDoctor(ctx, conn)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	scans.Wait()
	if serveErr != nil || n != 3 {
		return finishCell(cell, Fail, fmt.Sprintf("doctor exchange streams=%d serve=%v: %s", n, serveErr, output.String()))
	}
	return finishCell(cell, Pass, "three doctor send/receive/echo streams completed")
}

// irohRelayDisabled is kept here so the harness explicitly chooses loopback
// direct paths and never mistakes public relay availability for local parity.
func irohRelayDisabled() iroh.Option { return iroh.WithRelayMode(relay.ModeDisabled()) }

func serveDoctor(ctx context.Context, conn *iroh.Conn) (int, error) {
	count := 0
	for count < 3 {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return count, err
		}
		if err := handleDoctorStream(stream); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func runDoctorActive(ctx context.Context, conn *iroh.Conn, size uint64) (int, error) {
	tests := []struct {
		kind uint64
		send uint64
		recv uint64
	}{
		{kind: 1, send: size},
		{kind: 2, recv: size},
		{kind: 0, send: size, recv: size},
	}
	for i, test := range tests {
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return i, fmt.Errorf("open doctor stream: %w", err)
		}
		header := appendLEB(nil, test.kind)
		header = appendLEB(header, size)
		if test.kind == 2 {
			header = appendLEB(header, 1024*1024)
		}
		header = append(header, make([]byte, 16-len(header))...)
		if _, err := stream.Write(header); err != nil {
			return i, fmt.Errorf("write doctor request: %w", err)
		}
		if test.send != 0 {
			if _, err := io.CopyN(stream, zeroReader{}, int64(test.send)); err != nil {
				return i, fmt.Errorf("write doctor payload: %w", err)
			}
		}
		if err := stream.Close(); err != nil {
			return i, fmt.Errorf("finish doctor request: %w", err)
		}
		got, err := io.Copy(io.Discard, stream)
		if err != nil {
			return i, fmt.Errorf("read doctor response: %w", err)
		}
		if got != int64(test.recv) {
			return i, fmt.Errorf("doctor response bytes=%d, want %d", got, test.recv)
		}
	}
	return len(tests), nil
}

func appendLEB(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func handleDoctorStream(stream *iroh.Stream) error {
	header := make([]byte, 16)
	if _, err := io.ReadFull(stream, header); err != nil {
		return fmt.Errorf("read doctor request: %w", err)
	}
	kind, n, err := readLEB(header)
	if err != nil {
		return err
	}
	size, _, err := readLEB(header[n:])
	if err != nil {
		return err
	}
	switch kind {
	case 0: // Echo
		if _, err := io.CopyN(stream, stream, int64(size)); err != nil {
			return fmt.Errorf("echo %d bytes: %w", size, err)
		}
	case 1: // Drain
		if _, err := io.CopyN(io.Discard, stream, int64(size)); err != nil {
			return fmt.Errorf("drain %d bytes: %w", size, err)
		}
	case 2: // Send
		if _, err := io.CopyN(stream, zeroReader{}, int64(size)); err != nil {
			return fmt.Errorf("send %d bytes: %w", size, err)
		}
	default:
		return fmt.Errorf("unknown doctor request %d", kind)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("finish doctor response: %w", err)
	}
	return nil
}

func readLEB(b []byte) (uint64, int, error) {
	var v uint64
	for i, c := range b {
		if i == 10 || i == 9 && c > 1 {
			return 0, 0, fmt.Errorf("doctor postcard integer overflows uint64")
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, io.ErrUnexpectedEOF
}

type doctorReady struct {
	id   key.EndpointID
	addr netip.AddrPort
}

func scanDoctor(r io.Reader, out *lockedBuffer, ready chan<- doctorReady, wg *sync.WaitGroup) {
	defer wg.Done()
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		out.WriteLine(line)
		m := doctorConnectLine.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		id, err := key.ParseEndpointID(m[1])
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddrPort(m[2])
		if err != nil {
			continue
		}
		select {
		case ready <- doctorReady{id: id, addr: addr}:
		default:
		}
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) WriteLine(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.b.WriteString(s)
	b.b.WriteByte('\n')
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func finishCell(c Cell, verdict Verdict, detail string) Cell {
	c.Result = verdict
	c.Detail = detail
	return c
}
