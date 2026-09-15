package iroh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/sys/unix"
)

type layerLadderSample struct {
	Rung           string                        `json:"rung"`
	Lang           string                        `json:"lang"`
	Sample         int                           `json:"sample"`
	PID            int                           `json:"pid,omitempty"`
	Bytes          int64                         `json:"bytes"`
	Messages       int64                         `json:"messages,omitempty"`
	DurationNS     int64                         `json:"duration_ns"`
	CPUUserNS      int64                         `json:"cpu_user_ns,omitempty"`
	CPUSysNS       int64                         `json:"cpu_sys_ns,omitempty"`
	OpDurationNS   []int64                       `json:"op_duration_ns,omitempty"`
	FlowBytes      []int64                       `json:"flow_bytes,omitempty"`
	FlowDurationNS []int64                       `json:"flow_duration_ns,omitempty"`
	Transport      *layerLadderTransportCounters `json:"transport,omitempty"`
}

type layerLadderTransportCounters struct {
	QUICPacketsSent      uint64 `json:"quic_packets_sent"`
	QUICBytesSent        uint64 `json:"quic_bytes_sent"`
	StreamFramesSent     uint64 `json:"stream_frames_sent,omitempty"`
	StreamBytesSent      uint64 `json:"stream_bytes_sent,omitempty"`
	ACKFramesSent        uint64 `json:"ack_frames_sent,omitempty"`
	ACKOnlyPacketsSent   uint64 `json:"ack_only_packets_sent,omitempty"`
	StreamActivations    uint64 `json:"stream_activations,omitempty"`
	SendLoopRuns         uint64 `json:"send_loop_runs,omitempty"`
	UDPDatagramsSent     uint64 `json:"udp_datagrams_sent,omitempty"`
	UDPBytesSent         uint64 `json:"udp_bytes_sent,omitempty"`
	UDPSendSyscalls      uint64 `json:"udp_send_syscalls,omitempty"`
	UDPGSOSyscalls       uint64 `json:"udp_gso_syscalls,omitempty"`
	UDPGSOSegments       uint64 `json:"udp_gso_segments,omitempty"`
	CorkTimerActivations uint64 `json:"cork_timer_activations,omitempty"`
	UDPReceiveSyscalls   uint64 `json:"udp_receive_syscalls,omitempty"`
	UDPDatagramsReceived uint64 `json:"udp_datagrams_received,omitempty"`
	UDPGROReads          uint64 `json:"udp_gro_reads,omitempty"`
}

type benchmarkCPUTime struct {
	userNS int64
	sysNS  int64
}

func readBenchmarkCPUTime(b *testing.B) benchmarkCPUTime {
	b.Helper()
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		b.Fatalf("get process CPU time: %v", err)
	}
	return benchmarkCPUTime{
		userNS: usage.Utime.Sec*1e9 + int64(usage.Utime.Usec)*1e3,
		sysNS:  usage.Stime.Sec*1e9 + int64(usage.Stime.Usec)*1e3,
	}
}

// reportCPUPerOp reports process CPU time per op since start. Unlike ns/op it
// is insensitive to frequency scaling and to time spent blocked.
func reportCPUPerOp(b *testing.B, start benchmarkCPUTime) {
	end := readBenchmarkCPUTime(b)
	ns := (end.userNS - start.userNS) + (end.sysNS - start.sysNS)
	b.ReportMetric(float64(ns)/float64(b.N)/1e3, "cpu-µs/op")
}

func emitLayerLadderSample(b *testing.B, rung string, bytes int64) {
	emitLayerLadderSampleMetrics(b, rung, bytes, benchmarkCPUTime{-1, -1}, nil)
}

func emitLayerLadderSampleMetrics(b *testing.B, rung string, bytes int64, cpuStart benchmarkCPUTime, opDurationNS []int64) {
	emitLayerLadderSampleRecord(b, layerLadderSample{Rung: rung, Bytes: bytes, OpDurationNS: opDurationNS}, cpuStart)
}

func emitLayerLadderSampleRecord(b *testing.B, s layerLadderSample, cpuStart benchmarkCPUTime) {
	b.Helper()
	path := os.Getenv("IROH_LAYER_LADDER_JSONL")
	if path == "" {
		return
	}
	sample, err := strconv.Atoi(os.Getenv("IROH_LAYER_LADDER_SAMPLE"))
	if err != nil {
		b.Fatalf("parse IROH_LAYER_LADDER_SAMPLE: %v", err)
	}
	lang := os.Getenv("IROH_LAYER_LADDER_LANG")
	if lang == "" {
		lang = "go"
	}
	// The testing package may invoke a benchmark several times while choosing
	// b.N, so keep only the final calibrated invocation from this process.
	// Replacing this process's own warm-up is intended; replacing any other
	// record destroys a measurement, and the record already in the file says
	// which of the two this is.
	s.Lang = lang
	s.Sample = sample
	s.PID = os.Getpid()
	if err := checkLadderPathOwnership(path, s); err != nil {
		b.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		b.Fatalf("open layer-ladder JSONL: %v", err)
	}
	s.DurationNS = b.Elapsed().Nanoseconds()
	if cpuStart.userNS >= 0 {
		cpuEnd := readBenchmarkCPUTime(b)
		s.CPUUserNS = cpuEnd.userNS - cpuStart.userNS
		s.CPUSysNS = cpuEnd.sysNS - cpuStart.sysNS
	}
	err = json.NewEncoder(f).Encode(s)
	closeErr := f.Close()
	if err != nil {
		b.Fatalf("write layer-ladder JSONL: %v", err)
	}
	if closeErr != nil {
		b.Fatalf("close layer-ladder JSONL: %v", closeErr)
	}
}

// checkLadderPathOwnership reports an error when path already holds anything
// other than this process's own b.N warm-up for this cell and repetition, which
// is the only record O_TRUNC may destroy. Every other outcome -- another cell,
// another repetition, another process, a file this check cannot parse, a path it
// cannot read -- is an error, because the alternative is a fail-open that
// reports a destroyed measurement as a successful one.
func checkLadderPathOwnership(path string, s layerLadderSample) error {
	prev, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // first write to this path
	}
	if err != nil {
		return fmt.Errorf("read layer-ladder JSONL %s to check for an existing record: %w", path, err)
	}
	if len(prev) == 0 {
		return nil
	}
	var old layerLadderSample
	if err := json.Unmarshal(prev, &old); err != nil {
		return fmt.Errorf("layer-ladder JSONL %s holds %d bytes this check cannot parse (%v): "+
			"O_TRUNC would destroy it unexamined; remove the file to start a fresh run", path, len(prev), err)
	}
	if old.Rung != "" && old.Rung != s.Rung {
		return fmt.Errorf("layer-ladder JSONL %s already holds rung %q and this is %q: "+
			"one cell per path, or O_TRUNC destroys the other cell's sample", path, old.Rung, s.Rung)
	}
	if old.Rung == s.Rung && old.Sample != s.Sample {
		return fmt.Errorf("layer-ladder JSONL %s already holds sample %d of rung %q and this is sample %d: "+
			"the repetition must be part of the path, or O_TRUNC keeps only the last",
			path, old.Sample, s.Rung, s.Sample)
	}
	// Matching rung and sample still does not make the record ours: a second
	// process measuring the same cell writes an identical-looking one.
	if old.PID != s.PID {
		return fmt.Errorf("layer-ladder JSONL %s already holds a record from process %d and this is process %d: "+
			"only this process's own warm-up may be replaced; remove the file to start a fresh run",
			path, old.PID, s.PID)
	}
	return nil
}

func benchmarkConnPair(b *testing.B, alpn string) (client, server *Conn) {
	return benchmarkConnPairAddr(b, alpn, netip.MustParseAddr("127.0.0.1"))
}

func benchmarkConnPairAddr(b *testing.B, alpn string, ip netip.Addr) (client, server *Conn) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	b.Cleanup(cancel)

	srvKey, _ := key.GenerateSecretKey()
	transportConfig := WithTransportConfig(&QUICTransportConfig{InitialPacketSize: 1200, MaxIncomingStreams: 64})
	srvEP, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn), transportConfig,
		WithBindAddr(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { srvEP.Shutdown(context.Background()) })

	clientEP, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(ip, 0)), transportConfig)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { clientEP.Shutdown(context.Background()) })

	type accepted struct {
		conn *Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := srvEP.Accept(ctx)
		done <- accepted{conn: c, err: err}
	}()

	// A wildcard-bound endpoint reports an unspecified address, which is not
	// dialable; reach it on loopback at the port it bound.
	srvAddr := srvEP.LocalAddr()
	if srvAddr.Addr().IsUnspecified() {
		srvAddr = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), srvAddr.Port())
	}
	addr := netaddr.NewEndpointAddr(srvEP.ID()).WithIP(srvAddr)
	client, err = clientEP.Connect(ctx, addr, alpn)
	if err != nil {
		b.Fatalf("connect: %v", err)
	}

	res := <-done
	if res.err != nil {
		b.Fatalf("accept: %v", res.err)
	}
	b.Cleanup(func() {
		client.CloseWithError(0, "")
		res.conn.CloseWithError(0, "")
	})
	return client, res.conn
}

// benchmarkConnPairWildcard is benchmarkConnPair on the socket shape a real
// endpoint has. Every other benchmark here binds 127.0.0.1, which is the one
// configuration where the two receive loops in internal/socket do not make the
// same syscall: a loopback-bound socket has no packet info to collect, so the
// ordinary loop reads with recvfrom, while the UDP_GRO loop must read with
// recvmsg to get the segment size. A wildcard socket -- what [WithBindAddr]
// binds by default -- collects packet info, so both loops read with recvmsg
// and a comparison between them measures the receive strategy rather than the
// syscall. Measuring offloads on a loopback-bound socket has already once
// reported a datagram regression that no endpoint could observe.
func benchmarkConnPairWildcard(b *testing.B, alpn string) (client, server *Conn) {
	b.Helper()
	return benchmarkConnPairAddr(b, alpn, netip.IPv4Unspecified())
}

// BenchmarkConnDatagramPingPongWildcard is BenchmarkConnDatagramPingPong on that
// wildcard socket, so the receive path is the one an application runs.
func BenchmarkConnDatagramPingPongWildcard(b *testing.B) {
	client, server := benchmarkConnPairWildcard(b, "iroh-bench-datagram-ping-pong-wildcard/0")
	benchmarkDatagramPingPong(b, client, server)
}

type benchConnStats struct {
	packetsSent          uint64
	packetsReceived      uint64
	bytesSent            uint64
	streamFramesSent     uint64
	streamBytesSent      uint64
	ackFramesSent        uint64
	ackOnlyPacketsSent   uint64
	streamActivations    uint64
	sendLoopRuns         uint64
	udpDatagramsSent     uint64
	udpBytesSent         uint64
	udpSendSyscalls      uint64
	udpGSOSyscalls       uint64
	udpGSOSegments       uint64
	corkTimerActivations uint64
	udpReceiveSyscalls   uint64
	udpDatagramsReceived uint64
	udpGROReads          uint64
}

func snapshotConnStats(c *Conn) benchConnStats {
	s := c.qc.ConnectionStats()
	p := c.qc.PerformanceStats()
	u := socket.SnapshotPerformanceStats()
	return benchConnStats{
		packetsSent:          s.PacketsSent,
		packetsReceived:      s.PacketsReceived,
		bytesSent:            s.BytesSent,
		streamFramesSent:     p.StreamFramesSent,
		streamBytesSent:      p.StreamBytesSent,
		ackFramesSent:        p.ACKFramesSent,
		ackOnlyPacketsSent:   p.ACKOnlyPacketsSent,
		streamActivations:    p.StreamActivations,
		sendLoopRuns:         p.SendLoopRuns,
		udpDatagramsSent:     p.UDPDatagramsSent,
		udpBytesSent:         p.UDPBytesSent,
		udpSendSyscalls:      p.UDPSendSyscalls,
		udpGSOSyscalls:       p.UDPGSOSyscalls,
		udpGSOSegments:       p.UDPGSOSegments,
		corkTimerActivations: p.CorkTimerActivations,
		udpReceiveSyscalls:   u.UDPReceiveSyscalls,
		udpDatagramsReceived: u.UDPDatagramsReceived,
		udpGROReads:          u.UDPGROReads,
	}
}

func reportConnStats(b *testing.B, client, server *Conn, clientStart, serverStart benchConnStats) {
	b.Helper()
	if b.N == 0 {
		return
	}
	clientEnd := snapshotConnStats(client)
	serverEnd := snapshotConnStats(server)
	packetsSent := (clientEnd.packetsSent - clientStart.packetsSent) + (serverEnd.packetsSent - serverStart.packetsSent)
	packetsReceived := (clientEnd.packetsReceived - clientStart.packetsReceived) + (serverEnd.packetsReceived - serverStart.packetsReceived)
	bytesSent := (clientEnd.bytesSent - clientStart.bytesSent) + (serverEnd.bytesSent - serverStart.bytesSent)
	b.ReportMetric(float64(packetsSent)/float64(b.N), "qpackets-sent/op")
	b.ReportMetric(float64(packetsReceived)/float64(b.N), "qpackets-recv/op")
	b.ReportMetric(float64(bytesSent)/float64(b.N), "qbytes-sent/op")
}

func reportConnSenderStats(b *testing.B, sender *Conn, start benchConnStats) *layerLadderTransportCounters {
	b.Helper()
	if b.N == 0 {
		return nil
	}
	end := snapshotConnStats(sender)
	packets := end.packetsSent - start.packetsSent
	bytes := end.bytesSent - start.bytesSent
	b.ReportMetric(float64(packets)/float64(b.N), "qsender-packets/op")
	b.ReportMetric(float64(bytes)/float64(b.N), "qsender-bytes/op")
	return &layerLadderTransportCounters{
		QUICPacketsSent:      packets,
		QUICBytesSent:        bytes,
		StreamFramesSent:     end.streamFramesSent - start.streamFramesSent,
		StreamBytesSent:      end.streamBytesSent - start.streamBytesSent,
		ACKFramesSent:        end.ackFramesSent - start.ackFramesSent,
		ACKOnlyPacketsSent:   end.ackOnlyPacketsSent - start.ackOnlyPacketsSent,
		StreamActivations:    end.streamActivations - start.streamActivations,
		SendLoopRuns:         end.sendLoopRuns - start.sendLoopRuns,
		UDPDatagramsSent:     end.udpDatagramsSent - start.udpDatagramsSent,
		UDPBytesSent:         end.udpBytesSent - start.udpBytesSent,
		UDPSendSyscalls:      end.udpSendSyscalls - start.udpSendSyscalls,
		UDPGSOSyscalls:       end.udpGSOSyscalls - start.udpGSOSyscalls,
		UDPGSOSegments:       end.udpGSOSegments - start.udpGSOSegments,
		CorkTimerActivations: end.corkTimerActivations - start.corkTimerActivations,
		UDPReceiveSyscalls:   end.udpReceiveSyscalls - start.udpReceiveSyscalls,
		UDPDatagramsReceived: end.udpDatagramsReceived - start.udpDatagramsReceived,
		UDPGROReads:          end.udpGROReads - start.udpGROReads,
	}
}

func reportConnCipher(b *testing.B, c *Conn) {
	b.Helper()
	b.ReportMetric(float64(c.qc.ConnectionState().TLS.CipherSuite), "cipher-suite")
}

func benchmarkQUICConnPair(b *testing.B, alpn string) (client, server *quic.Conn) {
	return benchmarkQUICConnPairWithConfigAddr(b, alpn, &quic.Config{InitialPacketSize: 1200}, net.IPv4(127, 0, 0, 1))
}

func benchmarkQUICConnPairWithConfig(b *testing.B, alpn string, conf *quic.Config) (client, server *quic.Conn) {
	return benchmarkQUICConnPairWithConfigAddr(b, alpn, conf, net.IPv4(127, 0, 0, 1))
}

func benchmarkQUICConnPairWithConfigAddr(b *testing.B, alpn string, conf *quic.Config, ip net.IP) (client, server *quic.Conn) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	b.Cleanup(cancel)

	srvKey, _ := key.GenerateSecretKey()
	clientKey, _ := key.GenerateSecretKey()
	serverTLS, err := serverTLSConfig(srvKey, []string{alpn})
	if err != nil {
		b.Fatal(err)
	}
	clientTLS, err := clientTLSConfig(clientKey, srvKey.Public().EndpointID(), []string{alpn}, nil)
	if err != nil {
		b.Fatal(err)
	}

	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { serverUDP.Close() })
	ln, err := quic.Listen(serverUDP, serverTLS, conf)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ln.Close() })

	type accepted struct {
		conn *quic.Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept(ctx)
		done <- accepted{conn: c, err: err}
	}()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { clientUDP.Close() })
	client, err = quic.Dial(ctx, clientUDP, ln.Addr(), clientTLS, conf)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	res := <-done
	if res.err != nil {
		b.Fatalf("accept: %v", res.err)
	}
	b.Cleanup(func() {
		client.CloseWithError(0, "")
		res.conn.CloseWithError(0, "")
	})
	return client, res.conn
}

func snapshotQUICConnStats(c *quic.Conn) benchConnStats {
	s := c.ConnectionStats()
	return benchConnStats{
		packetsSent:     s.PacketsSent,
		packetsReceived: s.PacketsReceived,
		bytesSent:       s.BytesSent,
	}
}

func reportQUICConnStats(b *testing.B, client, server *quic.Conn, clientStart, serverStart benchConnStats) {
	b.Helper()
	if b.N == 0 {
		return
	}
	clientEnd := snapshotQUICConnStats(client)
	serverEnd := snapshotQUICConnStats(server)
	packetsSent := (clientEnd.packetsSent - clientStart.packetsSent) + (serverEnd.packetsSent - serverStart.packetsSent)
	packetsReceived := (clientEnd.packetsReceived - clientStart.packetsReceived) + (serverEnd.packetsReceived - serverStart.packetsReceived)
	bytesSent := (clientEnd.bytesSent - clientStart.bytesSent) + (serverEnd.bytesSent - serverStart.bytesSent)
	b.ReportMetric(float64(packetsSent)/float64(b.N), "qpackets-sent/op")
	b.ReportMetric(float64(packetsReceived)/float64(b.N), "qpackets-recv/op")
	b.ReportMetric(float64(bytesSent)/float64(b.N), "qbytes-sent/op")
}

func BenchmarkConnStreamPingPong(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-ping-pong/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}
	defer s.Close()

	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		var buf [1]byte
		for {
			if _, err := io.ReadFull(peer, buf[:]); err != nil {
				done <- err
				return
			}
			if _, err := peer.Write(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	clientStart := snapshotConnStats(client)
	serverStart := snapshotConnStats(server)
	cpuStart := readBenchmarkCPUTime(b)
	captureLatency := os.Getenv("IROH_CAPTURE_OP_LATENCY") == "1"
	var opDurationNS []int64
	if captureLatency {
		opDurationNS = make([]int64, 0, b.N)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var start time.Time
		if captureLatency {
			start = time.Now()
		}
		if _, err := s.Write(buf[:]); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(s, buf[:]); err != nil {
			b.Fatalf("read: %v", err)
		}
		if captureLatency {
			opDurationNS = append(opDurationNS, time.Since(start).Nanoseconds())
		}
	}
	b.StopTimer()
	emitLayerLadderSampleMetrics(b, "full-ping", int64(b.N), cpuStart, opDurationNS)
	reportConnStats(b, client, server, clientStart, serverStart)
	reportConnCipher(b, client)
	s.CancelRead(0)
	s.CancelWrite(0)
	<-done
}

func BenchmarkConnStreamPingPongPhases(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-ping-pong-phases/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}
	defer s.Close()

	type phaseTotals struct {
		read  time.Duration
		write time.Duration
	}
	phases := make(chan phaseTotals, 1)
	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		var buf [1]byte
		var totals phaseTotals
		for {
			t0 := time.Now()
			if _, err := io.ReadFull(peer, buf[:]); err != nil {
				phases <- totals
				done <- err
				return
			}
			t1 := time.Now()
			if _, err := peer.Write(buf[:]); err != nil {
				phases <- totals
				done <- err
				return
			}
			t2 := time.Now()
			totals.read += t1.Sub(t0)
			totals.write += t2.Sub(t1)
		}
	}()

	var buf [1]byte
	var writeTotal, readTotal time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t0 := time.Now()
		if _, err := s.Write(buf[:]); err != nil {
			b.Fatalf("write: %v", err)
		}
		t1 := time.Now()
		if _, err := io.ReadFull(s, buf[:]); err != nil {
			b.Fatalf("read: %v", err)
		}
		t2 := time.Now()
		writeTotal += t1.Sub(t0)
		readTotal += t2.Sub(t1)
	}
	b.StopTimer()
	if b.N > 0 {
		b.ReportMetric(float64(writeTotal.Nanoseconds())/float64(b.N), "write-ns/op")
		b.ReportMetric(float64(readTotal.Nanoseconds())/float64(b.N), "read-ns/op")
	}
	s.CancelRead(0)
	s.CancelWrite(0)
	<-done
	serverPhases := <-phases
	if b.N > 0 {
		b.ReportMetric(float64(serverPhases.read.Nanoseconds())/float64(b.N), "server-read-ns/op")
		b.ReportMetric(float64(serverPhases.write.Nanoseconds())/float64(b.N), "server-write-ns/op")
	}
}

func BenchmarkConnStreamThroughput(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-throughput/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		_, err = io.Copy(io.Discard, peer)
		done <- err
	}()

	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	clientStart := snapshotConnStats(client)
	serverStart := snapshotConnStats(server)
	cpuStart := readBenchmarkCPUTime(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Write(buf); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	b.StopTimer()
	reportCPUPerOp(b, cpuStart)
	transport := reportConnSenderStats(b, client, clientStart)
	emitLayerLadderSampleRecord(b, layerLadderSample{
		Rung:      "full-steady",
		Bytes:     int64(b.N) * int64(len(buf)),
		Transport: transport,
	}, cpuStart)
	if err := s.Close(); err != nil {
		b.Fatalf("close stream: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			b.Fatalf("copy: %v", err)
		}
	case <-time.After(10 * time.Second):
		s.CancelRead(0)
		s.CancelWrite(0)
		b.Fatalf("copy did not finish after stream close")
	}
	reportConnStats(b, client, server, clientStart, serverStart)
	reportConnCipher(b, client)
}

func BenchmarkQUICRawUDPStreamPingPong(b *testing.B) {
	client, server := benchmarkQUICConnPair(b, "iroh-bench-raw-quic-ping-pong/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}
	defer s.Close()

	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		var buf [1]byte
		for {
			if _, err := io.ReadFull(peer, buf[:]); err != nil {
				done <- err
				return
			}
			if _, err := peer.Write(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	clientStart := snapshotQUICConnStats(client)
	serverStart := snapshotQUICConnStats(server)
	cpuStart := readBenchmarkCPUTime(b)
	captureLatency := os.Getenv("IROH_CAPTURE_OP_LATENCY") == "1"
	var opDurationNS []int64
	if captureLatency {
		opDurationNS = make([]int64, 0, b.N)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var start time.Time
		if captureLatency {
			start = time.Now()
		}
		if _, err := s.Write(buf[:]); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(s, buf[:]); err != nil {
			b.Fatalf("read: %v", err)
		}
		if captureLatency {
			opDurationNS = append(opDurationNS, time.Since(start).Nanoseconds())
		}
	}
	b.StopTimer()
	emitLayerLadderSampleMetrics(b, "quic-ping", int64(b.N), cpuStart, opDurationNS)
	reportQUICConnStats(b, client, server, clientStart, serverStart)
	s.CancelRead(0)
	s.CancelWrite(0)
	<-done
}

func BenchmarkQUICRawUDPStreamThroughput(b *testing.B) {
	client, server := benchmarkQUICConnPair(b, "iroh-bench-raw-quic-throughput/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		_, err = io.Copy(io.Discard, peer)
		done <- err
	}()

	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	clientStart := snapshotQUICConnStats(client)
	serverStart := snapshotQUICConnStats(server)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Write(buf); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	b.StopTimer()
	emitLayerLadderSample(b, "quic-steady", int64(b.N)*int64(len(buf)))
	if err := s.Close(); err != nil {
		b.Fatalf("close stream: %v", err)
	}
	if err := <-done; err != nil {
		b.Fatalf("copy: %v", err)
	}
	reportQUICConnStats(b, client, server, clientStart, serverStart)
}

func BenchmarkConnDatagramPingPong(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-datagram-ping-pong/0")
	benchmarkDatagramPingPong(b, client, server)
}

func benchmarkDatagramPingPong(b *testing.B, client, server *Conn) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		for {
			p, err := server.ReadDatagram(ctx)
			if err != nil {
				done <- err
				return
			}
			if err := server.SendDatagram(p); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := []byte{0}
	b.ReportAllocs()
	clientStart := snapshotConnStats(client)
	serverStart := snapshotConnStats(server)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.SendDatagram(buf); err != nil {
			b.Fatalf("send datagram: %v", err)
		}
		if _, err := client.ReadDatagram(ctx); err != nil {
			b.Fatalf("read datagram: %v", err)
		}
	}
	b.StopTimer()
	reportConnStats(b, client, server, clientStart, serverStart)
	client.CloseWithError(0, "")
	<-done
}

func BenchmarkConnDatagramThroughput(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-datagram-throughput/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		for {
			p, err := server.ReadDatagram(ctx)
			if err != nil {
				done <- err
				return
			}
			if err := server.SendDatagram(p); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	clientStart := snapshotConnStats(client)
	serverStart := snapshotConnStats(server)
	b.ResetTimer()
	const window = 32
	var sent, received int
	for received < b.N {
		for sent < b.N && sent-received < window {
			if err := client.SendDatagram(buf); err != nil {
				b.Fatalf("send datagram: %v", err)
			}
			sent++
		}
		if _, err := client.ReadDatagram(ctx); err != nil {
			b.Fatalf("read datagram: %v", err)
		}
		received++
	}
	b.StopTimer()
	reportConnStats(b, client, server, clientStart, serverStart)
	client.CloseWithError(0, "")
	<-done
}

func benchmarkTCPConnPair(b *testing.B) (client, server net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ln.Close() })

	type accepted struct {
		conn net.Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		done <- accepted{conn: c, err: err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial tcp: %v", err)
	}
	res := <-done
	if res.err != nil {
		b.Fatalf("accept tcp: %v", res.err)
	}
	b.Cleanup(func() {
		client.Close()
		res.conn.Close()
	})
	return client, res.conn
}

func BenchmarkRawTCPConnPingPong(b *testing.B) {
	client, server := benchmarkTCPConnPair(b)

	done := make(chan error, 1)
	go func() {
		var buf [1]byte
		for {
			if _, err := io.ReadFull(server, buf[:]); err != nil {
				done <- err
				return
			}
			if _, err := server.Write(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	cpuStart := readBenchmarkCPUTime(b)
	captureLatency := os.Getenv("IROH_CAPTURE_OP_LATENCY") == "1"
	var opDurationNS []int64
	if captureLatency {
		opDurationNS = make([]int64, 0, b.N)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var start time.Time
		if captureLatency {
			start = time.Now()
		}
		if _, err := client.Write(buf[:]); err != nil {
			b.Fatalf("write tcp: %v", err)
		}
		if _, err := io.ReadFull(client, buf[:]); err != nil {
			b.Fatalf("read tcp: %v", err)
		}
		if captureLatency {
			opDurationNS = append(opDurationNS, time.Since(start).Nanoseconds())
		}
	}
	b.StopTimer()
	emitLayerLadderSampleMetrics(b, "tcp-ping", int64(b.N), cpuStart, opDurationNS)
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawTCPConnThroughput(b *testing.B) {
	client, server := benchmarkTCPConnPair(b)

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, server)
		done <- err
	}()

	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf); err != nil {
			b.Fatalf("write tcp: %v", err)
		}
	}
	b.StopTimer()
	emitLayerLadderSample(b, "tcp", int64(b.N)*int64(len(buf)))
	client.Close()
	if err := <-done; err != nil {
		b.Fatalf("copy tcp: %v", err)
	}
}

func benchmarkUDPConnPair(b *testing.B) (client, server *net.UDPConn) {
	b.Helper()
	server, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { server.Close() })

	client, err = net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("dial udp: %v", err)
	}
	b.Cleanup(func() { client.Close() })
	return client, server
}

func benchmarkUnconnectedUDPConnPair(b *testing.B) (client, server *net.UDPConn, serverAddr netip.AddrPort) {
	b.Helper()
	server, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { server.Close() })
	client, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { client.Close() })
	return client, server, server.LocalAddr().(*net.UDPAddr).AddrPort()
}

func BenchmarkRawUDPPingPong(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)

	done := make(chan error, 1)
	go func() {
		var buf [1]byte
		for {
			n, addr, err := server.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			if _, err := server.WriteToUDPAddrPort(buf[:n], addr); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf[:]); err != nil {
			b.Fatalf("write udp: %v", err)
		}
		if _, err := io.ReadFull(client, buf[:]); err != nil {
			b.Fatalf("read udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawUDPQueuedPingPong(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)

	type writeReq struct {
		conn *net.UDPConn
		addr netip.AddrPort
		buf  [1]byte
	}
	writes := make(chan writeReq, 16)
	writerDone := make(chan error, 1)
	go func() {
		for req := range writes {
			var err error
			if req.addr.IsValid() {
				_, err = req.conn.WriteToUDPAddrPort(req.buf[:], req.addr)
			} else {
				_, err = req.conn.Write(req.buf[:])
			}
			if err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()

	done := make(chan error, 1)
	go func() {
		var buf [1]byte
		for {
			n, addr, err := server.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			if n != 1 {
				done <- io.ErrShortBuffer
				return
			}
			writes <- writeReq{conn: server, addr: addr, buf: buf}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writes <- writeReq{conn: client, buf: buf}
		if _, err := io.ReadFull(client, buf[:]); err != nil {
			b.Fatalf("read udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
	close(writes)
	if err := <-writerDone; err != nil {
		b.Fatalf("write udp: %v", err)
	}
}

func BenchmarkRawUDPFullyQueuedPingPong(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)

	type datagram struct {
		addr netip.AddrPort
		buf  [1]byte
	}
	type writeReq struct {
		conn *net.UDPConn
		addr netip.AddrPort
		buf  [1]byte
	}

	clientReads := make(chan datagram, 16)
	serverReads := make(chan datagram, 16)
	readLoop := func(conn *net.UDPConn, out chan<- datagram, done chan<- error) {
		var buf [1]byte
		for {
			n, addr, err := conn.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			if n != 1 {
				done <- io.ErrShortBuffer
				return
			}
			out <- datagram{addr: addr, buf: buf}
		}
	}

	clientReadDone := make(chan error, 1)
	serverReadDone := make(chan error, 1)
	go readLoop(client, clientReads, clientReadDone)
	go readLoop(server, serverReads, serverReadDone)

	writes := make(chan writeReq, 16)
	writerDone := make(chan error, 1)
	go func() {
		for req := range writes {
			var err error
			if req.addr.IsValid() {
				_, err = req.conn.WriteToUDPAddrPort(req.buf[:], req.addr)
			} else {
				_, err = req.conn.Write(req.buf[:])
			}
			if err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()

	serverDone := make(chan error, 1)
	go func() {
		for d := range serverReads {
			writes <- writeReq{conn: server, addr: d.addr, buf: d.buf}
		}
		serverDone <- nil
	}()

	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writes <- writeReq{conn: client, buf: buf}
		<-clientReads
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-clientReadDone
	<-serverReadDone
	close(serverReads)
	<-serverDone
	close(writes)
	if err := <-writerDone; err != nil {
		b.Fatalf("write udp: %v", err)
	}
}

func BenchmarkRawUDPMagicQueuedPingPong(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)
	benchmarkRawUDPMagicQueuedPingPong(b, client, server, netip.AddrPort{})
}

func BenchmarkRawUDPUnconnectedMagicQueuedPingPong(b *testing.B) {
	client, server, serverAddr := benchmarkUnconnectedUDPConnPair(b)
	benchmarkRawUDPMagicQueuedPingPong(b, client, server, serverAddr)
}

func benchmarkRawUDPMagicQueuedPingPong(b *testing.B, client, server *net.UDPConn, clientWriteAddr netip.AddrPort) {

	type datagram struct {
		addr netip.AddrPort
		buf  []byte
	}
	type writeReq struct {
		conn *net.UDPConn
		addr netip.AddrPort
		buf  []byte
	}

	const (
		recvDepth = 4
		bufSize   = 1452 + 512
	)

	pool := make(chan []byte, 1024)
	getBuf := func() []byte {
		select {
		case buf := <-pool:
			return buf
		default:
			return make([]byte, bufSize)
		}
	}
	putBuf := func(buf []byte) {
		select {
		case pool <- buf[:bufSize]:
		default:
		}
	}

	readLoop := func(conn *net.UDPConn, out chan<- datagram, done chan<- error) {
		for {
			buf := getBuf()
			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				putBuf(buf)
				done <- err
				return
			}
			out <- datagram{addr: addr, buf: buf[:n]}
		}
	}

	clientReads := make(chan datagram, recvDepth)
	serverReads := make(chan datagram, recvDepth)
	clientReadDone := make(chan error, 1)
	serverReadDone := make(chan error, 1)
	go readLoop(client, clientReads, clientReadDone)
	go readLoop(server, serverReads, serverReadDone)

	writes := make(chan writeReq, 64)
	writerDone := make(chan error, 1)
	go func() {
		for req := range writes {
			var err error
			if req.addr.IsValid() {
				_, err = req.conn.WriteToUDPAddrPort(req.buf, req.addr)
			} else {
				_, err = req.conn.Write(req.buf)
			}
			if err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()

	serverDone := make(chan error, 1)
	go func() {
		var buf [1]byte
		for d := range serverReads {
			if len(d.buf) != 1 {
				putBuf(d.buf)
				serverDone <- io.ErrShortBuffer
				return
			}
			copy(buf[:], d.buf)
			putBuf(d.buf)
			writes <- writeReq{conn: server, addr: d.addr, buf: buf[:]}
		}
		serverDone <- nil
	}()

	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writes <- writeReq{conn: client, addr: clientWriteAddr, buf: buf[:]}
		d := <-clientReads
		copy(buf[:], d.buf)
		putBuf(d.buf)
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-clientReadDone
	<-serverReadDone
	close(serverReads)
	<-serverDone
	close(writes)
	if err := <-writerDone; err != nil {
		b.Fatalf("write udp: %v", err)
	}
}

func BenchmarkRawUDPThroughput(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)
	b.Cleanup(func() { client.SetReadDeadline(time.Now()) })

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		for {
			n, addr, err := server.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			if _, err := server.WriteToUDPAddrPort(buf[:n], addr); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf); err != nil {
			b.Fatalf("write udp: %v", err)
		}
		if _, err := io.ReadFull(client, buf); err != nil {
			b.Fatalf("read udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawUDPSendThroughput(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		for {
			if _, _, err := server.ReadFromUDPAddrPort(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf); err != nil {
			b.Fatalf("write udp: %v", err)
		}
	}
	b.StopTimer()
	emitLayerLadderSample(b, "udp", int64(b.N)*int64(len(buf)))
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawUDPUnconnectedSendThroughput(b *testing.B) {
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		client.Close()
		b.Fatal(err)
	}
	serverAddr := server.LocalAddr().(*net.UDPAddr).AddrPort()

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		for {
			if _, _, err := server.ReadFromUDPAddrPort(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.WriteToUDPAddrPort(buf, serverAddr); err != nil {
			b.Fatalf("write udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawUDPUnconnectedAckedSendThroughput(b *testing.B) {
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		client.Close()
		b.Fatal(err)
	}
	serverAddr := server.LocalAddr().(*net.UDPAddr).AddrPort()

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		var ack [1]byte
		var nrecv int
		for {
			_, addr, err := server.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			nrecv++
			if nrecv%10 == 0 {
				if _, err := server.WriteToUDPAddrPort(ack[:], addr); err != nil {
					done <- err
					return
				}
			}
		}
	}()

	ackDone := make(chan error, 1)
	go func() {
		var ack [1]byte
		for {
			if _, _, err := client.ReadFromUDPAddrPort(ack[:]); err != nil {
				ackDone <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.WriteToUDPAddrPort(buf, serverAddr); err != nil {
			b.Fatalf("write udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
	<-ackDone
}

func BenchmarkRawMagicConnSendThroughput(b *testing.B) {
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		clientUDP.Close()
		b.Fatal(err)
	}

	sock := socket.NewSocket()
	magic := socket.NewMagicConn(sock, clientUDP)

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		for {
			if _, _, err := serverUDP.ReadFromUDPAddrPort(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	addr := serverUDP.LocalAddr()
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := magic.WriteTo(buf, addr); err != nil {
			b.Fatalf("write magic: %v", err)
		}
	}
	b.StopTimer()
	magic.Close()
	serverUDP.Close()
	<-done
}

func BenchmarkRawMagicConnAckedSendThroughput(b *testing.B) {
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		clientUDP.Close()
		b.Fatal(err)
	}

	sock := socket.NewSocket()
	magic := socket.NewMagicConn(sock, clientUDP)
	ctx, cancel := context.WithCancel(context.Background())
	go magic.Serve(ctx)

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		var ack [1]byte
		var nrecv int
		for {
			_, addr, err := serverUDP.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			nrecv++
			if nrecv%10 == 0 {
				if _, err := serverUDP.WriteToUDPAddrPort(ack[:], addr); err != nil {
					done <- err
					return
				}
			}
		}
	}()

	ackDone := make(chan error, 1)
	go func() {
		var ack [1]byte
		for {
			if _, _, err := magic.ReadFrom(ack[:]); err != nil {
				ackDone <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	addr := serverUDP.LocalAddr()
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := magic.WriteTo(buf, addr); err != nil {
			b.Fatalf("write magic: %v", err)
		}
	}
	b.StopTimer()
	cancel()
	magic.Close()
	serverUDP.Close()
	<-done
	<-ackDone
}

func BenchmarkRawMagicConnPingPong(b *testing.B) {
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		clientUDP.Close()
		b.Fatal(err)
	}

	clientSock := socket.NewSocket()
	serverSock := socket.NewSocket()
	client := socket.NewMagicConn(clientSock, clientUDP)
	server := socket.NewMagicConn(serverSock, serverUDP)
	ctx, cancel := context.WithCancel(context.Background())
	go client.Serve(ctx)
	go server.Serve(ctx)

	done := make(chan error, 1)
	go func() {
		var buf [1]byte
		for {
			n, addr, err := server.ReadFrom(buf[:])
			if err != nil {
				done <- err
				return
			}
			if n != 1 {
				done <- io.ErrShortBuffer
				return
			}
			if _, err := server.WriteTo(buf[:], addr); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	serverAddr := serverUDP.LocalAddr()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.WriteTo(buf[:], serverAddr); err != nil {
			b.Fatalf("write magic: %v", err)
		}
		if _, _, err := client.ReadFrom(buf[:]); err != nil {
			b.Fatalf("read magic: %v", err)
		}
	}
	b.StopTimer()
	cancel()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawMagicConnReceiveThroughput(b *testing.B) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		udp.Close()
		b.Fatal(err)
	}

	sock := socket.NewSocket()
	magic := socket.NewMagicConn(sock, udp)
	ctx, cancel := context.WithCancel(context.Background())
	go magic.Serve(ctx)

	done := make(chan error, 1)
	payload := make([]byte, 1200)
	dst := udp.LocalAddr()
	go func() {
		for {
			if _, err := sender.WriteTo(payload, dst); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := magic.ReadFrom(buf); err != nil {
			b.Fatalf("read magic: %v", err)
		}
	}
	b.StopTimer()
	cancel()
	magic.Close()
	sender.Close()
	<-done
}
