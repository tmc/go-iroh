package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const transportALPN = "go-iroh-compat/1"

func RunTransportMatrix(rustClient, version, digest string) []Cell {
	return []Cell{
		runTransportDatagrams(rustClient, version, digest),
		runTransportClose(rustClient, version, digest),
		runTransportRemoteInfo(rustClient, version, digest),
		runTransportZeroRTT(rustClient, version, digest),
	}
}

func runTransportDatagrams(bin, version, digest string) (cell Cell) {
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	cell, ctx, cancel, peer, ep := startTransportCell(bin, version, digest, "handshake/datagrams", "datagrams")
	defer cancel()
	if peer == nil {
		return cell
	}
	defer peer.close()
	defer ep.Shutdown(context.Background())
	conn, err := ep.Connect(ctx, peer.endpointAddr(), transportALPN)
	if err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("connect Rust datagram peer: %v", err))
	}
	if err := conn.SendDatagram([]byte("go-datagram")); err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("send Go datagram: %v", err))
	}
	got, err := conn.ReadDatagram(ctx)
	if err != nil || string(got) != "rust-datagram" {
		return finishCell(cell, Fail, fmt.Sprintf("Rust datagram = %q, err %v", got, err))
	}
	if err := conn.SendDatagram([]byte("go-ack")); err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("acknowledge Rust datagram: %v", err))
	}
	ack, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("accept Rust datagram acknowledgement: %v", err))
	}
	ackText, err := io.ReadAll(ack)
	if err != nil || string(ackText) != "datagrams-ok" {
		return finishCell(cell, Fail, fmt.Sprintf("Rust datagram acknowledgement = %q, err %v", ackText, err))
	}
	_ = conn.Close()
	if err := peer.waitFor("datagrams-ok"); err != nil {
		return finishCell(cell, Fail, err.Error())
	}
	return finishCell(cell, Pass, "Go and the Rust test driver exchanged QUIC datagrams in both directions")
}

func runTransportClose(bin, version, digest string) (cell Cell) {
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	cell, ctx, cancel, peer, ep := startTransportCell(bin, version, digest, "handshake/close-semantics", "close")
	defer cancel()
	if peer == nil {
		return cell
	}
	defer peer.close()
	defer ep.Shutdown(context.Background())
	conn, err := ep.Connect(ctx, peer.endpointAddr(), transportALPN)
	if err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("connect Rust close peer: %v", err))
	}
	if err := conn.CloseWithError(42, "bye"); err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("close Go connection: %v", err))
	}
	if err := peer.waitFor("close-ok"); err != nil {
		return finishCell(cell, Fail, err.Error())
	}
	return finishCell(cell, Pass, "Rust peer observed Go application close code 42 and reason bye")
}

func runTransportRemoteInfo(bin, version, digest string) (cell Cell) {
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	cell, ctx, cancel, peer, ep := startTransportCell(bin, version, digest, "handshake/remote-info", "remote-info")
	defer cancel()
	if peer == nil {
		return cell
	}
	defer peer.close()
	defer ep.Shutdown(context.Background())
	conn, err := ep.Connect(ctx, peer.endpointAddr(), transportALPN)
	if err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("connect Rust remote-info peer: %v", err))
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("open remote-info stream: %v", err))
	}
	if _, err := stream.Write([]byte("remote-info")); err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("write remote-info stream: %v", err))
	}
	_ = stream.Close()
	got, err := io.ReadAll(stream)
	if err != nil || string(got) != "remote-info" {
		return finishCell(cell, Fail, fmt.Sprintf("remote-info echo = %q, err %v", got, err))
	}
	info, ok := ep.RemoteInfo(peer.id)
	if !ok || !info.ID.Equal(peer.id) || len(info.Addrs) == 0 {
		return finishCell(cell, Fail, fmt.Sprintf("Go remote info = %+v, present %t", info, ok))
	}
	_ = conn.Close()
	if err := peer.waitFor("remote-info-ok"); err != nil {
		return finishCell(cell, Fail, err.Error())
	}
	return finishCell(cell, Pass, "Go and the Rust test driver both recorded the authenticated peer and direct address")
}

func runTransportZeroRTT(bin, version, digest string) (cell Cell) {
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	cell, ctx, cancel, peer, ep := startTransportCell(bin, version, digest, "handshake/zero-rtt", "zero-rtt")
	defer cancel()
	if peer == nil {
		return cell
	}
	defer peer.close()
	defer ep.Shutdown(context.Background())
	first, err := ep.ConnectEarly(ctx, peer.endpointAddr(), transportALPN)
	if err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("prime Rust session: %v", err))
	}
	conn1, early := first.Into0RTT()
	if early {
		return finishCell(cell, Fail, "cold connection unexpectedly offered 0-RTT")
	}
	if err := transportEcho(ctx, conn1, "cold"); err != nil {
		return finishCell(cell, Fail, err.Error())
	}
	time.Sleep(200 * time.Millisecond)
	_ = conn1.Close()
	second, err := ep.ConnectEarly(ctx, peer.endpointAddr(), transportALPN)
	if err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("resume Rust session: %v", err))
	}
	conn2, early := second.Into0RTT()
	if !early {
		return finishCell(cell, Fail, "warm connection did not offer 0-RTT")
	}
	if err := transportEcho(ctx, conn2, "early"); err != nil {
		return finishCell(cell, Fail, err.Error())
	}
	select {
	case <-conn2.HandshakeComplete():
	case <-ctx.Done():
		return finishCell(cell, Fail, "resumed handshake: "+ctx.Err().Error())
	}
	if !conn2.Used0RTT() {
		return finishCell(cell, Fail, "Rust peer rejected Go 0-RTT data")
	}
	_ = conn2.Close()
	if err := peer.waitFor("zero-rtt-ok"); err != nil {
		return finishCell(cell, Fail, err.Error())
	}
	return finishCell(cell, Pass, "Go resumed a Rust-issued TLS session and Rust accepted the second stream as 0-RTT")
}

func transportEcho(ctx context.Context, conn *iroh.Conn, message string) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open transport stream: %w", err)
	}
	if _, err := stream.Write([]byte(message)); err != nil {
		return fmt.Errorf("write transport stream: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("finish transport stream: %w", err)
	}
	got, err := io.ReadAll(stream)
	if err != nil || string(got) != message {
		return fmt.Errorf("transport echo = %q, err %v", got, err)
	}
	return nil
}

func startTransportCell(bin, version, digest, scenario, mode string) (Cell, context.Context, context.CancelFunc, *transportPeer, *iroh.Endpoint) {
	cell := Cell{Scenario: scenario, Iroh: version, Tier: "B", Expected: Pass, Peer: "rust-driver@" + digest, PeerDigest: digest}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	peer, err := startTransportPeer(ctx, bin, mode)
	if err != nil {
		return finishCell(cell, SetupError, err.Error()), ctx, cancel, nil, nil
	}
	cell.PeerPID = peer.cmd.Process.Pid
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), irohRelayDisabled())
	if err != nil {
		peer.close()
		return finishCell(cell, SetupError, fmt.Sprintf("bind Go transport peer: %v", err)), ctx, cancel, nil, nil
	}
	return cell, ctx, cancel, peer, ep
}

type transportPeer struct {
	cmd    *exec.Cmd
	id     key.EndpointID
	addr   netip.AddrPort
	output lockedBuffer
	done   chan error
	once   sync.Once
}

func startTransportPeer(ctx context.Context, bin, mode string) (*transportPeer, error) {
	cmd := exec.CommandContext(ctx, bin, "transport-server", mode)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	p := &transportPeer{cmd: cmd, done: make(chan error, 1)}
	cmd.Stderr = &p.output
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start Rust transport peer: %w", err)
	}
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil {
		p.close()
		return nil, fmt.Errorf("read Rust transport readiness: %w: %s", err, p.output.String())
	}
	var ready struct{ ID, Addr string }
	if err := json.Unmarshal([]byte(line), &ready); err != nil {
		p.close()
		return nil, fmt.Errorf("decode Rust transport readiness: %w: %s", err, line)
	}
	p.id, err = key.ParseEndpointID(ready.ID)
	if err != nil {
		p.close()
		return nil, fmt.Errorf("parse Rust endpoint id: %w", err)
	}
	p.addr, err = netip.ParseAddrPort(ready.Addr)
	if err != nil {
		p.close()
		return nil, fmt.Errorf("parse Rust endpoint address: %w", err)
	}
	go func() {
		_, _ = io.Copy(&p.output, reader)
		p.done <- cmd.Wait()
	}()
	return p, nil
}

func (p *transportPeer) endpointAddr() netaddr.EndpointAddr {
	return netaddr.NewEndpointAddr(p.id).WithIP(p.addr)
}

func (p *transportPeer) waitFor(marker string) error {
	if err := <-p.done; err != nil {
		return fmt.Errorf("Rust transport peer: %w: %s", err, p.output.String())
	}
	if !strings.Contains(p.output.String(), marker) {
		return fmt.Errorf("Rust transport peer omitted %q: %s", marker, p.output.String())
	}
	return nil
}

func (p *transportPeer) close() {
	p.once.Do(func() {
		if p.cmd.ProcessState == nil {
			_ = p.cmd.Process.Kill()
		}
	})
}
