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

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func RunGossip(bin, version, digest string) (cell Cell) {
	cell = Cell{Scenario: "vectors/gossip-frame", Iroh: version, Peer: "rust-driver@" + digest, PeerDigest: digest}
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	peer, err := startGossipPeer(ctx, bin)
	if err != nil {
		return finishCell(cell, SetupError, err.Error())
	}
	defer peer.close()
	cell.PeerPID = peer.cmd.Process.Pid
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")), irohRelayDisabled())
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("bind Go gossip endpoint: %v", err))
	}
	g := gossip.NewGossip(ep)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{gossip.ALPN: g.Handler()}, nil)
	if err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("start Go gossip router: %v", err))
	}
	defer router.Shutdown(context.Background())
	var topic gossip.TopicID
	copy(topic[:], []byte("go-iroh rust gossip interop 001!"))
	sub, err := g.SubscribeAndJoin(ctx, topic, []netaddr.EndpointAddr{peer.endpointAddr()})
	if err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("join Rust gossip peer: %v: %s", err, peer.output.String()))
	}
	defer sub.Close()
	_, receiver := sub.Split()
	if err := receiver.Joined(ctx); err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("wait for Rust gossip neighbor: %v", err))
	}
	events := make(chan gossip.Event, 1)
	go func() {
		for ev, err := range receiver.Events() {
			if err == nil && ev.Kind == gossip.Received {
				events <- ev
				return
			}
		}
	}()
	if err := sub.Broadcast(ctx, []byte("hello from go")); err != nil {
		return finishCell(cell, Fail, fmt.Sprintf("broadcast Go gossip frame: %v", err))
	}
	for {
		select {
		case ev := <-events:
			if ev.Kind == gossip.Received && string(ev.Content) == "hello from rust" && ev.DeliveredFrom.Equal(peer.id) {
				if err := peer.waitFor("gossip-ok"); err != nil {
					return finishCell(cell, Fail, err.Error())
				}
				return finishCell(cell, Pass, "Go and upstream Rust gossip codecs exchanged framed broadcasts in both directions")
			}
		case <-ctx.Done():
			return finishCell(cell, Fail, "gossip exchange: "+ctx.Err().Error()+": "+peer.output.String())
		}
	}
}

type gossipPeer struct {
	cmd    *exec.Cmd
	id     key.EndpointID
	addr   netip.AddrPort
	output lockedBuffer
	done   chan error
	once   sync.Once
}

func startGossipPeer(ctx context.Context, bin string) (*gossipPeer, error) {
	cmd := exec.CommandContext(ctx, bin, "gossip-server")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	p := &gossipPeer{cmd: cmd, done: make(chan error, 1)}
	cmd.Stderr = &p.output
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start Rust gossip peer: %w", err)
	}
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil {
		p.close()
		return nil, fmt.Errorf("read Rust gossip readiness: %w: %s", err, p.output.String())
	}
	var ready struct {
		ID    string   `json:"id"`
		Addrs []string `json:"addrs"`
	}
	if err := json.Unmarshal([]byte(line), &ready); err != nil || len(ready.Addrs) == 0 {
		p.close()
		return nil, fmt.Errorf("decode Rust gossip readiness: %v: %s", err, line)
	}
	p.id, err = key.ParseEndpointID(ready.ID)
	if err == nil {
		p.addr, err = netip.ParseAddrPort(ready.Addrs[0])
	}
	if err != nil {
		p.close()
		return nil, fmt.Errorf("parse Rust gossip address: %w", err)
	}
	go func() {
		_, _ = io.Copy(&p.output, reader)
		p.done <- cmd.Wait()
	}()
	return p, nil
}

func (p *gossipPeer) endpointAddr() netaddr.EndpointAddr {
	return netaddr.NewEndpointAddr(p.id).WithIP(p.addr)
}

func (p *gossipPeer) waitFor(marker string) error {
	if err := <-p.done; err != nil {
		return fmt.Errorf("Rust gossip peer: %w: %s", err, p.output.String())
	}
	if !strings.Contains(p.output.String(), marker) {
		return fmt.Errorf("Rust gossip peer omitted %q: %s", marker, p.output.String())
	}
	return nil
}

func (p *gossipPeer) close() {
	p.once.Do(func() {
		if p.cmd.ProcessState == nil {
			_ = p.cmd.Process.Kill()
		}
	})
}
