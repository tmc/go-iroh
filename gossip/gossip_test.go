package gossip_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func ExampleDiscovery() {
	sk, _ := key.GenerateSecretKey()
	discovery := gossip.New(sk.Public().EndpointID())

	var services iroh.AddressLookupServices
	services.AddPublisher(discovery)
	services.AddResolver(discovery)

	fmt.Println(discovery != nil)
	// Output:
	// true
}

func TestSenderHandlerLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var topic gossip.TopicID
	copy(topic[:], "topic")
	want := []gossip.Message{{
		Topic: topic,
		Message: gossip.TopicMessage{
			Kind: gossipproto.TopicMessageSwarm,
			Swarm: gossipproto.HyparviewMessage{
				Kind: gossipproto.HyparviewJoin,
			},
		},
	}}
	var otherTopic gossip.TopicID
	copy(otherTopic[:], "other")
	want = append(want, gossip.Message{
		Topic: otherTopic,
		Message: gossip.TopicMessage{
			Kind: gossipproto.TopicMessageSwarm,
			Swarm: gossipproto.HyparviewMessage{
				Kind: gossipproto.HyparviewNeighbor,
				Neighbor: gossipproto.Neighbor{
					Priority: gossipproto.PriorityHigh,
				},
			},
		},
	})

	gotc := make(chan gossip.Message, len(want))
	fromc := make(chan key.EndpointID, len(want))

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		gossip.ALPN: &gossip.Handler{
			Handle: func(ctx context.Context, from key.EndpointID, msg gossip.Message) error {
				fromc <- from
				gotc <- msg
				return nil
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, gossip.ALPN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	sender := gossip.NewSender(conn, 0)
	for _, msg := range want {
		if err := sender.Send(ctx, msg); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if err := sender.Close(); err != nil {
		t.Fatalf("close sender: %v", err)
	}

	got := make(map[gossip.TopicID]gossip.Message)
	for range want {
		select {
		case msg := <-gotc:
			got[msg.Topic] = msg
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for _, msg := range want {
		if got[msg.Topic].Message.Kind != msg.Message.Kind || got[msg.Topic].Message.Swarm.Kind != msg.Message.Swarm.Kind {
			t.Fatalf("message for topic %x = %+v, want %+v", msg.Topic, got[msg.Topic], msg)
		}
	}

	for range want {
		select {
		case from := <-fromc:
			if !from.Equal(client.ID()) {
				t.Fatalf("from = %s, want %s", from, client.ID())
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func TestGossipTopicLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var topic gossip.TopicID
	copy(topic[:], "topic")

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	serverGossip := gossip.NewGossip(server)
	serverRouter, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		gossip.ALPN: serverGossip.Handler(),
	}, nil)
	if err != nil {
		t.Fatalf("new server router: %v", err)
	}
	defer serverRouter.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	clientGossip := gossip.NewGossip(client)
	clientRouter, err := iroh.NewRouter(client, map[string]iroh.ProtocolHandler{
		gossip.ALPN: clientGossip.Handler(),
	}, nil)
	if err != nil {
		t.Fatalf("new client router: %v", err)
	}
	defer clientRouter.Shutdown(ctx)

	serverTopic, err := serverGossip.Subscribe(ctx, topic, nil)
	if err != nil {
		t.Fatalf("server subscribe: %v", err)
	}
	defer serverTopic.Close()

	serverAddr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	clientTopic, err := clientGossip.Subscribe(ctx, topic, []netaddr.EndpointAddr{serverAddr})
	if err != nil {
		t.Fatalf("client subscribe: %v", err)
	}
	defer clientTopic.Close()

	if ev := nextEvent(ctx, t, clientTopic); ev.Kind != gossip.NeighborUp {
		t.Fatalf("client first event = %+v, want NeighborUp", ev)
	}
	if ev := nextEvent(ctx, t, serverTopic); ev.Kind != gossip.NeighborUp {
		t.Fatalf("server first event = %+v, want NeighborUp", ev)
	}

	if err := clientTopic.Broadcast(ctx, []byte("hello")); err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	for {
		ev := nextEvent(ctx, t, serverTopic)
		if ev.Kind != gossip.Received {
			continue
		}
		if string(ev.Content) != "hello" {
			t.Fatalf("content = %q, want hello", ev.Content)
		}
		if !ev.DeliveredFrom.Equal(client.ID()) {
			t.Fatalf("delivered from = %s, want %s", ev.DeliveredFrom, client.ID())
		}
		if err := clientTopic.Close(); err != nil {
			t.Fatalf("close topic: %v", err)
		}
		if err := clientTopic.Broadcast(ctx, []byte("after close")); err == nil {
			t.Fatal("broadcast after close succeeded")
		}
		return
	}
}

func TestGossipTopicSplitAndSubscribeAndJoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var topic gossip.TopicID
	copy(topic[:], "split")

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	serverGossip := gossip.NewGossip(server)
	serverRouter, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		gossip.ALPN: serverGossip.Handler(),
	}, nil)
	if err != nil {
		t.Fatalf("new server router: %v", err)
	}
	defer serverRouter.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	clientGossip := gossip.NewGossip(client)
	clientRouter, err := iroh.NewRouter(client, map[string]iroh.ProtocolHandler{
		gossip.ALPN: clientGossip.Handler(),
	}, nil)
	if err != nil {
		t.Fatalf("new client router: %v", err)
	}
	defer clientRouter.Shutdown(ctx)

	serverTopic, err := serverGossip.Subscribe(ctx, topic, nil)
	if err != nil {
		t.Fatalf("server subscribe: %v", err)
	}
	defer serverTopic.Close()

	serverAddr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	clientTopic, err := clientGossip.SubscribeAndJoin(ctx, topic, []netaddr.EndpointAddr{serverAddr})
	if err != nil {
		t.Fatalf("client subscribe and join: %v", err)
	}
	defer clientTopic.Close()

	sender, receiver := clientTopic.Split()
	if !receiver.IsJoined() || !clientTopic.IsJoined() {
		t.Fatal("client topic is not joined")
	}
	neighbors := receiver.Neighbors()
	if len(neighbors) != 1 || !neighbors[0].Equal(server.ID()) {
		t.Fatalf("neighbors = %v, want [%s]", neighbors, server.ID())
	}
	if err := receiver.Joined(ctx); err != nil {
		t.Fatalf("receiver joined: %v", err)
	}
	if err := sender.Broadcast(ctx, []byte("split hello")); err != nil {
		t.Fatalf("split broadcast: %v", err)
	}
	for {
		ev := nextEvent(ctx, t, serverTopic)
		if ev.Kind != gossip.Received {
			continue
		}
		if string(ev.Content) != "split hello" {
			t.Fatalf("content = %q, want split hello", ev.Content)
		}
		cm := clientGossip.Metrics()
		if cm.MsgsDataSent == 0 || cm.NeighborUp == 0 {
			t.Fatalf("client metrics = %+v, want data sent and neighbor up", cm)
		}
		sm := serverGossip.Metrics()
		if sm.MsgsDataRecv == 0 || sm.NeighborUp == 0 {
			t.Fatalf("server metrics = %+v, want data recv and neighbor up", sm)
		}
		if got := cm.Snapshot()["msgs_data_sent"]; got == 0 {
			t.Fatalf("snapshot msgs_data_sent = %d, want non-zero", got)
		}
		return
	}
}

func TestDiscoveryLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var topic gossip.TopicID
	copy(topic[:], "discovery")

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	serverGossip := gossip.NewGossip(server)
	serverRouter, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		gossip.ALPN: serverGossip.Handler(),
	}, nil)
	if err != nil {
		t.Fatalf("new server router: %v", err)
	}
	defer serverRouter.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	clientGossip := gossip.NewGossip(client)
	clientRouter, err := iroh.NewRouter(client, map[string]iroh.ProtocolHandler{
		gossip.ALPN: clientGossip.Handler(),
	}, nil)
	if err != nil {
		t.Fatalf("new client router: %v", err)
	}
	defer clientRouter.Shutdown(ctx)

	serverAddr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	serverDiscovery := gossip.New(server.ID(), gossip.WithGossip(serverGossip, topic, nil))
	clientDiscovery := gossip.New(client.ID(), gossip.WithGossip(clientGossip, topic, []netaddr.EndpointAddr{serverAddr}))

	data := dns.NewEndpointData(netaddr.IPAddr{Addr: server.LocalAddr()})
	serverDiscovery.Publish(data)

	startErr := make(chan error, 2)
	go func() { startErr <- serverDiscovery.Start(ctx) }()
	go func() { startErr <- clientDiscovery.Start(ctx) }()

	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				serverDiscovery.Publish(data)
			}
		}
	}()

	for item, err := range clientDiscovery.Resolve(ctx, server.ID()) {
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if item.Provenance() != gossip.Provenance {
			t.Fatalf("provenance = %q, want %q", item.Provenance(), gossip.Provenance)
		}
		if got := item.EndpointInfo().Data.IPAddrs(); len(got) != 1 || got[0] != server.LocalAddr() {
			t.Fatalf("ip addrs = %v, want %v", got, server.LocalAddr())
		}
		cancel()
		<-done
		return
	}
	t.Fatal("resolve produced no items")
}

func nextEvent(ctx context.Context, t *testing.T, topic *gossip.Topic) gossip.Event {
	t.Helper()
	type result struct {
		event gossip.Event
		err   error
		ok    bool
	}
	done := make(chan result, 1)
	go func() {
		for ev, err := range topic.Events() {
			done <- result{event: ev, err: err, ok: true}
			return
		}
		done <- result{}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("event: %v", res.err)
		}
		if !res.ok {
			t.Fatal("event stream closed")
		}
		return res.event
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return gossip.Event{}
}

// TestGossipTopicEventsBufferedBeforeFirstRead checks that the event stream
// starts at Subscribe and not at the first call to Events: a caller that joins
// the topic and only then reads still sees the NeighborUp it missed.
func TestGossipTopicEventsBufferedBeforeFirstRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var topic gossip.TopicID
	copy(topic[:], "buffered")

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	serverGossip := gossip.NewGossip(server)
	serverRouter, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		gossip.ALPN: serverGossip.Handler(),
	}, nil)
	if err != nil {
		t.Fatalf("new server router: %v", err)
	}
	defer serverRouter.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	clientGossip := gossip.NewGossip(client)
	clientRouter, err := iroh.NewRouter(client, map[string]iroh.ProtocolHandler{
		gossip.ALPN: clientGossip.Handler(),
	}, nil)
	if err != nil {
		t.Fatalf("new client router: %v", err)
	}
	defer clientRouter.Shutdown(ctx)

	serverTopic, err := serverGossip.Subscribe(ctx, topic, nil)
	if err != nil {
		t.Fatalf("server subscribe: %v", err)
	}
	defer serverTopic.Close()

	serverAddr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	clientTopic, err := clientGossip.Subscribe(ctx, topic, []netaddr.EndpointAddr{serverAddr})
	if err != nil {
		t.Fatalf("client subscribe: %v", err)
	}
	defer clientTopic.Close()

	// Wait for the join with the state-based accessor, which does not consume
	// events, so nothing has read the stream by the time Events is called.
	for len(clientTopic.Neighbors()) == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("client never joined")
		case <-time.After(10 * time.Millisecond):
		}
	}

	if ev := nextEvent(ctx, t, clientTopic); ev.Kind != gossip.NeighborUp {
		t.Fatalf("first event after join = %+v, want NeighborUp", ev)
	}
}
