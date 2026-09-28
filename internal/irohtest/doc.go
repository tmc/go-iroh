// Package irohtest runs real iroh endpoints on an in-memory network, for
// tests that need several peers, impaired links, or misbehaving peers.
//
// Every peer is an ordinary [iroh.Endpoint] bound without IP, relay, or
// net-report work. Its only transport is an in-memory [iroh.CustomTransport]
// that delivers datagrams over channels, so a [Net] opens no sockets and
// every goroutine it starts blocks only on channels and timers. That makes a
// Net usable inside a [testing/synctest] bubble, where time is virtual:
// handshake and idle timeouts elapse instantly, a stall shows up as an exact
// duration, and a hang shows up as a deadlock.
//
// Each direction of a link can be impaired with an [Impairment]: loss,
// delay and jitter, duplication, a rate limit, a stall after a number of
// datagrams, or an outright cut. Loss and jitter draw from a PRNG seeded per
// link, so a failing sequence reproduces.
//
// A typical isolation test runs a server, a peer that misbehaves, and a peer
// that must still be served within a budget:
//
//	synctest.Test(t, func(t *testing.T) {
//		n := irohtest.NewNet(t)
//		srv := n.Peer(iroh.WithALPNs(alpn))
//		bad := n.Peer()
//		bad.Impair(irohtest.Impairment{StallAfter: 2}) // ClientHello, then silence
//		go bad.Connect(ctx, srv.Addr(), alpn)
//		good := n.Peer()
//		irohtest.Within(t, time.Second, func(ctx context.Context) error {
//			_, err := good.Connect(ctx, srv.Addr(), alpn)
//			return err
//		})
//	})
//
// Package irohtest imports package iroh, so iroh's own internal tests
// cannot use it; its external (iroh_test) tests and every other package can.
package irohtest
