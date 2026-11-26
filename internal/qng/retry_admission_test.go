package quic

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	tls "github.com/tmc/go-iroh/internal/itls/tls"
	"github.com/tmc/go-iroh/internal/qng/internal/handshake"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/qlogwriter"
)

func TestVerifySourceAddressRetriesBeforeConnectionConstruction(t *testing.T) {
	serverTLS, clientTLS, _, _, _, _ := multipathTLSConfigs(t)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	var verifyCalls atomic.Int32
	var newConnCalls atomic.Int32
	origNewConn := newConnection
	newConnection = func(
		ctx context.Context,
		cancel context.CancelCauseFunc,
		sendConn sendConn,
		connRunner connRunner,
		origDestConnID protocol.ConnectionID,
		retrySrcConnID protocol.ConnectionID,
		clientDestConnID protocol.ConnectionID,
		destConnID protocol.ConnectionID,
		srcConnID protocol.ConnectionID,
		connIDGenerator ConnectionIDGenerator,
		statelessResetter *statelessResetter,
		config *Config,
		tlsConf *tls.Config,
		tokenGenerator *handshake.TokenGenerator,
		clientAddrValidated bool,
		createdAt time.Duration,
		tracer qlogwriter.Trace,
		logger utils.Logger,
		v protocol.Version,
	) *wrappedConn {
		if verifyCalls.Load() == 0 {
			t.Error("newConnection called before VerifySourceAddress")
		}
		if !retrySrcConnID.Valid() {
			t.Error("newConnection retrySrcConnID invalid, want Retry source connection id")
		}
		if !clientAddrValidated {
			t.Error("newConnection clientAddrValidated = false, want true after Retry")
		}
		newConnCalls.Add(1)
		return origNewConn(ctx, cancel, sendConn, connRunner, origDestConnID, retrySrcConnID, clientDestConnID, destConnID, srcConnID, connIDGenerator, statelessResetter, config, tlsConf, tokenGenerator, clientAddrValidated, createdAt, tracer, logger, v)
	}
	t.Cleanup(func() { newConnection = origNewConn })

	tr := &Transport{
		Conn: udpConn,
		VerifySourceAddress: func(net.Addr) bool {
			verifyCalls.Add(1)
			return true
		},
	}
	ln, err := tr.ListenEarly(serverTLS, &Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	closeAccepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		if !conn.RemoteAddrValidated() {
			t.Error("accepted connection RemoteAddrValidated = false, want true")
		}
		select {
		case <-closeAccepted:
		case <-ctx.Done():
			done <- ctx.Err()
			return
		}
		_ = conn.CloseWithError(0, "")
		done <- nil
	}()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()
	clientConn, err := DialEarly(ctx, clientUDP, udpConn.LocalAddr(), clientTLS, &Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.CloseWithError(0, "")
	close(closeAccepted)

	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if verifyCalls.Load() == 0 {
		t.Fatal("VerifySourceAddress was not called")
	}
	if newConnCalls.Load() != 1 {
		t.Fatalf("newConnection calls = %d, want 1", newConnCalls.Load())
	}
}
