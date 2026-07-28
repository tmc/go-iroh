package netreport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	tls "github.com/tmc/go-iroh/internal/itls/tls"
	quic "github.com/tmc/go-iroh/internal/qng"
)

func TestQADWireConstants(t *testing.T) {
	// These must match iroh-relay/src/quic.rs exactly or QAD connections will
	// not interoperate with Rust relays.
	if alpnQAD != "/iroh-qad/0" {
		t.Errorf("alpnQAD = %q, want /iroh-qad/0 (quic.rs:10)", alpnQAD)
	}
	if qadCloseCode != 1 {
		t.Errorf("qadCloseCode = %d, want 1 (quic.rs:12)", qadCloseCode)
	}
	if string(qadCloseReason) != "finished" {
		t.Errorf("qadCloseReason = %q, want finished (quic.rs:14)", qadCloseReason)
	}
	if defaultRelayQuicPort != 7842 {
		t.Errorf("defaultRelayQuicPort = %d, want 7842 (defaults.rs:7)", defaultRelayQuicPort)
	}
	if qadInitialRTT != 111*time.Millisecond {
		t.Errorf("qadInitialRTT = %v, want 111ms (quic.rs:293)", qadInitialRTT)
	}
	if qadKeepAlive != 25*time.Second {
		t.Errorf("qadKeepAlive = %v, want 25s (quic.rs:297)", qadKeepAlive)
	}
	if qadMaxIdle != 35*time.Second {
		t.Errorf("qadMaxIdle = %v, want 35s (quic.rs:298)", qadMaxIdle)
	}
}

func TestObservedAddrNoConnectionFallback(t *testing.T) {
	// With no connection, observedAddr must report ErrExtensionNotNegotiated
	// rather than fabricate an address.
	qad := &qadConn{}
	_, err := qad.observedAddr(context.Background())
	if !errors.Is(err, ErrExtensionNotNegotiated) {
		t.Errorf("observedAddr err = %v, want ErrExtensionNotNegotiated", err)
	}
}

// TestQADLoopbackHandshake proves the QAD client can complete a real QUIC
// handshake over the QAD ALPN against a loopback qng listener, read a non-zero
// RTT, and close gracefully with the QAD close code and reason. The server does
// not advertise observed-address reports, so the probe is latency-only.
func TestQADLoopbackHandshake(t *testing.T) {
	// A relay presents a standard WebPKI (X.509) certificate for QAD, not a raw
	// public key, so the QAD client uses ordinary chain verification (skipped
	// here for the self-signed test cert). Mirror that on the loopback server.
	serverCert := selfSignedCert(t)
	serverTLS := &tls.Config{
		Certificates:           []tls.Certificate{serverCert},
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{alpnQAD},
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	ln, err := quic.Listen(udpConn, serverTLS, &quic.Config{
		MaxIdleTimeout:  qadMaxIdle,
		KeepAlivePeriod: qadKeepAlive,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err == nil {
			accepted <- struct{}{}
			// Keep the connection alive until the client closes it.
			<-conn.Context().Done()
		}
	}()

	serverAddr := netip.MustParseAddrPort(udpConn.LocalAddr().String())
	qad, err := newQADClient(serverAddr, "relay.iroh.invalid",
		&tls.Config{InsecureSkipVerify: true},
		&quic.Config{
			MaxIdleTimeout:  qadMaxIdle,
			KeepAlivePeriod: qadKeepAlive,
		})
	if err != nil {
		t.Fatalf("newQADClient: %v", err)
	}

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept QAD connection")
	}

	// RTT for path 0 should be available (non-negative); other paths return 0.
	if rtt := qad.rtt(0); rtt < 0 {
		t.Errorf("rtt(0) = %v, want >= 0", rtt)
	}
	if rtt := qad.rtt(1); rtt != 0 {
		t.Errorf("rtt(1) = %v, want 0 (no multipath)", rtt)
	}

	// No observed-address report was negotiated by the server.
	if _, err := qad.observedAddr(ctx); !errors.Is(err, ErrExtensionNotNegotiated) {
		t.Errorf("observedAddr err = %v, want ErrExtensionNotNegotiated", err)
	}

	// Graceful close with the QAD close code and reason must not error.
	if err := qad.close(qadCloseCode, qadCloseReason); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestQADObservedAddrLoopback(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
	}{
		{"ipv4", net.IPv4(127, 0, 0, 1)},
		{"ipv6", net.IPv6loopback},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, stop := startLoopbackQADWithConfig(t, tt.ip, &quic.Config{
				SendObservedAddressReports: true,
				KeepAlivePeriod:            100 * time.Millisecond,
				MaxIdleTimeout:             qadMaxIdle,
			})
			defer stop()

			qad, err := newQADClient(addr, "relay.iroh.invalid",
				&tls.Config{InsecureSkipVerify: true},
				&quic.Config{
					ReceiveObservedAddressReports: true,
					KeepAlivePeriod:               100 * time.Millisecond,
					MaxIdleTimeout:                qadMaxIdle,
				})
			if err != nil {
				t.Fatalf("newQADClient: %v", err)
			}
			defer qad.close(qadCloseCode, qadCloseReason)

			// Single call, no polling: observedAddr must wait for the report.
			got, err := qad.observedAddr(context.Background())
			if err != nil {
				t.Fatalf("observedAddr: %v", err)
			}
			if tt.ip.To4() != nil && !got.Addr().Is4() {
				t.Fatalf("observedAddr = %v, want IPv4", got)
			}
			if tt.ip.To4() == nil && !got.Addr().Is6() {
				t.Fatalf("observedAddr = %v, want IPv6", got)
			}
			if got.Port() == 0 {
				t.Fatalf("observedAddr = %v, want non-zero port", got)
			}
		})
	}
}

// selfSignedCert builds a self-signed ed25519 X.509 certificate for the
// loopback QAD server.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.iroh.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"relay.iroh.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// TestQADObservedAddrNotNegotiatedReturnsPromptly pins the other half of the
// wait: a relay that never reports must not cost the probe its whole budget.
func TestQADObservedAddrNotNegotiatedReturnsPromptly(t *testing.T) {
	addr, stop := startLoopbackQADWithConfig(t, net.IPv4(127, 0, 0, 1), &quic.Config{
		// Address discovery deliberately not offered by the server.
		KeepAlivePeriod: 100 * time.Millisecond,
		MaxIdleTimeout:  qadMaxIdle,
	})
	defer stop()

	qad, err := newQADClient(addr, "relay.iroh.invalid",
		&tls.Config{InsecureSkipVerify: true},
		&quic.Config{
			ReceiveObservedAddressReports: true,
			KeepAlivePeriod:               100 * time.Millisecond,
			MaxIdleTimeout:                qadMaxIdle,
		})
	if err != nil {
		t.Fatalf("newQADClient: %v", err)
	}
	defer qad.close(qadCloseCode, qadCloseReason)

	start := time.Now()
	if _, err := qad.observedAddr(context.Background()); !errors.Is(err, ErrExtensionNotNegotiated) {
		t.Fatalf("observedAddr err = %v, want ErrExtensionNotNegotiated", err)
	}
	if elapsed := time.Since(start); elapsed >= qadObservedAddrWait {
		t.Fatalf("waited %v for a relay that never reports; want a prompt return", elapsed)
	}
}
