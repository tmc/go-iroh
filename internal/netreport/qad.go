package netreport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	tls "github.com/tmc/go-iroh/internal/itls/tls"
	quic "github.com/tmc/go-iroh/internal/qng"
)

// ErrExtensionNotNegotiated is returned by [qadConn.observedAddr] when no
// reflexive address is available: either QUIC Address Discovery was not
// negotiated on the connection, or no OBSERVED_ADDRESS report arrived within
// [qadObservedAddrWait]. The forked quic-go implements the extension (slice
// X3); see the package doc.
var ErrExtensionNotNegotiated = errors.New("netreport: quic observed-address extension not negotiated")

// qadConn is a client-side QUIC Address Discovery connection to a relay. It
// mirrors the QAD client in iroh-relay/src/quic.rs: it advertises the
// receive-only address-discovery role so the relay reports our reflexive
// address, and exposes both the connection latency and the observed address.
//
// The zero value is not usable; construct one with [newQADClient].
type qadConn struct {
	conn      *quic.Conn
	transport *quic.Transport
	udpConn   net.PacketConn
	// ownsTransport reports whether close should also tear down transport and
	// udpConn (true when newQADClient created its own UDP socket).
	ownsTransport bool
}

// newQADClient dials a QAD connection to dialAddr, presenting the QAD ALPN and
// using host as the TLS server name. baseTLS, if non-nil, supplies the TLS
// verification policy (a relay presents a standard WebPKI certificate, so QAD
// uses ordinary chain verification); tests pass a config with
// InsecureSkipVerify to trust a self-signed relay. quicCfg, if non-nil,
// overrides the QAD transport defaults (keep-alive, idle timeout).
//
// It returns once the QUIC handshake completes. The caller must close the
// returned connection with [qadConn.close].
func newQADClient(dialAddr netip.AddrPort, host string, baseTLS *tls.Config, quicCfg *quic.Config) (*qadConn, error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: udpConn}

	cfg := quicCfg
	if cfg == nil {
		cfg = defaultQADConfig()
	}

	ctx, cancel := context.WithTimeout(context.Background(), probesTimeout)
	defer cancel()

	conn, err := tr.Dial(ctx, net.UDPAddrFromAddrPort(dialAddr), qadTLSConfig(host, baseTLS), cfg)
	if err != nil {
		tr.Close()
		udpConn.Close()
		return nil, err
	}
	return &qadConn{
		conn:          conn,
		transport:     tr,
		udpConn:       udpConn,
		ownsTransport: true,
	}, nil
}

// qadTLSConfig builds the TLS config for a QAD client connection from base,
// forcing TLS 1.3, the QAD ALPN, and host as the server name. base supplies the
// certificate-verification policy; if nil the relay's WebPKI certificate is
// verified against the system roots. iroh-relay/src/quic.rs:273.
func qadTLSConfig(host string, base *tls.Config) *tls.Config {
	cfg := &tls.Config{}
	if base != nil {
		cfg = base.Clone()
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.NextProtos = []string{alpnQAD}
	cfg.ServerName = host
	return cfg
}

// defaultQADConfig returns the QAD transport configuration matching
// iroh-relay/src/quic.rs:286-301.
//
// ReceiveObservedAddressReports advertises the address-discovery role
// (receive-only) so a QAD relay reports our reflexive address, mirroring
// transport.receive_observed_address_reports(true) (quic.rs:294). Initial RTT,
// keep-alive, and idle timeout are set as in Rust.
func defaultQADConfig() *quic.Config {
	return &quic.Config{
		InitialRTT:                    qadInitialRTT,
		KeepAlivePeriod:               qadKeepAlive,
		MaxIdleTimeout:                qadMaxIdle,
		ReceiveObservedAddressReports: true,
	}
}

// rtt returns the connection round-trip time for pathID. Because the forked
// quic-go has no multipath, only path 0 exists; any other pathID returns zero.
// The value is qng's smoothed RTT estimate, matching Connection::rtt
// (iroh-relay/src/quic.rs:345 uses rtt(PathId::ZERO)).
func (qad *qadConn) rtt(pathID uint64) time.Duration {
	if pathID != 0 {
		return 0
	}
	return qad.conn.ConnectionStats().SmoothedRTT
}

// observedAddr returns the host's reflexive address as reported by the relay
// via QUIC Address Discovery, waiting up to [qadObservedAddrWait] for the
// first report — relays send OBSERVED_ADDRESS after the handshake the dial
// waits for, so an immediate read always loses that race. Returns
// [ErrExtensionNotNegotiated], without waiting, when the relay did not
// negotiate address discovery, and when no report arrives in time.
func (qad *qadConn) observedAddr(ctx context.Context) (netip.AddrPort, error) {
	if qad.conn == nil {
		return netip.AddrPort{}, ErrExtensionNotNegotiated
	}
	ctx, cancel := context.WithTimeout(ctx, qadObservedAddrWait)
	defer cancel()
	if addr, ok := qad.conn.AwaitObservedAddr(ctx); ok {
		return addr, nil
	}
	return netip.AddrPort{}, ErrExtensionNotNegotiated
}

// close gracefully closes the QAD connection with the given application error
// code and reason, then releases the transport and socket. iroh closes with
// code [qadCloseCode] (1) and reason [qadCloseReason] ("finished");
// iroh-relay/src/quic.rs:347.
func (qad *qadConn) close(code uint64, reason []byte) error {
	err := qad.conn.CloseWithError(quic.ApplicationErrorCode(code), string(reason))
	if qad.ownsTransport {
		qad.transport.Close()
		qad.udpConn.Close()
	}
	return err
}
