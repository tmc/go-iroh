package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
)

func TestConfigInitialRTT(t *testing.T) {
	if got := populateConfig(nil).InitialRTT; got != utils.DefaultInitialRTT {
		t.Fatalf("default InitialRTT = %v, want %v", got, utils.DefaultInitialRTT)
	}

	const want = 111 * time.Millisecond
	cfg := populateConfig(&Config{InitialRTT: want})
	if cfg.InitialRTT != want {
		t.Fatalf("InitialRTT = %v, want %v", cfg.InitialRTT, want)
	}
}

func TestConfigInitialRTTAppliesBeforeHandshake(t *testing.T) {
	const want = 111 * time.Millisecond
	c := &Conn{
		config:      populateConfig(&Config{InitialRTT: want}),
		ctx:         context.Background(),
		conn:        configTestSendConn{},
		perspective: protocol.PerspectiveClient,
		logger:      utils.DefaultLogger,
	}
	c.preSetup()
	if got := c.rttStats.SmoothedRTT(); got != want {
		t.Fatalf("SmoothedRTT = %v, want %v", got, want)
	}
	if got := c.rttStats.LatestRTT(); got != want {
		t.Fatalf("LatestRTT = %v, want %v", got, want)
	}
}

type configTestSendConn struct{}

func (configTestSendConn) Write([]byte, uint16, protocol.ECN) error   { return nil }
func (configTestSendConn) WriteTo([]byte, net.Addr, packetInfo) error { return nil }
func (configTestSendConn) Close() error                               { return nil }
func (configTestSendConn) LocalAddr() net.Addr                        { return &net.UDPAddr{} }
func (configTestSendConn) RemoteAddr() net.Addr                       { return &net.UDPAddr{} }
func (configTestSendConn) ChangeRemoteAddr(net.Addr, packetInfo)      {}
func (configTestSendConn) capabilities() connCapabilities             { return connCapabilities{} }
