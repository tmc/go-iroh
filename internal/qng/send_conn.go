package quic

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write(b []byte, gsoSize uint16, ecn protocol.ECN) error
	WriteTo([]byte, net.Addr, packetInfo) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	ChangeRemoteAddr(addr net.Addr, info packetInfo)

	capabilities() connCapabilities
}

type remoteAddrInfo struct {
	addr net.Addr
	oob  []byte
}

type sconn struct {
	rawConn

	localAddr net.Addr

	remoteAddrInfo atomic.Pointer[remoteAddrInfo]

	logger utils.Logger

	// writeMu serializes writes. A sconn is written from several goroutines:
	// the connection run loop (inline sends, probes, connection-close packets)
	// and the dedicated sendQueue.Run goroutine. They share the gotGSOError and
	// wroteFirstPacket fields and the oob scratch buffer, so writes must not
	// overlap. The mutex is uncontended on the common path and is never held
	// across a blocking operation.
	writeMu     sync.Mutex
	performance sendConnPerformanceCounters

	// If GSO enabled, and we receive a GSO error for this remote address, GSO is disabled.
	gotGSOError bool
	// Used to catch the error sometimes returned by the first sendmsg call on Linux,
	// see https://github.com/golang/go/issues/63322.
	wroteFirstPacket bool
}

var _ sendConn = &sconn{}

func newSendConn(c rawConn, remote net.Addr, info packetInfo, logger utils.Logger) *sconn {
	localAddr := c.LocalAddr()
	if info.addr.IsValid() {
		if udpAddr, ok := localAddr.(*net.UDPAddr); ok {
			addrCopy := *udpAddr
			addrCopy.IP = info.addr.AsSlice()
			localAddr = &addrCopy
		}
	}

	sc := &sconn{
		rawConn:   c,
		localAddr: localAddr,
		logger:    logger,
	}
	sc.remoteAddrInfo.Store(&remoteAddrInfo{
		addr: remote,
		oob:  packetInfoOOB(info),
	})
	return sc
}

func (c *sconn) Write(p []byte, gsoSize uint16, ecn protocol.ECN) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	ai := c.remoteAddrInfo.Load()
	err := c.writePacket(p, ai.addr, ai.oob, gsoSize, ecn)
	if err != nil && isGSOError(err) {
		// disable GSO for future calls
		c.gotGSOError = true
		if c.logger.Debug() {
			c.logger.Debugf("GSO failed when sending to %s", ai.addr)
		}
		// send out the packets one by one
		for len(p) > 0 {
			l := min(len(p), int(gsoSize))
			if err := c.writePacket(p[:l], ai.addr, ai.oob, 0, ecn); err != nil {
				return err
			}
			p = p[l:]
		}
		return nil
	}
	return err
}

func (c *sconn) writePacket(p []byte, addr net.Addr, oob []byte, gsoSize uint16, ecn protocol.ECN) error {
	_, err := c.WritePacket(p, addr, oob, gsoSize, ecn)
	if err != nil && !c.wroteFirstPacket && isPermissionError(err) {
		_, err = c.WritePacket(p, addr, oob, gsoSize, ecn)
	}
	c.wroteFirstPacket = true
	if err == nil {
		c.performance.recordWrite(len(p), gsoSize)
	}
	return err
}

func (c *sconn) WriteTo(b []byte, addr net.Addr, info packetInfo) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.WritePacket(b, addr, info.OOB(), 0, protocol.ECNUnsupported)
	return err
}

func (c *sconn) capabilities() connCapabilities {
	capabilities := c.rawConn.capabilities()
	if capabilities.GSO {
		capabilities.GSO = !c.gotGSOError
	}
	return capabilities
}

func (c *sconn) ChangeRemoteAddr(addr net.Addr, info packetInfo) {
	c.remoteAddrInfo.Store(&remoteAddrInfo{
		addr: addr,
		oob:  packetInfoOOB(info),
	})
}

func packetInfoOOB(info packetInfo) []byte {
	oob := info.OOB()
	// Reserve space for UDP_SEGMENT and ECN control messages.
	n := len(oob)
	return append(oob, make([]byte, 64)...)[:n]
}

func (c *sconn) RemoteAddr() net.Addr { return c.remoteAddrInfo.Load().addr }
func (c *sconn) LocalAddr() net.Addr  { return c.localAddr }
