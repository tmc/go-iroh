//go:build linux

package udp

import (
	"errors"
	"net"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

type gsoSendConn struct {
	*basicConn
	conn gsoCapablePacketConn
}

func newGSOSendConn(conn gsoCapablePacketConn, supportsDF bool) (Conn, bool, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if !isGSOEnabled(raw) {
		return nil, false, nil
	}
	return &gsoSendConn{
		basicConn: &basicConn{PacketConn: conn, supportsDF: supportsDF},
		conn:      conn,
	}, true, nil
}

func (c *gsoSendConn) WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	if ecn != protocol.ECNUnsupported {
		panic("cannot use ECN with a GSO send connection")
	}
	if gsoSize == 0 {
		return c.basicConn.WritePacket(b, addr, packetInfoOOB, 0, ecn)
	}
	if len(b) < minGSOSegments*int(gsoSize) {
		return c.writePackets(b, addr, packetInfoOOB, int(gsoSize), ecn)
	}
	oob := packetInfoOOB
	oob = appendUDPSegmentSizeMsg(oob, gsoSize)
	n, _, err := c.conn.WriteMsgUDP(b, oob, addr.(*net.UDPAddr))
	return n, err
}

func (c *gsoSendConn) writePackets(b []byte, addr net.Addr, packetInfoOOB []byte, size int, ecn protocol.ECN) (int, error) {
	written := 0
	for len(b) > 0 {
		n := min(len(b), size)
		m, err := c.basicConn.WritePacket(b[:n], addr, packetInfoOOB, 0, ecn)
		written += m
		if err != nil || m != n {
			return written, err
		}
		b = b[n:]
	}
	return written, nil
}

func (c *gsoSendConn) Capabilities() Capabilities {
	return Capabilities{DF: c.supportsDF, GSO: true}
}
