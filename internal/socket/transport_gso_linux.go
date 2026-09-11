//go:build linux

package socket

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// WriteMsgUDP writes a possibly segmented datagram. Direct IP destinations use
// the kernel's UDP_SEGMENT path. Other transports receive one datagram per
// segment through the ordinary magic-socket router.
func (m *MagicConn) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	segmentSize := udpSegmentSize(oob)
	if m.sock.IsClosed() {
		return len(p), len(oob), nil
	}
	ap := canonicalAddrPort(addr.AddrPort())
	if m.transports.ip == nil || (!isDefinitelyIP(ap.Addr()) && Classify(ap.Addr()) != KindIP) {
		m.writeMsgSegments(p, addr, segmentSize)
		return len(p), len(oob), nil
	}
	n, oobn, err = m.udp.WriteMsgUDPAddrPort(p, m.transports.ip.withPacketInfo(ap, oob), ap)
	if err == nil {
		for range segmentCount(len(p), segmentSize) {
			m.recordIPSent(ap)
		}
		return n, len(oob), nil
	}
	// EIO on a segmented write is the kernel refusing GSO, not a lost
	// datagram: the caller disables GSO and resends the batch one datagram at
	// a time, and those resends are counted on the ordinary path. Counting
	// here would count them twice.
	if segmentSize > 0 && errors.Is(err, unix.EIO) {
		return n, oobn, err
	}
	m.metrics.blackholed.Add(uint64(segmentCount(len(p), segmentSize)))
	return len(p), len(oob), nil
}

func (m *MagicConn) writeMsgSegments(p []byte, addr *net.UDPAddr, segmentSize int) {
	if segmentSize <= 0 || segmentSize >= len(p) {
		m.WriteTo(p, addr)
		return
	}
	if m.sendRelayBatch(canonicalAddrPort(addr.AddrPort()).Addr(), p, segmentSize) {
		return
	}
	for len(p) > 0 {
		n := min(len(p), segmentSize)
		m.WriteTo(p[:n], addr)
		p = p[n:]
	}
}

func udpSegmentSize(oob []byte) int {
	for len(oob) > 0 {
		header, data, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return 0
		}
		if header.Level == syscall.IPPROTO_UDP && header.Type == unix.UDP_SEGMENT && len(data) >= 2 {
			return int(binary.NativeEndian.Uint16(data))
		}
		oob = remainder
	}
	return 0
}
