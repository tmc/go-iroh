//go:build linux

package socket

import (
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

// enableGRO turns on UDP_GRO so one recvmsg can return many coalesced
// datagrams from the same peer.
func enableGRO(conn *net.UDPConn) bool {
	rc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); err != nil {
		return false
	}
	return serr == nil
}

const groOOBSize = 64

// groSegmentSize returns the UDP_GRO segment size in oob, or 0.
func groSegmentSize(oob []byte) int {
	for len(oob) > 0 {
		hdr, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return 0
		}
		if hdr.Level == unix.IPPROTO_UDP && hdr.Type == unix.UDP_GRO && len(data) >= 4 {
			return int(int32(binary.NativeEndian.Uint32(data)))
		}
		oob = rest
	}
	return 0
}
