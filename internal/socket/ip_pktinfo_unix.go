//go:build unix

package socket

import (
	"encoding/binary"
	"net/netip"

	"golang.org/x/sys/unix"
)

// Sizes of struct in_pktinfo and struct in6_pktinfo, laid out the same on
// every platform that has them.
const (
	sizeofInet4Pktinfo = 12 // uint32 ifindex, in_addr spec_dst, in_addr addr
	sizeofInet6Pktinfo = 20 // in6_addr addr, uint32 ifindex
)

// parsePacketInfo extracts the destination address of a received datagram
// from its control messages without allocating. Both families are
// recognized: the level the kernel uses depends on the socket and the
// traffic, not on the bind address alone.
func parsePacketInfo(oob []byte) (localAddr, bool) {
	for len(oob) > 0 {
		h, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return localAddr{}, false
		}
		switch {
		case h.Level == unix.IPPROTO_IP && h.Type == sysIPPktinfo && len(data) >= sizeofInet4Pktinfo:
			return localAddr{
				addr:    netip.AddrFrom4([4]byte(data[8:12])),
				ifIndex: int(binary.NativeEndian.Uint32(data[0:4])),
			}, true
		case h.Level == unix.IPPROTO_IPV6 && h.Type == unix.IPV6_PKTINFO && len(data) >= sizeofInet6Pktinfo:
			a := netip.AddrFrom16([16]byte(data[0:16]))
			ifIndex := 0
			if a.IsLinkLocalUnicast() {
				ifIndex = int(binary.NativeEndian.Uint32(data[16:20]))
			}
			return localAddr{addr: a.Unmap(), ifIndex: ifIndex}, true
		}
		oob = rest
	}
	return localAddr{}, false
}
