//go:build !js

package iroh

import (
	"net"
	"net/netip"
)

// hostInterfaceAddrs returns the host's currently active unicast interface IP
// addresses. When non-loopback addresses are available, loopback addresses are
// omitted; when no non-loopback interface is up, loopback addresses are
// returned so local peers remain reachable (matching upstream
// n0-computer/iroh#4605).
func hostInterfaceAddrs() []netip.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var nonLoopback, loopback []netip.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
				continue
			}
			if addr.IsLoopback() {
				loopback = append(loopback, addr)
			} else {
				nonLoopback = append(nonLoopback, addr)
			}
		}
	}
	if len(nonLoopback) > 0 {
		return nonLoopback
	}
	return loopback
}
