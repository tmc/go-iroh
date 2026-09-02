//go:build !js

package iroh

import (
	"net"
	"net/netip"
)

func bindPacketConn(c config, bind netip.AddrPort) (*net.UDPConn, error) {
	if c.disableIP {
		return nil, nil
	}
	// Bind an IPv4 address on an IPv4 socket. net.ListenUDP("udp", ...) gives
	// 0.0.0.0 a dual-stack socket whose LocalAddr reports [::], so a caller
	// that asked for IPv4 would get an IPv6 address back from
	// Endpoint.LocalAddr. The default bind address is the IPv6 unspecified
	// address, so the default socket stays dual-stack.
	network := "udp"
	if bind.Addr().Is4() {
		network = "udp4"
	}
	return net.ListenUDP(network, net.UDPAddrFromAddrPort(bind))
}
