//go:build !unix

package socket

// sysIPPktinfo matches nothing: there is no packet info to parse here.
const sysIPPktinfo = -1

// parsePacketInfo reports no arrival address: x/net delivers no packet info
// here, so the transport never asks for one.
func parsePacketInfo([]byte) (localAddr, bool) { return localAddr{}, false }
