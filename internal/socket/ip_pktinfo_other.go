//go:build !unix

package socket

// parsePacketInfo reports no arrival address: x/net delivers no packet info
// here, so the transport never asks for one.
func parsePacketInfo([]byte) (localAddr, bool) { return localAddr{}, false }
