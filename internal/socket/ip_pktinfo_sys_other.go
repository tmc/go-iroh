//go:build unix && !linux && !darwin

package socket

// sysIPPktinfo matches nothing: the BSDs report an IPv4 destination through
// IP_RECVDSTADDR, which x/net cannot pair with an IPv4 source on send. IPv6
// packet info (RFC 3542) is recognized.
const sysIPPktinfo = -1
