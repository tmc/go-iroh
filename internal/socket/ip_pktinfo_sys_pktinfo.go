//go:build linux || darwin

package socket

import "golang.org/x/sys/unix"

// sysIPPktinfo is the control message type carrying struct in_pktinfo.
const sysIPPktinfo = unix.IP_PKTINFO
