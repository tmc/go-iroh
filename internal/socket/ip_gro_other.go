//go:build !linux

package socket

import "net"

func enableGRO(*net.UDPConn) bool { return false }

const groOOBSize = 0

func groSegmentSize([]byte) int { return 0 }
