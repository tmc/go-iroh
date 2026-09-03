//go:build !js && !windows

package mdns

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func reusePortControl(_, _ string, c syscall.RawConn) error {
	var firstErr error
	err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	if err != nil {
		return err
	}
	return firstErr
}
