//go:build !linux

package udp

func newGSOSendConn(gsoCapablePacketConn, bool) (Conn, bool, error) {
	return nil, false, nil
}
