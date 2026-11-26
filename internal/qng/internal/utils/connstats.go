package utils

import "sync/atomic"

// ConnectionStats stores stats for the connection. See the public
// ConnectionStats struct in connection.go for more information
type ConnectionStats struct {
	CongestionWindow atomic.Uint64

	BytesSent       atomic.Uint64
	PacketsSent     atomic.Uint64
	BytesReceived   atomic.Uint64
	PacketsReceived atomic.Uint64
	BytesLost       atomic.Int64
	PacketsLost     atomic.Int64
	PTOs            atomic.Uint64
	SpuriousLosses  atomic.Uint64
	PathCIDsBlocked atomic.Uint64
}
