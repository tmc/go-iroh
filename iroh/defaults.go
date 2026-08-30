package iroh

import (
	"time"

	"github.com/tmc/go-iroh/internal/socket"
)

// Wire and behavioral constants shared with the Rust iroh implementation.
// Values are cited to the iroh source so they can be re-verified on upgrades.

const (
	// HeartbeatInterval is the QUIC keep-alive / path keep-alive interval.
	// iroh/src/socket.rs HEARTBEAT_INTERVAL.
	HeartbeatInterval = 5 * time.Second

	// PathMaxIdleTimeout is the idle timeout for a non-relay (direct) path.
	// iroh/src/socket.rs PATH_MAX_IDLE_TIMEOUT.
	PathMaxIdleTimeout = socket.PathMaxIdleTimeout

	// RelayPathMaxIdleTimeout is the idle timeout for a relay path.
	// iroh/src/socket.rs RELAY_PATH_MAX_IDLE_TIMEOUT.
	RelayPathMaxIdleTimeout = socket.RelayPathMaxIdleTimeout

	// MaxMultipathPaths is the QUIC multipath path limit (transport parameter).
	// iroh/src/socket.rs MAX_MULTIPATH_PATHS.
	MaxMultipathPaths = 8

	// MaxQNTAddresses is the maximum number of remote NAT-traversal addresses
	// (transport parameter). iroh/src/socket.rs MAX_QNT_ADDRESSES.
	MaxQNTAddresses = 32
)

// ConnectTimeout bounds a single Connect call when no reachable address
// succeeds. iroh/src/endpoint.rs documents a 10s connect timeout.
const ConnectTimeout = 10 * time.Second

// dialAttemptTimeout bounds how long a dial waits for an unproven target's
// handshake before trying the next one. See Endpoint.connectEarly.
const dialAttemptTimeout = 3 * time.Second
