//go:build js

package iroh

import "net/netip"

// hostInterfaceAddrs returns nil in js/wasm builds where direct UDP interface
// enumeration is unavailable.
func hostInterfaceAddrs() []netip.Addr { return nil }
