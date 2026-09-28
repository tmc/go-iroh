//go:build !js

package mdns

// peerCount reports the number of cached peers.
func (d *Discovery) peerCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.peers)
}
