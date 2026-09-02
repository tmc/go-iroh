package iroh

import (
	"context"
	"iter"
	"sync"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// MemoryProvenance is the default provenance string for [MemoryLookup] items.
const MemoryProvenance = "memory_lookup"

// MemoryLookup is an in-memory [AddressResolver] for addressing information added
// out-of-band, such as from an endpoint ticket. Applications add and remove
// entries; resolution returns the stored info for an id.
//
// The zero value is not usable; create one with [NewMemoryLookup] or
// [NewMemoryLookupWithProvenance]. A MemoryLookup is safe for concurrent use.
//
// It is the Go analog of iroh's MemoryLookup.
type MemoryLookup struct {
	mu         sync.RWMutex
	endpoints  map[key.EndpointID]storedInfo
	provenance string
}

type storedInfo struct {
	data        dns.EndpointData
	lastUpdated time.Time
}

// NewMemoryLookup returns an empty MemoryLookup using [MemoryProvenance].
func NewMemoryLookup() *MemoryLookup {
	return NewMemoryLookupWithProvenance(MemoryProvenance)
}

// NewMemoryLookupWithProvenance returns an empty MemoryLookup whose resolved
// [Item]s report the given provenance.
func NewMemoryLookupWithProvenance(provenance string) *MemoryLookup {
	return &MemoryLookup{
		endpoints:  make(map[key.EndpointID]storedInfo),
		provenance: provenance,
	}
}

// MemoryLookupFromInfo returns a MemoryLookup pre-populated with infos.
func MemoryLookupFromInfo(infos ...dns.EndpointInfo) *MemoryLookup {
	m := NewMemoryLookup()
	for _, info := range infos {
		m.AddEndpointInfo(info)
	}
	return m
}

// SetEndpointInfo replaces all stored info for info.ID, returning the previous
// [dns.EndpointData] and whether an entry existed.
func (m *MemoryLookup) SetEndpointInfo(info dns.EndpointInfo) (dns.EndpointData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, existed := m.endpoints[info.ID]
	m.endpoints[info.ID] = storedInfo{data: info.Data, lastUpdated: time.Now()}
	return prev.data, existed
}

// AddEndpointInfo merges info into the stored entry for info.ID: new direct
// addresses are appended and the user data is overwritten. If no entry exists,
// one is created.
func (m *MemoryLookup) AddEndpointInfo(info dns.EndpointInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.endpoints[info.ID]
	if !ok {
		m.endpoints[info.ID] = storedInfo{data: info.Data, lastUpdated: time.Now()}
		return
	}
	existing.data.AddAddrs(info.Data.Addrs()...)
	existing.data.SetUserData(info.Data.UserData())
	existing.lastUpdated = time.Now()
	m.endpoints[info.ID] = existing
}

// AddEndpointAddr is a convenience wrapper for [MemoryLookup.AddEndpointInfo]
// taking an [netaddr.EndpointAddr].
func (m *MemoryLookup) AddEndpointAddr(addr netaddr.EndpointAddr) {
	m.AddEndpointInfo(dns.EndpointInfoFromAddr(addr))
}

// GetEndpointInfo returns the stored info for id and whether it exists.
func (m *MemoryLookup) GetEndpointInfo(id key.EndpointID) (dns.EndpointInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, ok := m.endpoints[id]
	if !ok {
		return dns.EndpointInfo{}, false
	}
	return dns.EndpointInfo{ID: id, Data: info.data}, true
}

// RemoveEndpointInfo removes and returns the info for id, and whether it
// existed.
func (m *MemoryLookup) RemoveEndpointInfo(id key.EndpointID) (dns.EndpointInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, ok := m.endpoints[id]
	if !ok {
		return dns.EndpointInfo{}, false
	}
	delete(m.endpoints, id)
	return dns.EndpointInfo{ID: id, Data: info.data}, true
}

// Resolve returns the stored info for id, or an empty sequence if there is no
// entry.
func (m *MemoryLookup) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[Item, error] {
	m.mu.RLock()
	info, ok := m.endpoints[id]
	m.mu.RUnlock()
	if !ok {
		return func(yield func(Item, error) bool) {}
	}
	lastUpdated := uint64(info.lastUpdated.UnixMicro())
	item := NewItem(dns.EndpointInfo{ID: id, Data: info.data}, m.provenance, &lastUpdated)
	return func(yield func(Item, error) bool) {
		if ctx.Err() == nil {
			yield(item, nil)
		}
	}
}

// FilteredAddressPublisher wraps an [AddressPublisher], applying an
// [AddrFilter] to the data before publishing it to the inner service.
//
// The zero value is not usable; create one with [NewFilteredAddressPublisher].
type FilteredAddressPublisher struct {
	inner  AddressPublisher
	filter AddrFilter
}

// NewFilteredAddressPublisher wraps inner so that published data is filtered by
// f before reaching inner.
func NewFilteredAddressPublisher(inner AddressPublisher, f AddrFilter) FilteredAddressPublisher {
	return FilteredAddressPublisher{inner: inner, filter: f}
}

// Inner returns the wrapped publisher.
func (f FilteredAddressPublisher) Inner() AddressPublisher { return f.inner }

// Publish filters data and publishes it to the inner service.
func (f FilteredAddressPublisher) Publish(data dns.EndpointData) {
	f.inner.Publish(applyFilter(data, f.filter))
}
