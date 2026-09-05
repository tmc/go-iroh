//go:build !js

// Package mdns provides local-network endpoint discovery for go-iroh.
//
// A Discovery advertises endpoint direct addresses on the local multicast DNS
// link and resolves peers advertised by other Discovery values. It implements
// iroh.AddressPublisher and iroh.AddressResolver, so it can be registered with
// iroh.AddressLookupServices.
//
// A Discovery listens and multicasts on both 224.0.0.251 and ff02::fb, so
// peers sharing only an IPv6 link find each other. IPv6 is best effort: a host
// without it works exactly as it did over IPv4 alone. The addresses a packet
// carries are independent of the link it rides: AAAA records travel over IPv4
// too, because an IPv6 address learned over an IPv4 link is still dialable.
//
// The Go API is not stable before v1 and may change in any v0 release.
package mdns
