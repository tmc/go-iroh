//go:build !js

// Package mdns provides local-network endpoint discovery for go-iroh.
//
// A Discovery advertises endpoint direct addresses on the local multicast DNS
// link and resolves peers advertised by other Discovery values. It implements
// iroh.AddressPublisher and iroh.AddressResolver, so it can be registered with
// iroh.AddressLookupServices.
//
// The transport is IPv4 only: a Discovery listens on udp4 and multicasts to
// 224.0.0.251, not to ff02::fb, so two peers that share only an IPv6 link do
// not find each other. The addresses it carries are not restricted that way.
// AAAA records ride the IPv4 packets, because an IPv6 address learned over an
// IPv4 link is still dialable.
//
// The Go API is not stable before v1 and may change in any v0 release.
package mdns
