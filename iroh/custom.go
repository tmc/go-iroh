package iroh

import (
	"context"

	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/netaddr"
)

// CustomDatagram is one datagram received by a [CustomTransport].
type CustomDatagram struct {
	Remote   netaddr.CustomAddr
	Local    netaddr.CustomAddr
	HasLocal bool
	Data     []byte
}

// CustomTransport is a pluggable endpoint transport for custom addresses.
// Implementations own their wire format and exchange datagrams using
// [netaddr.CustomAddr] values advertised in endpoint addresses.
type CustomTransport interface {
	// Serve runs the transport until ctx is done, passing each received
	// datagram to recv.
	//
	// recv reports whether the datagram was taken. A false result means the
	// datagram was dropped, most often because the receive queue was full
	// under a burst; it is not a signal to stop. Serve must keep serving and
	// return only when ctx is done, so `if !recv(d) { return }` tears the
	// transport down on the first burst. Shutdown is reported through ctx
	// alone, which is cancelled before the queue stops being drained.
	Serve(ctx context.Context, recv func(CustomDatagram) bool)

	// Send sends p to remote. local is nil when qng did not select a specific
	// local custom address for the path.
	Send(remote netaddr.CustomAddr, local *netaddr.CustomAddr, p []byte) bool
}

// AdvertisingCustomTransport is a custom transport that can publish local
// addresses in [Endpoint.Addr] and [Endpoint.WatchAddr].
//
// Existing [CustomTransport] implementations do not need to implement this
// interface. Transports that do implement it must return only address material
// that peers can dial through the same transport id.
type AdvertisingCustomTransport interface {
	CustomTransport

	// LocalCustomAddrs returns the local custom addresses this endpoint should
	// advertise. The returned slice is copied by the endpoint.
	LocalCustomAddrs(context.Context) ([]netaddr.CustomAddr, error)
}

type customTransportAdapter struct {
	t CustomTransport
}

func (a customTransportAdapter) Serve(ctx context.Context, recv func(socket.CustomDatagram) bool) {
	a.t.Serve(ctx, func(d CustomDatagram) bool {
		return recv(socket.CustomDatagram{
			Remote:   d.Remote,
			Local:    d.Local,
			HasLocal: d.HasLocal,
			Data:     d.Data,
		})
	})
}

func (a customTransportAdapter) Send(remote netaddr.CustomAddr, local *netaddr.CustomAddr, p []byte) bool {
	return a.t.Send(remote, local, p)
}

func customTransportAdapters(custom []CustomTransport) []socket.CustomTransport {
	if len(custom) == 0 {
		return nil
	}
	out := make([]socket.CustomTransport, 0, len(custom))
	for _, t := range custom {
		if t != nil {
			out = append(out, customTransportAdapter{t: t})
		}
	}
	return out
}

func customTransportLocalAddrs(ctx context.Context, custom []CustomTransport) []netaddr.CustomAddr {
	var out []netaddr.CustomAddr
	for _, t := range custom {
		a, ok := t.(AdvertisingCustomTransport)
		if !ok {
			continue
		}
		addrs, err := a.LocalCustomAddrs(ctx)
		if err != nil {
			continue
		}
		out = append(out, addrs...)
	}
	return out
}
