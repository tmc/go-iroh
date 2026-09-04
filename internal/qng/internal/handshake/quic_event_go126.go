//go:build go1.26

package handshake

import tls "github.com/tmc/go-iroh/internal/itls/tls"

const quicErrorEvent tls.QUICEventKind = tls.QUICErrorEvent

func extractQUICEventError(ev tls.QUICEvent) error {
	return ev.Err
}
