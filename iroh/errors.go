package iroh

import (
	"errors"
	"fmt"
	"net"

	quic "github.com/tmc/go-iroh/internal/qng"
)

// ApplicationError is an application-defined connection close error.
type ApplicationError struct {
	// Code is the application-defined close code.
	Code uint64
	// Reason is the application-defined close reason.
	Reason string
	// Remote reports whether the peer sent the close.
	Remote bool
}

// Error returns a human-readable close error.
func (e *ApplicationError) Error() string {
	who := "local"
	if e.Remote {
		who = "remote"
	}
	if e.Reason == "" {
		return fmt.Sprintf("application close %d (%s)", e.Code, who)
	}
	return fmt.Sprintf("application close %d (%s): %s", e.Code, who, e.Reason)
}

// Unwrap returns [net.ErrClosed].
func (e *ApplicationError) Unwrap() error { return net.ErrClosed }

// AsApplicationError returns the application close error in err, if any.
func AsApplicationError(err error) (*ApplicationError, bool) {
	var appErr *quic.ApplicationError
	if !errors.As(err, &appErr) {
		return nil, false
	}
	return &ApplicationError{
		Code:   uint64(appErr.ErrorCode),
		Reason: appErr.ErrorMessage,
		Remote: appErr.Remote,
	}, true
}

// ErrTLSHandshakeFailure reports a QUIC handshake that ended in the TLS
// "handshake_failure" alert (alert 40), which a peer sends when it finds no
// acceptable set of handshake parameters. Between iroh endpoints the cause is a
// key-exchange group mismatch: the two [KeyExchangePolicy] values have no group
// in common, so neither side can complete the exchange. The cipher suite and
// the raw-public-key signature algorithm are fixed by the protocol and never
// differ between iroh peers; a peer running another implementation may send the
// same alert for another reason.
//
// [Endpoint.Connect] and [Endpoint.Dial] wrap such a failure so it can be told
// apart from other handshake failures without matching error text:
//
//	if _, err := ep.Connect(ctx, addr, alpn); errors.Is(err, iroh.ErrTLSHandshakeFailure) {
//		// no key exchange group in common; see WithKeyExchangePolicy
//	}
//
// The alert is symmetric: the dialer sees it whether its own policy or the
// peer's was the narrower one.
var ErrTLSHandshakeFailure = errors.New("iroh: tls handshake failure")

// alertHandshakeFailure is the TLS handshake_failure alert (RFC 8446, B.2).
const alertHandshakeFailure = 40

// tlsHandshakeFailure joins err with [ErrTLSHandshakeFailure] when err carries a
// QUIC CRYPTO_ERROR for the handshake_failure alert, and returns err unchanged
// otherwise. The message is err's own, so only errors.Is sees the difference.
func tlsHandshakeFailure(err error) error {
	var te *quic.TransportError
	if !errors.As(err, &te) || !te.ErrorCode.IsCryptoError() {
		return err
	}
	if te.ErrorCode-0x100 != alertHandshakeFailure {
		return err
	}
	return handshakeFailureError{err}
}

// handshakeFailureError adds [ErrTLSHandshakeFailure] to an error chain without
// changing what the error says.
type handshakeFailureError struct{ err error }

func (e handshakeFailureError) Error() string   { return e.err.Error() }
func (e handshakeFailureError) Unwrap() []error { return []error{ErrTLSHandshakeFailure, e.err} }
