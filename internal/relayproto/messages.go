package relayproto

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/tmc/go-iroh/key"
)

// ProtocolVersion is the negotiated relay protocol version for a connection.
type ProtocolVersion int

// Relay protocol versions.
const (
	ProtocolV1 ProtocolVersion = 1
	ProtocolV2 ProtocolVersion = 2
)

// Wire identifiers for the relay protocol versions, sent in the
// Sec-WebSocket-Protocol header.
const (
	protocolV1Wire = "iroh-relay-v1"
	protocolV2Wire = "iroh-relay-v2"
)

// SupportedProtocolVersions returns the wire identifiers of all supported
// protocol versions, newest first (the order offered to a relay server).
func SupportedProtocolVersions() []string {
	return []string{protocolV2Wire, protocolV1Wire}
}

// WireString returns the wire identifier for v.
func (v ProtocolVersion) WireString() string {
	switch v {
	case ProtocolV1:
		return protocolV1Wire
	case ProtocolV2:
		return protocolV2Wire
	default:
		return ""
	}
}

// ParseProtocolVersion parses a protocol version from its wire identifier.
func ParseProtocolVersion(s string) (ProtocolVersion, bool) {
	switch s {
	case protocolV1Wire:
		return ProtocolV1, true
	case protocolV2Wire:
		return ProtocolV2, true
	default:
		return 0, false
	}
}

// Status is a one-way relay-to-client message declaring the connection health.
type Status uint8

const (
	// StatusHealthy reports the connection recovered from previous problems.
	StatusHealthy Status = 0
	// StatusSameEndpointIDConnected reports another endpoint connected with the
	// same id; no more messages will be received.
	StatusSameEndpointIDConnected Status = 1
	// StatusRateLimited reports the relay is throttling this client's
	// outbound traffic.
	StatusRateLimited Status = 2
)

// RelayToClientMsg is a message a relay sends to a client. Exactly one of its
// fields is meaningful, selected by Type.
type RelayToClientMsg struct {
	Type FrameType
	// Datagrams / RemoteEndpointID for FrameRelayToClientDatagram(Batch).
	RemoteEndpointID key.EndpointID
	Datagrams        Datagrams
	// EndpointGone for FrameEndpointGone.
	EndpointGone key.EndpointID
	// Status for FrameStatus.
	Status Status
	// Ping/Pong payload for FramePing/FramePong.
	Ping [8]byte
	// Restarting durations for FrameRestarting.
	ReconnectIn time.Duration
	TryFor      time.Duration
	// Health problem text for FrameHealth (deprecated, V1 only).
	Health string
}

// AppendTo appends the wire encoding of m to dst.
func (m RelayToClientMsg) AppendTo(dst []byte) []byte {
	dst = writeFrameType(dst, m.frameType())
	switch m.Type {
	case FrameRelayToClientDatagram, FrameRelayToClientDatagramBat:
		id := m.RemoteEndpointID.Bytes()
		dst = append(dst, id[:]...)
		dst = m.Datagrams.appendTo(dst)
	case FrameEndpointGone:
		id := m.EndpointGone.Bytes()
		dst = append(dst, id[:]...)
	case FramePing, FramePong:
		dst = append(dst, m.Ping[:]...)
	case FrameHealth:
		dst = append(dst, m.Health...)
	case FrameRestarting:
		dst = binary.BigEndian.AppendUint32(dst, uint32(m.ReconnectIn.Milliseconds()))
		dst = binary.BigEndian.AppendUint32(dst, uint32(m.TryFor.Milliseconds()))
	case FrameStatus:
		dst = append(dst, byte(m.Status))
	}
	return dst
}

// EncodedLen returns the number of bytes AppendTo writes.
func (m RelayToClientMsg) EncodedLen() int {
	return frameTypeEncodedLen(m.frameType()) + m.PayloadLen()
}

// PayloadLen returns the number of payload bytes after the frame type varint.
func (m RelayToClientMsg) PayloadLen() int {
	switch m.Type {
	case FrameRelayToClientDatagram, FrameRelayToClientDatagramBat:
		return 32 + m.Datagrams.encodedLen()
	case FrameEndpointGone:
		return 32
	case FramePing, FramePong:
		return 8
	case FrameStatus:
		return 1
	case FrameRestarting:
		return 8
	case FrameHealth:
		return len(m.Health)
	default:
		return 0
	}
}

// frameType returns the wire frame type for m, deriving the datagram batch
// variant from the segment size.
func (m RelayToClientMsg) frameType() FrameType {
	if m.Type == FrameRelayToClientDatagram || m.Type == FrameRelayToClientDatagramBat {
		if m.Datagrams.isBatch() {
			return FrameRelayToClientDatagramBat
		}
		return FrameRelayToClientDatagram
	}
	return m.Type
}

// ParseRelayToClientMsg decodes a relay-to-client message. version gates the
// deprecated Health (V1 only) and Status (V2+) frames.
func ParseRelayToClientMsg(content []byte, version ProtocolVersion) (RelayToClientMsg, error) {
	return parseRelayToClientMsg(content, version, false)
}

// ParseRelayToClientMsgNoCopy decodes a relay-to-client message without
// copying datagram contents. The returned message aliases content.
func ParseRelayToClientMsgNoCopy(content []byte, version ProtocolVersion) (RelayToClientMsg, error) {
	return parseRelayToClientMsg(content, version, true)
}

func parseRelayToClientMsg(content []byte, version ProtocolVersion, noCopy bool) (RelayToClientMsg, error) {
	ft, rest, err := readFrameType(content)
	if err != nil {
		return RelayToClientMsg{}, err
	}
	if len(rest) > MaxPacketSize {
		return RelayToClientMsg{}, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(rest))
	}
	switch ft {
	case FrameRelayToClientDatagram, FrameRelayToClientDatagramBat:
		if len(rest) < key.PublicKeySize {
			return RelayToClientMsg{}, ErrInvalidFrame
		}
		id, err := validKeys.endpointID(rest[:key.PublicKeySize])
		if err != nil {
			return RelayToClientMsg{}, err
		}
		dg, err := parseDatagrams(rest[key.PublicKeySize:], ft == FrameRelayToClientDatagramBat, noCopy)
		if err != nil {
			return RelayToClientMsg{}, err
		}
		return RelayToClientMsg{Type: ft, RemoteEndpointID: id, Datagrams: dg}, nil
	case FrameEndpointGone:
		if len(rest) != key.PublicKeySize {
			return RelayToClientMsg{}, ErrInvalidFrame
		}
		id, err := validKeys.endpointID(rest)
		if err != nil {
			return RelayToClientMsg{}, err
		}
		return RelayToClientMsg{Type: ft, EndpointGone: id}, nil
	case FramePing, FramePong:
		if len(rest) != 8 {
			return RelayToClientMsg{}, ErrInvalidFrame
		}
		var p [8]byte
		copy(p[:], rest)
		return RelayToClientMsg{Type: ft, Ping: p}, nil
	case FrameHealth:
		if version != ProtocolV1 {
			return RelayToClientMsg{}, ErrFrameNotAllowedInVersion
		}
		return RelayToClientMsg{Type: ft, Health: string(rest)}, nil
	case FrameRestarting:
		if len(rest) != 8 {
			return RelayToClientMsg{}, ErrInvalidFrame
		}
		reconnect := time.Duration(binary.BigEndian.Uint32(rest[:4])) * time.Millisecond
		tryFor := time.Duration(binary.BigEndian.Uint32(rest[4:])) * time.Millisecond
		return RelayToClientMsg{Type: ft, ReconnectIn: reconnect, TryFor: tryFor}, nil
	case FrameStatus:
		if version < ProtocolV2 {
			return RelayToClientMsg{}, ErrFrameNotAllowedInVersion
		}
		if len(rest) < 1 {
			return RelayToClientMsg{}, ErrInvalidFrame
		}
		return RelayToClientMsg{Type: ft, Status: Status(rest[0])}, nil
	default:
		return RelayToClientMsg{}, fmt.Errorf("%w: %s", ErrUnknownFrameType, ft)
	}
}

// ClientToRelayMsg is a message a client sends to a relay. Exactly one of its
// fields is meaningful, selected by Type.
type ClientToRelayMsg struct {
	Type FrameType
	// DstEndpointID / Datagrams for FrameClientToRelayDatagram(Batch).
	DstEndpointID key.EndpointID
	Datagrams     Datagrams
	// Ping/Pong payload for FramePing/FramePong.
	Ping [8]byte
}

// AppendTo appends the wire encoding of m to dst.
func (m ClientToRelayMsg) AppendTo(dst []byte) []byte {
	dst = writeFrameType(dst, m.frameType())
	switch m.Type {
	case FrameClientToRelayDatagram, FrameClientToRelayDatagramBat:
		id := m.DstEndpointID.Bytes()
		dst = append(dst, id[:]...)
		dst = m.Datagrams.appendTo(dst)
	case FramePing, FramePong:
		dst = append(dst, m.Ping[:]...)
	}
	return dst
}

// EncodedLen returns the number of bytes AppendTo writes.
func (m ClientToRelayMsg) EncodedLen() int {
	payload := 0
	switch m.Type {
	case FrameClientToRelayDatagram, FrameClientToRelayDatagramBat:
		payload = 32 + m.Datagrams.encodedLen()
	case FramePing, FramePong:
		payload = 8
	}
	return frameTypeEncodedLen(m.frameType()) + payload
}

func (m ClientToRelayMsg) frameType() FrameType {
	if m.Type == FrameClientToRelayDatagram || m.Type == FrameClientToRelayDatagramBat {
		if m.Datagrams.isBatch() {
			return FrameClientToRelayDatagramBat
		}
		return FrameClientToRelayDatagram
	}
	return m.Type
}

// ParseClientToRelayMsg decodes a client-to-relay message.
func ParseClientToRelayMsg(content []byte) (ClientToRelayMsg, error) {
	return parseClientToRelayMsg(content, false)
}

// ParseClientToRelayMsgNoCopy decodes a client-to-relay message without
// copying datagram contents. The returned message aliases content.
func ParseClientToRelayMsgNoCopy(content []byte) (ClientToRelayMsg, error) {
	return parseClientToRelayMsg(content, true)
}

func parseClientToRelayMsg(content []byte, noCopy bool) (ClientToRelayMsg, error) {
	ft, rest, err := readFrameType(content)
	if err != nil {
		return ClientToRelayMsg{}, err
	}
	if len(rest) > MaxPacketSize {
		return ClientToRelayMsg{}, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(rest))
	}
	switch ft {
	case FrameClientToRelayDatagram, FrameClientToRelayDatagramBat:
		if len(rest) < key.PublicKeySize {
			return ClientToRelayMsg{}, ErrInvalidFrame
		}
		id, err := validKeys.endpointID(rest[:key.PublicKeySize])
		if err != nil {
			return ClientToRelayMsg{}, err
		}
		dg, err := parseDatagrams(rest[key.PublicKeySize:], ft == FrameClientToRelayDatagramBat, noCopy)
		if err != nil {
			return ClientToRelayMsg{}, err
		}
		return ClientToRelayMsg{Type: ft, DstEndpointID: id, Datagrams: dg}, nil
	case FramePing, FramePong:
		if len(rest) != 8 {
			return ClientToRelayMsg{}, ErrInvalidFrame
		}
		var p [8]byte
		copy(p[:], rest)
		return ClientToRelayMsg{Type: ft, Ping: p}, nil
	default:
		return ClientToRelayMsg{}, fmt.Errorf("%w: %s", ErrUnknownFrameType, ft)
	}
}

func parseDatagrams(b []byte, isBatch, noCopy bool) (Datagrams, error) {
	if noCopy {
		return datagramsFromBytesNoCopy(b, isBatch)
	}
	return datagramsFromBytes(b, isBatch)
}
