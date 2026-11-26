package wire

import (
	"errors"
	"fmt"
	"io"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

var errUnknownFrameType = errors.New("unknown frame type")

// The FrameParser parses QUIC frames, one by one.
type FrameParser struct {
	ackDelayExponent         uint8
	supportsDatagrams        bool
	supportsResetStreamAt    bool
	supportsAckFrequency     bool
	supportsMultipath        bool
	supportsAddressDiscovery bool
	supportsNATTraversal     bool

	// To avoid allocating when parsing, keep a single ACK frame struct.
	// It is used over and over again.
	ackFrame *AckFrame
}

// NewFrameParser creates a new frame parser. supportsMultipath admits the QUIC
// multipath frame types (draft-ietf-quic-multipath); it is false unless the
// connection has negotiated multipath, so single-path parsing is unchanged.
func NewFrameParser(supportsDatagrams, supportsResetStreamAt, supportsAckFrequency, supportsMultipath bool) *FrameParser {
	return &FrameParser{
		supportsDatagrams:     supportsDatagrams,
		supportsResetStreamAt: supportsResetStreamAt,
		supportsAckFrequency:  supportsAckFrequency,
		supportsMultipath:     supportsMultipath,
		ackFrame:              &AckFrame{},
	}
}

// ParseType parses the frame type of the next frame.
// It skips over PADDING frames.
func (p *FrameParser) ParseType(b []byte, encLevel protocol.EncryptionLevel) (FrameType, int, error) {
	var parsed int
	for len(b) != 0 {
		typ, l, err := quicvarint.Parse(b)
		parsed += l
		if err != nil {
			return 0, parsed, &qerr.TransportError{
				ErrorCode:    qerr.FrameEncodingError,
				ErrorMessage: err.Error(),
			}
		}
		// Frame types must use the shortest possible encoding.
		if l != quicvarint.Len(typ) {
			return 0, parsed, &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				FrameType:    typ,
				ErrorMessage: "frame type not minimally encoded",
			}
		}
		b = b[l:]
		if typ == 0x0 { // skip PADDING frames
			continue
		}
		ft := FrameType(typ)
		// Frames of extensions we didn't advertise are handled like unknown frame types,
		// as if we didn't implement the extension.
		// For DATAGRAM frames, this deviates from RFC 9221, which requires a PROTOCOL_VIOLATION.
		valid := ft.isValidRFC9000() ||
			(p.supportsDatagrams && ft.IsDatagramFrameType()) ||
			(p.supportsResetStreamAt && ft == FrameTypeResetStreamAt) ||
			(p.supportsAckFrequency && (ft == FrameTypeAckFrequency || ft == FrameTypeImmediateAck)) ||
			(p.supportsMultipath && ft.isMultipathFrameType()) ||
			(p.supportsAddressDiscovery && ft.isAddressDiscoveryFrameType()) ||
			(p.supportsNATTraversal && ft.isNATTraversalFrameType())
		if !valid {
			return 0, parsed, &qerr.TransportError{
				ErrorCode:    qerr.FrameEncodingError,
				FrameType:    typ,
				ErrorMessage: errUnknownFrameType.Error(),
			}
		}
		if !ft.isAllowedAtEncLevel(encLevel) {
			return 0, parsed, &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				FrameType:    typ,
				ErrorMessage: fmt.Sprintf("%d not allowed at encryption level %s", ft, encLevel),
			}
		}
		return ft, parsed, nil
	}
	return 0, parsed, io.EOF
}

func (p *FrameParser) ParseStreamFrame(frameType FrameType, data []byte, v protocol.Version) (*StreamFrame, int, error) {
	frame, n, err := ParseStreamFrame(data, frameType, v)
	if err != nil {
		return nil, n, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    uint64(frameType),
			ErrorMessage: err.Error(),
		}
	}
	return frame, n, nil
}

func (p *FrameParser) ParseAckFrame(frameType FrameType, data []byte, encLevel protocol.EncryptionLevel, v protocol.Version) (*AckFrame, int, error) {
	ackDelayExponent := p.ackDelayExponent
	if encLevel != protocol.Encryption1RTT {
		ackDelayExponent = protocol.DefaultAckDelayExponent
	}
	p.ackFrame.Reset()
	l, err := parseAckFrame(p.ackFrame, data, frameType, ackDelayExponent, v)
	if err != nil {
		return nil, l, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    uint64(frameType),
			ErrorMessage: err.Error(),
		}
	}

	return p.ackFrame, l, nil
}

func (p *FrameParser) ParseDatagramFrame(frameType FrameType, data []byte, v protocol.Version) (*DatagramFrame, int, error) {
	f, l, err := parseDatagramFrame(data, frameType, v)
	if err != nil {
		return nil, 0, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    uint64(frameType),
			ErrorMessage: err.Error(),
		}
	}
	return f, l, nil
}

// ParseLessCommonFrame parses everything except STREAM, ACK or DATAGRAM.
// These cases should be handled separately for performance reasons.
func (p *FrameParser) ParseLessCommonFrame(frameType FrameType, data []byte, v protocol.Version) (Frame, int, error) {
	var frame Frame
	var l int
	var err error
	//nolint:exhaustive // Common frames should already be handled.
	switch frameType {
	case FrameTypePing:
		frame = &PingFrame{}
	case FrameTypeResetStream:
		frame, l, err = parseResetStreamFrame(data, false, v)
	case FrameTypeStopSending:
		frame, l, err = parseStopSendingFrame(data, v)
	case FrameTypeCrypto:
		frame, l, err = parseCryptoFrame(data, v)
	case FrameTypeNewToken:
		frame, l, err = parseNewTokenFrame(data, v)
	case FrameTypeMaxData:
		frame, l, err = parseMaxDataFrame(data, v)
	case FrameTypeMaxStreamData:
		frame, l, err = parseMaxStreamDataFrame(data, v)
	case FrameTypeBidiMaxStreams, FrameTypeUniMaxStreams:
		frame, l, err = parseMaxStreamsFrame(data, frameType, v)
	case FrameTypeDataBlocked:
		frame, l, err = parseDataBlockedFrame(data, v)
	case FrameTypeStreamDataBlocked:
		frame, l, err = parseStreamDataBlockedFrame(data, v)
	case FrameTypeBidiStreamBlocked, FrameTypeUniStreamBlocked:
		frame, l, err = parseStreamsBlockedFrame(data, frameType, v)
	case FrameTypeNewConnectionID:
		frame, l, err = parseNewConnectionIDFrame(data, false, v)
	case FrameTypeRetireConnectionID:
		frame, l, err = parseRetireConnectionIDFrame(data, false, v)
	case FrameTypePathChallenge:
		frame, l, err = parsePathChallengeFrame(data, v)
	case FrameTypePathResponse:
		frame, l, err = parsePathResponseFrame(data, v)
	case FrameTypeConnectionClose, FrameTypeApplicationClose:
		frame, l, err = parseConnectionCloseFrame(data, frameType, v)
	case FrameTypeHandshakeDone:
		frame = &HandshakeDoneFrame{}
	case FrameTypeResetStreamAt:
		frame, l, err = parseResetStreamFrame(data, true, v)
	case FrameTypeAckFrequency:
		frame, l, err = parseAckFrequencyFrame(data, v)
	case FrameTypeImmediateAck:
		frame = &ImmediateAckFrame{}
	// QUIC Address Discovery OBSERVED_ADDRESS frames
	// (draft-seemann-quic-address-discovery). ParseType only routes here when
	// supportsAddressDiscovery is set, so these cases are inert until QAD is
	// negotiated. The frame type selects the address family (frame.rs:1665-1668).
	case FrameTypeObservedIPv4Addr:
		frame, l, err = parseObservedAddrFrame(data, false, v)
	case FrameTypeObservedIPv6Addr:
		frame, l, err = parseObservedAddrFrame(data, true, v)
	// QUIC multipath frames (draft-ietf-quic-multipath). ParseType only routes
	// here when supportsMultipath is set, so these cases are inert single-path.
	// PATH_ACK/PATH_ACK_ECN are not base ACK types (IsAckFrameType is false for
	// 0x3e/0x3f), so they arrive here rather than in ParseAckFrame; multipath is
	// 1-RTT only, so the negotiated ack delay exponent always applies.
	case FrameTypePathAck:
		frame, l, err = parsePathAckFrame(data, false, p.ackDelayExponent, v)
	case FrameTypePathAckECN:
		frame, l, err = parsePathAckFrame(data, true, p.ackDelayExponent, v)
	case FrameTypePathAbandon:
		frame, l, err = parsePathAbandonFrame(data, v)
	case FrameTypePathStatusBackup:
		frame, l, err = parsePathStatusBackupFrame(data, v)
	case FrameTypePathStatusAvailable:
		frame, l, err = parsePathStatusAvailableFrame(data, v)
	case FrameTypePathNewConnectionID:
		frame, l, err = parseNewConnectionIDFrame(data, true, v)
	case FrameTypePathRetireConnectionID:
		frame, l, err = parseRetireConnectionIDFrame(data, true, v)
	case FrameTypeMaxPathID:
		frame, l, err = parseMaxPathIDFrame(data, v)
	case FrameTypePathsBlocked:
		frame, l, err = parsePathsBlockedFrame(data, v)
	case FrameTypePathCIDsBlocked:
		frame, l, err = parsePathCIDsBlockedFrame(data, v)
	// n0 NAT traversal frames. ParseType only routes here when
	// supportsNATTraversal is set, so these cases are inert until QNT is
	// negotiated. The frame type selects the address family.
	case FrameTypeAddIPv4Address:
		frame, l, err = parseAddAddressFrame(data, false, v)
	case FrameTypeAddIPv6Address:
		frame, l, err = parseAddAddressFrame(data, true, v)
	case FrameTypeReachOutAtIPv4:
		frame, l, err = parseReachOutFrame(data, false, v)
	case FrameTypeReachOutAtIPv6:
		frame, l, err = parseReachOutFrame(data, true, v)
	case FrameTypeRemoveAddress:
		frame, l, err = parseRemoveAddressFrame(data, v)
	default:
		err = errUnknownFrameType
	}
	if err != nil {
		return frame, l, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    uint64(frameType),
			ErrorMessage: err.Error(),
		}
	}
	return frame, l, err
}

// SetAckDelayExponent sets the acknowledgment delay exponent (sent in the transport parameters).
// This value is used to scale the ACK Delay field in the ACK frame.
func (p *FrameParser) SetAckDelayExponent(exp uint8) {
	p.ackDelayExponent = exp
}

// SetSupportsMultipath admits the QUIC multipath frame types
// (draft-ietf-quic-multipath). It is set after the handshake, once both peers
// have advertised the initial_max_path_id transport parameter. Before that the
// parser stays in single-path mode and rejects multipath frames as unknown.
func (p *FrameParser) SetSupportsMultipath(supported bool) {
	p.supportsMultipath = supported
}

// SetSupportsAddressDiscovery admits the QUIC Address Discovery
// OBSERVED_ADDRESS frame types (draft-seemann-quic-address-discovery). It is set
// after the handshake, once the peer's address-discovery role permits it to
// report observed addresses to us (i.e. peer.should_report(local) is true).
// Before that the parser rejects OBSERVED_ADDRESS frames as unknown, keeping
// un-negotiated connections byte-identical.
func (p *FrameParser) SetSupportsAddressDiscovery(supported bool) {
	p.supportsAddressDiscovery = supported
}

// SetSupportsNATTraversal admits the n0 NAT traversal frame types. It is set
// after the handshake once both peers negotiated the n0_nat_traversal transport
// parameter. Before that the parser rejects QNT frames as unknown.
func (p *FrameParser) SetSupportsNATTraversal(supported bool) {
	p.supportsNATTraversal = supported
}

func replaceUnexpectedEOF(e error) error {
	if e == io.ErrUnexpectedEOF {
		return io.EOF
	}
	return e
}
