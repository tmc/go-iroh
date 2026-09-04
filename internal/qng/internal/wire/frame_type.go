package wire

import "github.com/tmc/go-iroh/internal/qng/internal/protocol"

type FrameType uint64

// These constants correspond to those defined in RFC 9000.
// Stream frame types are not listed explicitly here; use FrameType.IsStreamFrameType() to identify them.
const (
	FrameTypePing        FrameType = 0x1
	FrameTypeAck         FrameType = 0x2
	FrameTypeAckECN      FrameType = 0x3
	FrameTypeResetStream FrameType = 0x4
	FrameTypeStopSending FrameType = 0x5
	FrameTypeCrypto      FrameType = 0x6
	FrameTypeNewToken    FrameType = 0x7

	FrameTypeMaxData            FrameType = 0x10
	FrameTypeMaxStreamData      FrameType = 0x11
	FrameTypeBidiMaxStreams     FrameType = 0x12
	FrameTypeUniMaxStreams      FrameType = 0x13
	FrameTypeDataBlocked        FrameType = 0x14
	FrameTypeStreamDataBlocked  FrameType = 0x15
	FrameTypeBidiStreamBlocked  FrameType = 0x16
	FrameTypeUniStreamBlocked   FrameType = 0x17
	FrameTypeNewConnectionID    FrameType = 0x18
	FrameTypeRetireConnectionID FrameType = 0x19
	FrameTypePathChallenge      FrameType = 0x1a
	FrameTypePathResponse       FrameType = 0x1b
	FrameTypeConnectionClose    FrameType = 0x1c
	FrameTypeApplicationClose   FrameType = 0x1d
	FrameTypeHandshakeDone      FrameType = 0x1e
	// https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/09/
	FrameTypeResetStreamAt FrameType = 0x24
	// https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/11/
	FrameTypeAckFrequency FrameType = 0xaf
	FrameTypeImmediateAck FrameType = 0x1f

	FrameTypeDatagramNoLength   FrameType = 0x30
	FrameTypeDatagramWithLength FrameType = 0x31

	// QUIC Address Discovery OBSERVED_ADDRESS frame types
	// (draft-seemann-quic-address-discovery), as used by iroh's noq QUIC fork.
	// The frame type selects the reported address family. See
	// internal/qng/n0ext/reference/frame.rs:100-103.
	FrameTypeObservedIPv4Addr FrameType = 0x9f81a6
	FrameTypeObservedIPv6Addr FrameType = 0x9f81a7

	// QUIC multipath frame types (draft-ietf-quic-multipath), as used by iroh's
	// noq QUIC fork. See internal/qng/n0ext/reference/frame.rs (lines 104-124).
	// These constants are defined so the multipath frame codecs can reference
	// them; they are not yet admitted by the frame parser or emitted by the
	// packer (that wiring is a later stage of the multipath port).
	FrameTypePathAck                FrameType = 0x3e
	FrameTypePathAckECN             FrameType = 0x3f
	FrameTypePathAbandon            FrameType = 0x3e75
	FrameTypePathStatusBackup       FrameType = 0x3e76
	FrameTypePathStatusAvailable    FrameType = 0x3e77
	FrameTypePathNewConnectionID    FrameType = 0x3e78
	FrameTypePathRetireConnectionID FrameType = 0x3e79
	FrameTypeMaxPathID              FrameType = 0x3e7a
	FrameTypePathsBlocked           FrameType = 0x3e7b
	FrameTypePathCIDsBlocked        FrameType = 0x3e7c

	// iroh NAT traversal frame types, as used by iroh's noq QUIC fork. See
	// internal/qng/n0ext/reference/frame.rs:126-135.
	FrameTypeAddIPv4Address FrameType = 0x3d7f90
	FrameTypeAddIPv6Address FrameType = 0x3d7f91
	FrameTypeReachOutAtIPv4 FrameType = 0x3d7f92
	FrameTypeReachOutAtIPv6 FrameType = 0x3d7f93
	FrameTypeRemoveAddress  FrameType = 0x3d7f94
)

func (t FrameType) IsStreamFrameType() bool {
	return t >= 0x8 && t <= 0xf
}

func (t FrameType) isValidRFC9000() bool {
	return t <= 0x1e
}

func (t FrameType) IsAckFrameType() bool {
	return t == FrameTypeAck || t == FrameTypeAckECN
}

func (t FrameType) IsDatagramFrameType() bool {
	return t == FrameTypeDatagramNoLength || t == FrameTypeDatagramWithLength
}

// isMultipathFrameType reports whether t is one of the QUIC multipath frame
// types. These match the Rust Frame::is_multipath_frame set (frame.rs:543-560):
// PathAck, PathAckEcn, PathAbandon, PathStatus{Backup,Available},
// Path{New,Retire}ConnectionId, MaxPathId, PathsBlocked, PathCidsBlocked.
func (t FrameType) isMultipathFrameType() bool {
	switch t {
	case FrameTypePathAck, FrameTypePathAckECN,
		FrameTypePathAbandon, FrameTypePathStatusBackup, FrameTypePathStatusAvailable,
		FrameTypePathNewConnectionID, FrameTypePathRetireConnectionID,
		FrameTypeMaxPathID, FrameTypePathsBlocked, FrameTypePathCIDsBlocked:
		return true
	default:
		return false
	}
}

// isAddressDiscoveryFrameType reports whether t is one of the QUIC Address
// Discovery OBSERVED_ADDRESS frame types (frame.rs:100-103).
func (t FrameType) isAddressDiscoveryFrameType() bool {
	return t == FrameTypeObservedIPv4Addr || t == FrameTypeObservedIPv6Addr
}

// isNATTraversalFrameType reports whether t is one of the n0 NAT traversal
// frame types (frame.rs:126-135).
func (t FrameType) isNATTraversalFrameType() bool {
	switch t {
	case FrameTypeAddIPv4Address, FrameTypeAddIPv6Address,
		FrameTypeReachOutAtIPv4, FrameTypeReachOutAtIPv6,
		FrameTypeRemoveAddress:
		return true
	default:
		return false
	}
}

func (t FrameType) isAllowedAtEncLevel(encLevel protocol.EncryptionLevel) bool {
	// All multipath frames MUST only be sent in 1-RTT packets; receiving one in
	// any other packet type is a PROTOCOL_VIOLATION
	// (frame.rs:524-535, Frame::is_1rtt; draft-ietf-quic-multipath-17 §4-1).
	if t.isMultipathFrameType() {
		return encLevel == protocol.Encryption1RTT
	}
	// OBSERVED_ADDRESS is likewise 1-RTT only (frame.rs Frame::is_1rtt; the
	// receive path rejects it outside the data space, mod.rs:5343-5347).
	if t.isAddressDiscoveryFrameType() {
		return encLevel == protocol.Encryption1RTT
	}
	// QNT frames carry NAT traversal state and are only valid in the 1-RTT
	// packet space, matching the noq frame parser's 1-RTT-only treatment.
	if t.isNATTraversalFrameType() {
		return encLevel == protocol.Encryption1RTT
	}
	//nolint:exhaustive
	switch encLevel {
	case protocol.EncryptionInitial, protocol.EncryptionHandshake:
		switch t {
		case FrameTypeCrypto, FrameTypeAck, FrameTypeAckECN, FrameTypeConnectionClose, FrameTypePing:
			return true
		default:
			return false
		}
	case protocol.Encryption0RTT:
		switch t {
		case FrameTypeCrypto, FrameTypeAck, FrameTypeAckECN, FrameTypeConnectionClose, FrameTypeNewToken, FrameTypePathResponse, FrameTypeRetireConnectionID:
			return false
		default:
			return true
		}
	case protocol.Encryption1RTT:
		return true
	default:
		panic("unknown encryption level")
	}
}
