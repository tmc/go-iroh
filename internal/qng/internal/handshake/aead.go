package handshake

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

// pathPacketNumberLow62 masks a packet number to the low 62 bits, as the
// draft-ietf-quic-multipath §2.4 path-and-packet-number reserves the two bits
// above the 62-bit packet number. QUIC packet numbers never exceed 2^62-1
// (RFC 9000 §17.1), so this is a no-op for valid packet numbers; it documents
// the invariant the draft relies on.
const pathPacketNumberLow62 = (uint64(1) << 62) - 1

// putPathNonce writes the AEAD nonce for path pid and packet number pn into buf,
// per draft-ietf-quic-multipath §2.4. For PathIDZero the nonce is the 8-byte
// big-endian packet number — byte-identical to the RFC 9001 nonce — so the
// single-path stack is unchanged. For a non-zero path it is the 12-byte
// big-endian path-and-packet-number: the path id in the high 32 bits, then two
// zero bits, then the 62-bit packet number in the low bits. It returns the
// sub-slice of buf that was written. buf must be at least 12 bytes.
func putPathNonce(buf []byte, pid protocol.PathID, pn protocol.PacketNumber) []byte {
	if pid == protocol.PathIDZero {
		nonce := buf[len(buf)-8:]
		binary.BigEndian.PutUint64(nonce, uint64(pn))
		return nonce
	}
	nonce := buf[len(buf)-12:]
	binary.BigEndian.PutUint32(nonce[:4], uint32(pid))
	binary.BigEndian.PutUint64(nonce[4:], uint64(pn)&pathPacketNumberLow62)
	return nonce
}

func createAEAD(suite cipherSuite, trafficSecret []byte, v protocol.Version) *xorNonceAEAD {
	keyLabel := hkdfLabelKeyV1
	ivLabel := hkdfLabelIVV1
	if v == protocol.Version2 {
		keyLabel = hkdfLabelKeyV2
		ivLabel = hkdfLabelIVV2
	}
	key := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, keyLabel, suite.KeyLen)
	iv := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, ivLabel, suite.IVLen())
	return suite.AEAD(key, iv)
}

type longHeaderSealer struct {
	aead            cipher.AEAD
	headerProtector headerProtector
	nonceBuf        [12]byte
}

var _ LongHeaderSealer = &longHeaderSealer{}

func newLongHeaderSealer(aead cipher.AEAD, headerProtector headerProtector) LongHeaderSealer {
	if aead.NonceSize() != 8 {
		panic("unexpected nonce size")
	}
	return &longHeaderSealer{
		aead:            aead,
		headerProtector: headerProtector,
	}
}

func (s *longHeaderSealer) Seal(dst, src []byte, pid protocol.PathID, pn protocol.PacketNumber, ad []byte) []byte {
	return s.aead.Seal(dst, putPathNonce(s.nonceBuf[:], pid, pn), src, ad)
}

func (s *longHeaderSealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	s.headerProtector.EncryptHeader(sample, firstByte, pnBytes)
}

func (s *longHeaderSealer) Overhead() int {
	return s.aead.Overhead()
}

type longHeaderOpener struct {
	aead            cipher.AEAD
	headerProtector headerProtector
	highestRcvdPN   protocol.PacketNumber // highest packet number received (which could be successfully unprotected)

	// use a single array to avoid allocations
	nonceBuf [12]byte
}

var _ LongHeaderOpener = &longHeaderOpener{}

func newLongHeaderOpener(aead cipher.AEAD, headerProtector headerProtector) LongHeaderOpener {
	if aead.NonceSize() != 8 {
		panic("unexpected nonce size")
	}
	return &longHeaderOpener{
		aead:            aead,
		headerProtector: headerProtector,
	}
}

// DecodePacketNumber reconstructs the truncated wire packet number. pid is
// always PathIDZero (long-header packets are never multipath), so a single
// highestRcvdPN suffices.
func (o *longHeaderOpener) DecodePacketNumber(_ protocol.PathID, wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, o.highestRcvdPN, wirePN)
}

func (o *longHeaderOpener) Open(dst, src []byte, pid protocol.PathID, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	dec, err := o.aead.Open(dst, putPathNonce(o.nonceBuf[:], pid, pn), src, ad)
	if err == nil {
		o.highestRcvdPN = max(o.highestRcvdPN, pn)
	} else {
		err = ErrDecryptionFailed
	}
	return dec, err
}

func (o *longHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
}
