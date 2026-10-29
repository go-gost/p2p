package host

import (
	"errors"
	"fmt"
)

// Capability bits exchanged via ctrlCaps. See capsIPv6 and capsNoDirect in
// direct.go for the bits that predate QUIC.
//
// capsQUIC marks a peer that speaks QUIC and carries the parameters for it in
// a TLV after the bits. The bit alone is a claim, not a usable identity: the
// QUIC TLV must be present and valid as well.
const capsQUIC uint8 = 1 << 3

// capsTLVVersion1 is the version of the TLV container that follows the caps
// byte. It versions the framing, not QUIC itself. A payload with only the caps
// byte is the legacy KCP form and has no TLV container.
const capsTLVVersion1 uint8 = 1

// capsTLVQUIC is the TLV type carrying the QUIC identity: [version 1B]
// [fingerprint 32B] [batchVersion 1B].
const capsTLVQUIC uint8 = 0x01

// quicCapsLen is the fixed length of a capsTLVQUIC value.
const quicCapsLen = 1 + 32 + 1

// errUnsupportedCapsVersion reports a caps payload whose TLV container version
// this host does not understand. The caps bits are still usable; the TLV
// segment is ignored.
var errUnsupportedCapsVersion = errors.New("caps: unsupported TLV version")

// quicCaps is the peer's QUIC identity as advertised in caps.
type quicCaps struct {
	Version      uint8
	Fingerprint  [32]byte
	BatchVersion uint8
}

// capsInfo is one caps payload: the capability bits plus the optional QUIC
// parameters. Bits keep their sticky OR semantics; QUIC is latest-wins and is
// meaningful only while capsQUIC is set.
type capsInfo struct {
	Bits uint8
	QUIC *quicCaps
}

// encodeCaps renders info on the wire. A hidden QUIC identity produces the
// legacy one-byte payload, so KCP peers and older releases see no change.
func encodeCaps(info capsInfo) []byte {
	if info.QUIC == nil {
		return []byte{info.Bits}
	}
	b := make([]byte, 0, 4+quicCapsLen)
	b = append(b, info.Bits, capsTLVVersion1, capsTLVQUIC, quicCapsLen, info.QUIC.Version)
	b = append(b, info.QUIC.Fingerprint[:]...)
	b = append(b, info.QUIC.BatchVersion)
	return b
}

// decodeCaps parses a caps payload. The bits are returned even when the TLV
// segment is malformed or of an unknown version, preserving the legacy
// behavior of acting on the first byte; a malformed payload never yields QUIC
// parameters. Unknown TLV types are skipped, and a repeated QUIC TLV overwrites
// the earlier one.
func decodeCaps(b []byte) (capsInfo, error) {
	if len(b) == 0 {
		return capsInfo{}, errors.New("caps: empty payload")
	}
	bits := b[0]
	if len(b) == 1 {
		return capsInfo{Bits: bits}, nil
	}
	if b[1] != capsTLVVersion1 {
		return capsInfo{Bits: bits}, errUnsupportedCapsVersion
	}
	var quic *quicCaps
	p := b[2:]
	for len(p) > 0 {
		if len(p) < 2 {
			return capsInfo{Bits: bits}, errors.New("caps: truncated TLV header")
		}
		typ, n := p[0], int(p[1])
		p = p[2:]
		if len(p) < n {
			return capsInfo{Bits: bits}, fmt.Errorf("caps: truncated TLV type %#x value: need %d bytes, have %d", typ, n, len(p))
		}
		val := p[:n]
		p = p[n:]
		if typ != capsTLVQUIC {
			continue
		}
		if n != quicCapsLen {
			return capsInfo{Bits: bits}, fmt.Errorf("caps: quic TLV length %d, want %d", n, quicCapsLen)
		}
		q := quicCaps{
			Version:      val[0],
			BatchVersion: val[33],
		}
		copy(q.Fingerprint[:], val[1:33])
		quic = &q
	}
	return capsInfo{Bits: bits, QUIC: quic}, nil
}
