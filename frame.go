package main

import "encoding/binary"

// maxFrame is the largest payload the 2-byte big-endian length prefix can
// carry. It must match x/p2p/streamconn.MaxFrame: the GOST side frames the
// datagrams, this host only passes the frames through, so both ends must agree
// on the prefix width.
const maxFrame = 65535

// appendFrame appends p to dst as one length-prefixed frame: a 2-byte
// big-endian length then the payload. Callers must pass len(p) <= maxFrame;
// the only caller sizes its read buffer to maxFrame, so the length never
// truncates.
func appendFrame(dst, p []byte) []byte {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	dst = append(dst, hdr[:]...)
	return append(dst, p...)
}

// frameAt parses the leading frame in b: payload length, the frame's total
// length (payload+2, with the payload at b[2:total]), and ok. ok is false when
// b does not yet hold a whole frame — the caller accumulating from a byte
// stream keeps the tail for the next read.
func frameAt(b []byte) (payload, total int, ok bool) {
	if len(b) < 2 {
		return 0, 0, false
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+n {
		return 0, 0, false
	}
	return n, 2 + n, true
}
