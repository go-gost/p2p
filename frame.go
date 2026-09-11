package main

import (
	"encoding/binary"
	"io"
	"net"
)

// Datagram framing. The data plane (smux over the relay or the hole-punched
// path) is a byte stream and does not preserve read boundaries, so each
// datagram travels as one length-prefixed frame — the same 2-byte big-endian
// prefix format the router handler's packetConn uses.

// maxFrame is the largest chunk that fits the 2-byte length prefix.
const maxFrame = 65535

// writeFrame writes p as one length-prefixed frame.
func writeFrame(w io.Writer, p []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	bufs := net.Buffers{hdr[:], p}
	_, err := bufs.WriteTo(w)
	return err
}

// readFrame reads one length-prefixed frame. A zero-length frame returns
// (nil, nil); the caller should skip it.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, nil
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}
