package host

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

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

// errDatagramTooLarge is returned by frameConn.Write for a datagram that does
// not fit the 2-byte length prefix — the same limit x/p2p/streamconn enforces
// on the gRPC carrier.
var errDatagramTooLarge = errors.New("p2p: datagram exceeds maxFrame")

// frameConn presents a byte-stream tunnel conn as the datagram conn a udp
// tunnel carries: every Write becomes one length-prefixed frame and every Read
// returns exactly one datagram, with bytes beyond the read buffer discarded as
// on a UDP socket. It is the in-process provider's counterpart of
// x/p2p/streamconn's framed mode: the gRPC carrier frames there, this carrier
// frames here, so both hand the inner dialer the same conn shape. The host
// never parses the data; the peer's GOST-side conn does.
type frameConn struct {
	net.Conn

	mu   sync.Mutex
	rbuf []byte // frame bytes read from the conn, held until one frame is whole
}

// newFrameConn wraps a raw tunnel conn for a udp tunnel.
func newFrameConn(c net.Conn) *frameConn { return &frameConn{Conn: c} }

func (c *frameConn) Write(p []byte) (int, error) {
	if len(p) > maxFrame {
		return 0, errDatagramTooLarge
	}
	if _, err := c.Conn.Write(appendFrame(nil, p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *frameConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if n, total, ok := frameAt(c.rbuf); ok {
			out := copy(b, c.rbuf[2:2+n])
			if total == len(c.rbuf) {
				c.rbuf = nil // drop the backing array; nothing is anchored
			} else {
				c.rbuf = append(c.rbuf[:0], c.rbuf[total:]...)
			}
			c.mu.Unlock()
			return out, nil
		}
		c.mu.Unlock()

		var buf [4096]byte
		n, err := c.Conn.Read(buf[:])
		if n > 0 {
			c.mu.Lock()
			c.rbuf = append(c.rbuf, buf[:n]...)
			c.mu.Unlock()
		}
		if err != nil {
			return 0, err
		}
	}
}
