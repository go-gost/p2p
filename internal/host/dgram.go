package host

import (
	"net"
	"sync"
	"time"
)

// dgramEdge adapts a UDP socket already dialed to the tun server into the
// byte-stream shape a datagram link pumps: frame bytes from the peer edge
// are parsed and each frame's payload sent as one datagram; each datagram read
// from the socket is emitted as one 2-byte-prefixed frame. It is the local edge
// of a udp target outlet: the socket dialed to the tun server, paired with the
// peer's framed datagram stream.
//
// This host still does not originate framing: the GOST side
// (x/p2p/streamconn) owns it, and this edge only converts between that framing
// and the tun server's datagrams.
type dgramEdge struct {
	conn *net.UDPConn

	wmu  sync.Mutex
	wbuf []byte // frame bytes not yet forming a whole frame

	rmu  sync.Mutex
	rbuf []byte // frame bytes staged for Read
	rdat []byte // reusable datagram buffer (one datagram fits maxFrame)

	closeOnce sync.Once
}

var _ net.Conn = (*dgramEdge)(nil)

// newDgramEdge wraps a UDP socket connected to the tun server.
func newDgramEdge(c *net.UDPConn) *dgramEdge {
	return &dgramEdge{
		conn: c,
		rdat: make([]byte, maxFrame),
	}
}

// Write sends the frame bytes arriving from the peer edge: every whole frame
// becomes one datagram (empty frames are skipped), and an incomplete tail is
// kept for the next call. The buffer stays bounded — frameAt completes a frame
// at maxFrame+2 bytes — so it needs no explicit cap. A send failure drops the
// backlog: datagrams are lossy.
func (e *dgramEdge) Write(p []byte) (int, error) {
	e.wmu.Lock()
	defer e.wmu.Unlock()

	e.wbuf = append(e.wbuf, p...)
	off := 0
	for {
		n, total, ok := frameAt(e.wbuf[off:])
		if !ok {
			break
		}
		if n > 0 {
			if _, err := e.conn.Write(e.wbuf[off+2 : off+total]); err != nil {
				e.wbuf = e.wbuf[:0]
				return len(p), err
			}
		}
		off += total
	}
	if off > 0 {
		e.wbuf = e.wbuf[:copy(e.wbuf, e.wbuf[off:])]
	}
	return len(p), nil
}

// Read emits one datagram from the tun server as a frame. A frame larger than
// p is delivered across several Reads; the peer's GOST-side conn reassembles
// it. An empty datagram is skipped.
func (e *dgramEdge) Read(p []byte) (int, error) {
	e.rmu.Lock()
	defer e.rmu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}
	for len(e.rbuf) == 0 {
		n, err := e.conn.Read(e.rdat)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		e.rbuf = appendFrame(e.rbuf[:0], e.rdat[:n])
	}
	n := copy(p, e.rbuf)
	e.rbuf = e.rbuf[n:]
	return n, nil
}

func (e *dgramEdge) LocalAddr() net.Addr  { return e.conn.LocalAddr() }
func (e *dgramEdge) RemoteAddr() net.Addr { return e.conn.RemoteAddr() }

func (e *dgramEdge) SetDeadline(t time.Time) error      { return e.conn.SetDeadline(t) }
func (e *dgramEdge) SetReadDeadline(t time.Time) error  { return e.conn.SetReadDeadline(t) }
func (e *dgramEdge) SetWriteDeadline(t time.Time) error { return e.conn.SetWriteDeadline(t) }

// Close is idempotent and closes the socket, which wakes a parked Read.
func (e *dgramEdge) Close() error {
	e.closeOnce.Do(func() {
		e.conn.Close()
	})
	return nil
}
