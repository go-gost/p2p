package host

import (
	"net"
	"sync"
	"time"
)

// packetPipeAddr is the local address one end of a packet pipe reports. The
// multiPathConn replaces it with the underlay address, so it only has to be
// distinct between the two ends.
type packetPipeAddr string

func (a packetPipeAddr) Network() string { return "pipe" }
func (a packetPipeAddr) String() string  { return string(a) }

// packetPipeCap bounds each direction of a test pipe. A real relay path is
// lossy; a full pipe drops the packet instead of blocking the writer, which is
// what keeps a stalled test from wedging a QUIC writer.
const packetPipeCap = 4096

// packetPipeEnd is one end of an in-memory packet pipe. Writes to it land in
// the peer's ReadFrom; both directions are independent.
type packetPipeEnd struct {
	in        <-chan []byte
	out       chan<- []byte
	local     net.Addr
	closed    chan struct{}
	closeOnce sync.Once
}

var _ net.PacketConn = (*packetPipeEnd)(nil)

// newPacketPipe returns the two ends of an in-memory, bidirectional datagram
// pipe. Either end can be closed to unblock its own ReadFrom; closing one end
// does not close the other, so the test controls each half of the relay path.
func newPacketPipe() (net.PacketConn, net.PacketConn) {
	ab := make(chan []byte, packetPipeCap)
	ba := make(chan []byte, packetPipeCap)
	a := &packetPipeEnd{
		in:     ba,
		out:    ab,
		local:  packetPipeAddr("a"),
		closed: make(chan struct{}),
	}
	b := &packetPipeEnd{
		in:     ab,
		out:    ba,
		local:  packetPipeAddr("b"),
		closed: make(chan struct{}),
	}
	return a, b
}

func (c *packetPipeEnd) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case pkt := <-c.in:
		return copy(p, pkt), c.local, nil
	}
}

// WriteTo never blocks: on a full pipe it drops the packet like a congested
// relay path would. QUIC retransmission covers the loss.
func (c *packetPipeEnd) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	pkt := append([]byte(nil), p...)
	select {
	case c.out <- pkt:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *packetPipeEnd) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *packetPipeEnd) LocalAddr() net.Addr { return c.local }

// Deadlines are no-ops: multiPathConn owns the deadlines quic-go sets, and no
// test reads this pipe directly.
func (c *packetPipeEnd) SetDeadline(time.Time) error      { return nil }
func (c *packetPipeEnd) SetReadDeadline(time.Time) error  { return nil }
func (c *packetPipeEnd) SetWriteDeadline(time.Time) error { return nil }
