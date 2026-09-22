package host

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// Stream is the byte-stream half of a tunnel carrier: the seam between a
// transport (or the in-memory pipe) and the net.Conn the tunnel pipe needs.
// Chunk boundaries are the carrier's business — the gRPC transport maps them to
// and from proto.Chunk, the in-memory pipe preserves them — the host sees
// bytes only.
type Stream interface {
	// Send writes one chunk. The payload is not retained: a carrier may copy
	// it, and the caller may reuse its buffer once Send returns.
	Send([]byte) error
	// Recv reads the next chunk. A Recv that returns an error ends the stream.
	Recv() ([]byte, error)
	// Context is the stream's lifetime: when it is done, the stream is over,
	// whatever Recv is doing.
	Context() context.Context
}

// streamConn adapts a Stream to the net.Conn the tunnel pipe needs. The host
// side is a raw byte pipe: no framing (a udp tunnel's frames travel through as
// bytes — the peer datagram channel parses them), no write deadline (a server
// handler cannot abort its stream; its return is the abort). It is deliberately
// a small standalone implementation rather than the GOST side's richer conn
// (x/p2p/streamconn): the two sides couple through the wire, not through code.
//
// One Recv pump hands chunks to Read through a one-chunk channel so Close can
// wake a parked Read. Without the pump a reader blocked inside Recv could only
// be woken by the stream ending — but the stream ending is exactly the case
// Close must handle (the peer EOFs while the client is idle), and the handler
// cannot return to end the RPC while its pipe is still blocked.
type streamConn struct {
	stream Stream
	abort  func() // ends the carrier on Close; nil when the handler's return ends it
	local  net.Addr
	remote net.Addr

	chunks chan []byte
	closed chan struct{}
	done   chan struct{}

	mu  sync.Mutex
	err error // the pump's terminal error
	rb  []byte
	rd  time.Time

	once sync.Once
}

func newStreamConn(stream Stream, abort func()) *streamConn {
	c := &streamConn{
		stream: stream,
		abort:  abort,
		local:  streamAddr{},
		remote: streamAddr{},
		chunks: make(chan []byte, 1),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
	go c.pump()
	return c
}

// streamAddr is the synthetic address of a tunnel carried by a stream. The
// tunnel has no socket, but callers read LocalAddr/RemoteAddr and call String
// on them (gost's forward connector logs both), so they must be non-nil.
type streamAddr struct {
	network string
	addr    string
}

func (a streamAddr) Network() string { return a.network }
func (a streamAddr) String() string  { return a.addr }

// pump moves chunks from Recv to Read; every exit funnels through run's
// return value, so a reader parked in Read always wakes.
func (c *streamConn) pump() {
	err := c.run()
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	close(c.done)
}

func (c *streamConn) run() error {
	for {
		chunk, err := c.stream.Recv()
		if err != nil {
			return err
		}
		select {
		case c.chunks <- chunk:
		case <-c.closed:
			return net.ErrClosed
		case <-c.stream.Context().Done():
			// The stream died (the client aborted it).
			return c.stream.Context().Err()
		}
	}
}

func (c *streamConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.rb) > 0 {
			n := copy(b, c.rb)
			c.rb = c.rb[n:]
			c.mu.Unlock()
			return n, nil
		}
		dl := c.rd
		c.mu.Unlock()

		var tch <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			tch = timer.C
		}

		select {
		case data := <-c.chunks:
			if timer != nil {
				timer.Stop()
			}
			return c.take(b, data), nil
		case <-c.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			// A chunk delivered before the terminal state is not lost.
			select {
			case data := <-c.chunks:
				return c.take(b, data), nil
			default:
			}
			return 0, c.termErr()
		case <-tch:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// take copies one chunk into b, stashing an oversized remainder for the next
// Read.
func (c *streamConn) take(b, data []byte) int {
	n := copy(b, data)
	if n < len(data) {
		c.mu.Lock()
		c.rb = data[n:]
		c.mu.Unlock()
	}
	return n
}

func (c *streamConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if len(b) == 0 {
		return 0, nil
	}
	// The bridge writes through an io.Copy 32 KiB buffer, so a send always
	// stays well under gRPC's message limit; no splitting here.
	if err := c.stream.Send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close marks the conn closed and wakes a parked Read; on the gRPC path the RPC
// ending (the handler returning) is what actually finishes the stream, and on
// the in-process path abort cancels the pipe.
func (c *streamConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		if c.err == nil {
			c.err = net.ErrClosed
		}
		c.mu.Unlock()
		close(c.closed)
		if c.abort != nil {
			c.abort()
		}
	})
	return nil
}

func (c *streamConn) termErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return net.ErrClosed
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline applies to subsequent Reads; unlike the GOST-side conn it
// has no mid-read update wake — the host bridge never re-sets one mid-read.
func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rd = t
	c.mu.Unlock()
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	return errors.New("p2p: stream write deadline not supported on a server stream")
}
