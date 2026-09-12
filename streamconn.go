package main

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-gost/plugin/p2p/proto"
)

// streamConn adapts the Tunnel server stream to the net.Conn the tunnel pipe
// needs. The host side is a raw byte pipe: no framing (a udp tunnel's frames
// travel through as bytes — the peer datagram channel parses them), no write
// deadline (a server handler cannot abort its stream; its return is the
// abort). It is deliberately a small standalone implementation rather than
// the GOST side's richer conn (x/p2p/streamconn): the plugin module holds
// contracts only and the host cannot import the x module, so the two sides
// couple through the proto (Chunk messages), not through code.
//
// One Recv pump hands chunks to Read through a one-chunk channel so Close can
// wake a parked Read. Without the pump a reader blocked inside Recv could
// only be woken by the stream ending — but the stream ending is exactly the
// case Close must handle (the peer EOFs while the client is idle), and the
// handler cannot return to end the RPC while its pipe is still blocked.
// tunnelStream is the data-carrying half of the Tunnel RPC; both
// proto.P2P_TunnelServer (the host handler) and proto.P2P_TunnelClient (the
// tests' client side) satisfy it.
type tunnelStream interface {
	Send(*proto.Chunk) error
	Recv() (*proto.Chunk, error)
	Context() context.Context
}

type streamConn struct {
	stream tunnelStream
	abort  func() // tests: cancels the client-side stream on Close; nil in the host handler

	chunks chan []byte
	closed chan struct{}
	done   chan struct{}

	mu  sync.Mutex
	err error // the pump's terminal error
	rb  []byte
	rd  time.Time

	once sync.Once
}

func newStreamConn(stream tunnelStream, abort func()) *streamConn {
	c := &streamConn{
		stream: stream,
		abort:  abort,
		chunks: make(chan []byte, 1),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
	go c.pump()
	return c
}

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
		case c.chunks <- chunk.GetData():
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
	if err := c.stream.Send(&proto.Chunk{Data: b}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close marks the conn closed and wakes a parked Read; on the host side the
// RPC ending (the handler returning) is what actually finishes the stream.
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

func (c *streamConn) LocalAddr() net.Addr  { return nil }
func (c *streamConn) RemoteAddr() net.Addr { return nil }

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
