package host

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// A retired edge must stop feeding the local conn. adopt installs a new peer
// edge and closes the old one, but "closed" is not "silent": streamConn.Read
// selects between a queued chunk and its closed channel, so an edge that was
// superseded a moment ago can still hand over one more chunk. When it does,
// those bytes belong to a different stream, and splicing them into the tunnel's
// byte stream is what makes the far end parse a frame header out of noise.
func TestLinkSupersededEdgeStopsWritingLocal(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	l := newTestLink(t, e, peerKey, failOpen)
	local := attachLocal(t, l)

	// zA is presented and served; closing it still leaks one queued chunk.
	zA := newZombieEdge([]byte("LEAK"))
	if !l.publishOwn(zA) {
		t.Fatal("link refused the presentation")
	}
	waitFor(t, 3*time.Second, func() bool { return zA.reading() })

	// A second edge supersedes it, which closes zA.
	zB := newZombieEdge(nil)
	t.Cleanup(func() { zB.Close() })
	if !l.adopt(zB, "test") {
		t.Fatal("link refused the adoption")
	}

	// The superseded edge's leaked chunk must not reach the local conn.
	local.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 16)
	if n, err := local.Read(buf); n > 0 {
		t.Fatalf("local conn received %d bytes from a superseded edge: %q", n, buf[:n])
	} else if err == nil {
		t.Fatal("local conn read succeeded without bytes")
	}

	if got := l.staleWrites.Load(); got == 0 {
		t.Fatal("staleWrites = 0, want the superseded write counted; without the count this failure is invisible in production")
	}
}

// The fence is scoped to the superseded edge only: the edge that replaced it
// must still deliver, or the link is simply broken.
func TestLinkCurrentEdgeStillWritesLocal(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	l := newTestLink(t, e, peerKey, failOpen)
	local := attachLocal(t, l)

	zA := newZombieEdge(nil)
	t.Cleanup(func() { zA.Close() })
	if !l.publishOwn(zA) {
		t.Fatal("link refused the presentation")
	}
	waitFor(t, 3*time.Second, func() bool { return zA.reading() })

	zB := newZombieEdge(nil)
	t.Cleanup(func() { zB.Close() })
	if !l.adopt(zB, "test") {
		t.Fatal("link refused the adoption")
	}
	waitFor(t, 3*time.Second, func() bool { return zB.reading() })

	zB.feed([]byte("LIVE"))
	local.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, err := local.Read(buf)
	if err != nil {
		t.Fatalf("read from local: %v", err)
	}
	if got := string(buf[:n]); got != "LIVE" {
		t.Fatalf("local received %q, want %q", got, "LIVE")
	}
	if got := l.staleWrites.Load(); got != 0 {
		t.Fatalf("staleWrites = %d on a healthy link, want 0", got)
	}
}

// gRPC does not allow two goroutines in SendMsg on one stream. Two serveEdge
// goroutines overlapping on a local conn — which the supersede window makes
// possible — is exactly that, so the conn must serialize its sends.
func TestStreamConnSerializesConcurrentWrites(t *testing.T) {
	s := &overlapStream{}
	c := newStreamConn(s, func() {})
	defer c.Close()

	payload := []byte("frame bytes")
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				if _, err := c.Write(payload); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()

	if got := s.maxInFlight.Load(); got > 1 {
		t.Fatalf("%d Sends overlapped on one stream, want 1: gRPC forbids concurrent SendMsg on a stream", got)
	}
}

// overlapStream records the high-water mark of concurrent Sends.
type overlapStream struct {
	inFlight    atomic.Int64
	maxInFlight atomic.Int64
}

func (s *overlapStream) Send([]byte) error {
	n := s.inFlight.Add(1)
	for {
		m := s.maxInFlight.Load()
		if n <= m || s.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	runtime.Gosched()
	s.inFlight.Add(-1)
	return nil
}

func (s *overlapStream) Recv() ([]byte, error) { return nil, io.EOF }

func (s *overlapStream) Context() context.Context { return context.Background() }

// zombieEdge is a peer edge that keeps serving after Close — the hazard the
// supersede window opens, modelled rather than hoped away. It hands over
// pending once after being closed, then errors like any closed conn.
type zombieEdge struct {
	ch      chan []byte
	closed  chan struct{}
	pending []byte

	once     sync.Once
	closeOne sync.Once
	inRead   atomic.Bool
}

func newZombieEdge(pending []byte) *zombieEdge {
	return &zombieEdge{
		ch:      make(chan []byte, 4),
		closed:  make(chan struct{}),
		pending: pending,
	}
}

func (z *zombieEdge) reading() bool { return z.inRead.Load() }

func (z *zombieEdge) feed(p []byte) { z.ch <- p }

func (z *zombieEdge) Read(b []byte) (int, error) {
	z.inRead.Store(true)
	defer z.inRead.Store(false)
	select {
	case p := <-z.ch:
		return copy(b, p), nil
	case <-z.closed:
		var p []byte
		leaked := false
		z.once.Do(func() { p, leaked = z.pending, true })
		if leaked {
			return copy(b, p), nil
		}
		return 0, net.ErrClosed
	}
}

func (z *zombieEdge) Write(b []byte) (int, error) { return len(b), nil }

func (z *zombieEdge) Close() error {
	z.closeOne.Do(func() { close(z.closed) })
	return nil
}

func (z *zombieEdge) LocalAddr() net.Addr              { return dummyAddr{} }
func (z *zombieEdge) RemoteAddr() net.Addr             { return dummyAddr{} }
func (z *zombieEdge) SetDeadline(time.Time) error      { return nil }
func (z *zombieEdge) SetReadDeadline(time.Time) error  { return nil }
func (z *zombieEdge) SetWriteDeadline(time.Time) error { return nil }
