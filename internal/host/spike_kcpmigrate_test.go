package host

// ---------------------------------------------------------------------------
// THROWAWAY SPIKE -- p2p KCP session migration (relay -> direct).
//
// Hypothesis: a long-lived kcp.UDPSession created once over a caller-owned
// net.PacketConn (ownConn=false) survives replacing the packet path underneath
// it, because KCP's own ARQ (snd_buf / seq / ACK) retransmits unacked segments
// on the new path. If true, the byte stream is preserved exactly and the smux
// layer above never notices the cutover.
//
// This file touches no production code. Delete it once the spike is answered.
//
// Mechanism modelled: the proposed extension of relayKCPPair -- one KCP session
// on top of a swappable PacketConn that (a) always reads both paths and (b)
// sends on the currently preferred path. kcp-go's defaultReadLoop
// (readloop.go:43) locks the source address from s.remote after the first
// packet and drops any packet whose ReadFrom addr differs, so the unified
// PacketConn must present a STABLE logical address (dummyAddr{} here, exactly
// as relayPacketConn already does).
// ---------------------------------------------------------------------------

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// spikeMedium is one direction of one path. send enqueues a datagram; recv
// dequeues. Faults (drop-all / duplicate / adjacent-swap) are toggled by the
// test to model the transition window. A full queue drops, like a lossy path.
type spikeMedium struct {
	ch   chan []byte
	sent atomic.Int64 // every send attempt: proves the path was actually used

	dropAll atomic.Bool
	dup     atomic.Bool
	swap    atomic.Bool

	mu      sync.Mutex
	pending []byte // held back for adjacent-swap
}

func newSpikeMedium() *spikeMedium {
	return &spikeMedium{ch: make(chan []byte, 4096)}
}

func (m *spikeMedium) send(p []byte) {
	m.sent.Add(1)
	if m.dropAll.Load() {
		return
	}
	cp := append([]byte(nil), p...)
	if m.dup.Load() {
		select {
		case m.ch <- append([]byte(nil), p...):
		default:
		}
	}
	if m.swap.Load() {
		m.mu.Lock()
		if m.pending == nil {
			m.pending = cp
			m.mu.Unlock()
			return
		}
		held := m.pending
		m.pending = cp
		m.mu.Unlock()
		m.deliver(held)
		return
	}
	// Not swapping: flush anything held first, then this packet.
	m.mu.Lock()
	held := m.pending
	m.pending = nil
	m.mu.Unlock()
	if held != nil {
		m.deliver(held)
	}
	m.deliver(cp)
}

func (m *spikeMedium) flush() {
	m.mu.Lock()
	held := m.pending
	m.pending = nil
	m.mu.Unlock()
	if held != nil {
		m.deliver(held)
	}
}

func (m *spikeMedium) deliver(p []byte) {
	select {
	case m.ch <- p:
	default:
		// full: drop, exactly like a lossy path
	}
}

func (m *spikeMedium) recv() <-chan []byte { return m.ch }

// spikeSwitchConn is a net.PacketConn whose send path flips at runtime and
// which always reads both paths (dual-read). Stable dummyAddr{} on every read
// keeps kcp-go's source-address lock happy across the switch.
type spikeSwitchConn struct {
	relayOut  *spikeMedium
	directOut *spikeMedium
	relayIn   *spikeMedium
	directIn  *spikeMedium

	sendDirect atomic.Bool
	// recvBoth defaults true (dual-read). The negative control turns it off to
	// show that reading only one path starves the session after a switch.
	recvBoth   atomic.Bool
	recvDirect atomic.Bool
	done       chan struct{}
	closeOnce  sync.Once
}

func (c *spikeSwitchConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.sendDirect.Load() {
		c.directOut.send(b)
	} else {
		c.relayOut.send(b)
	}
	return len(b), nil
}

func (c *spikeSwitchConn) readOne(b []byte, m *spikeMedium) (int, net.Addr, error) {
	select {
	case p := <-m.recv():
		return copy(b, p), dummyAddr{}, nil
	case <-c.done:
		select {
		case p := <-m.recv():
			return copy(b, p), dummyAddr{}, nil
		default:
		}
		return 0, nil, io.EOF
	}
}

func (c *spikeSwitchConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if !c.recvBoth.Load() {
		if c.recvDirect.Load() {
			return c.readOne(b, c.directIn)
		}
		return c.readOne(b, c.relayIn)
	}
	select {
	case p := <-c.relayIn.recv():
		return copy(b, p), dummyAddr{}, nil
	case p := <-c.directIn.recv():
		return copy(b, p), dummyAddr{}, nil
	case <-c.done:
		// Drain one buffered packet before EOF, like relayPacketConn.
		select {
		case p := <-c.relayIn.recv():
			return copy(b, p), dummyAddr{}, nil
		default:
		}
		select {
		case p := <-c.directIn.recv():
			return copy(b, p), dummyAddr{}, nil
		default:
		}
		return 0, nil, io.EOF
	}
}

func (c *spikeSwitchConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

func (c *spikeSwitchConn) LocalAddr() net.Addr             { return dummyAddr{} }
func (c *spikeSwitchConn) RemoteAddr() net.Addr            { return dummyAddr{} }
func (c *spikeSwitchConn) SetDeadline(time.Time) error     { return nil }
func (c *spikeSwitchConn) SetReadDeadline(time.Time) error { return nil }
func (c *spikeSwitchConn) SetWriteDeadline(time.Time) error {
	return nil
}

// spikePair is two KCP sessions over two swappable conns cross-wired through
// two independent paths (relay, direct).
type spikePair struct {
	connA, connB *spikeSwitchConn
	sessA, sessB *kcp.UDPSession

	relayAB, relayBA   *spikeMedium
	directAB, directBA *spikeMedium
}

func newSpikePair(t *testing.T) *spikePair {
	t.Helper()
	relayAB, relayBA := newSpikeMedium(), newSpikeMedium()
	directAB, directBA := newSpikeMedium(), newSpikeMedium()

	connA := &spikeSwitchConn{
		relayOut: relayAB, directOut: directAB,
		relayIn: relayBA, directIn: directBA,
		done: make(chan struct{}),
	}
	connA.recvBoth.Store(true)
	connB := &spikeSwitchConn{
		relayOut: relayBA, directOut: directBA,
		relayIn: relayAB, directIn: directAB,
		done: make(chan struct{}),
	}
	connB.recvBoth.Store(true)

	const conv = uint32(0x5eed5eed)
	sessA, err := kcp.NewConn4(conv, dummyAddr{}, nil, 0, 0, false, connA)
	if err != nil {
		t.Fatal(err)
	}
	sessB, err := kcp.NewConn4(conv, dummyAddr{}, nil, 0, 0, false, connB)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []*kcp.UDPSession{sessA, sessB} {
		s.SetNoDelay(1, 10, 2, 1)
		s.SetMtu(1400)
		s.SetWindowSize(512, 512)
	}
	p := &spikePair{
		connA: connA, connB: connB,
		sessA: sessA, sessB: sessB,
		relayAB: relayAB, relayBA: relayBA,
		directAB: directAB, directBA: directBA,
	}
	t.Cleanup(func() {
		sessA.Close()
		sessB.Close()
		connA.Close()
		connB.Close()
	})
	return p
}

func spikeWaitRead(t *testing.T, read *atomic.Int64, n int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for read.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("reader stalled at %d bytes (want >= %d)", read.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func spikeFirstMismatch(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

// TestSpikeKCPMigrationByteStream streams one payload while flipping the
// underlying path from relay to direct, with a black-hole burst on the new
// path, then reordering, then duplication. The bytes read must equal the bytes
// written, exactly once, in order.
func TestSpikeKCPMigrationByteStream(t *testing.T) {
	p := newSpikePair(t)

	const total = 8 << 20
	expected := make([]byte, total)
	rand.New(rand.NewSource(0x5eed)).Read(expected)
	got := make([]byte, total)

	var readBytes atomic.Int64
	var readErr, writeErr atomic.Value

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		off := 0
		for off < total {
			p.sessB.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := p.sessB.Read(got[off:])
			if err != nil {
				readErr.Store(err)
				return
			}
			off += n
			readBytes.Store(int64(off))
		}
	}()

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		off := 0
		const chunk = 64 << 10
		for off < total {
			end := off + chunk
			if end > total {
				end = total
			}
			n, err := p.sessA.Write(expected[off:end])
			if err != nil {
				writeErr.Store(err)
				return
			}
			off += n
		}
	}()

	// Phase 1: everything on relay; let the session establish and stream.
	spikeWaitRead(t, &readBytes, 512<<10, 30*time.Second)

	// Phase 2: A flips to direct UNILATERALLY and the new path starts as a
	// black hole. KCP must hold the unacked segments and retransmit them once
	// the hole clears. B still sends on relay. This is the cutover window.
	p.connA.sendDirect.Store(true)
	p.directAB.dropAll.Store(true)
	time.Sleep(200 * time.Millisecond)
	p.directAB.dropAll.Store(false)

	// Phase 3: B flips too; direct now carries both directions, reordered.
	p.directBA.swap.Store(true)
	spikeWaitRead(t, &readBytes, 2<<20, 30*time.Second)
	p.connB.sendDirect.Store(true)
	spikeWaitRead(t, &readBytes, 4<<20, 30*time.Second)
	p.directBA.swap.Store(false)
	p.directBA.flush()

	// Phase 4: duplicates on both direct directions; KCP must dedup by seq.
	p.directAB.dup.Store(true)
	p.directBA.dup.Store(true)
	spikeWaitRead(t, &readBytes, 6<<20, 30*time.Second)
	p.directAB.dup.Store(false)
	p.directBA.dup.Store(false)

	<-readerDone
	<-writerDone

	if err := readErr.Load(); err != nil {
		t.Fatalf("reader: %v", err)
	}
	if err := writeErr.Load(); err != nil {
		t.Fatalf("writer: %v", err)
	}
	if i := spikeFirstMismatch(got, expected); i >= 0 {
		t.Fatalf("byte stream corrupt at offset %d (got %d read)", i, readBytes.Load())
	}
	if p.directAB.sent.Load() == 0 || p.directBA.sent.Load() == 0 {
		t.Fatalf("direct path never carried traffic: AB=%d BA=%d",
			p.directAB.sent.Load(), p.directBA.sent.Load())
	}
	t.Logf("byte-stream migration OK: relayAB=%d relayBA=%d directAB=%d directBA=%d",
		p.relayAB.sent.Load(), p.relayBA.sent.Load(),
		p.directAB.sent.Load(), p.directBA.sent.Load())
}

// TestSpikeSmuxOverKCPMigration is the production-shaped case: smux runs on top
// of the migrated KCP session, and a stream opened before the cutover must
// finish uncorrupted after it.
func TestSpikeSmuxOverKCPMigration(t *testing.T) {
	p := newSpikePair(t)

	srv, err := smux.Server(p.sessA, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := smux.Client(p.sessB, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	const total = 4 << 20
	expected := make([]byte, total)
	rand.New(rand.NewSource(0xbeef)).Read(expected)

	var readBytes atomic.Int64
	var readErr atomic.Value
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		stream, err := srv.AcceptStream()
		if err != nil {
			readErr.Store(err)
			return
		}
		defer stream.Close()
		got := make([]byte, total)
		off := 0
		for off < total {
			stream.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := stream.Read(got[off:])
			if err != nil {
				readErr.Store(err)
				return
			}
			off += n
			readBytes.Store(int64(off))
		}
		if i := spikeFirstMismatch(got, expected); i >= 0 {
			readErr.Store(fmt.Errorf("smux stream corrupt at offset %d", i))
		}
	}()

	stream, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		off := 0
		const chunk = 32 << 10
		for off < total {
			end := off + chunk
			if end > total {
				end = total
			}
			n, err := stream.Write(expected[off:end])
			if err != nil {
				readErr.Store(err)
				return
			}
			off += n
		}
		stream.Close()
	}()

	spikeWaitRead(t, &readBytes, 256<<10, 30*time.Second)
	p.connA.sendDirect.Store(true)
	p.directAB.dropAll.Store(true)
	time.Sleep(200 * time.Millisecond)
	p.directAB.dropAll.Store(false)
	p.directBA.dup.Store(true)
	spikeWaitRead(t, &readBytes, 1<<20, 30*time.Second)
	p.connB.sendDirect.Store(true)
	spikeWaitRead(t, &readBytes, 2<<20, 30*time.Second)
	p.directBA.dup.Store(false)

	<-serverDone
	<-writerDone
	if err := readErr.Load(); err != nil {
		t.Fatalf("smux over KCP after migration: %v", err)
	}
	t.Logf("smux-over-KCP migration OK: relayAB=%d relayBA=%d directAB=%d directBA=%d",
		p.relayAB.sent.Load(), p.relayBA.sent.Load(),
		p.directAB.sent.Load(), p.directBA.sent.Load())
}

// TestSpikeNegativeWithoutDualRead is the negative control for the design
// choice "the unified conn must read both paths". B reads only relay; A flips
// its send path to direct. A's session must starve (B never sees the new-path
// packets, so it never ACKs them), proving dual-read is load-bearing rather
// than incidental.
func TestSpikeNegativeWithoutDualRead(t *testing.T) {
	p := newSpikePair(t)
	p.connB.recvBoth.Store(false) // B reads only relay, and keeps sending relay

	const total = 4 << 20
	expected := make([]byte, total)
	rand.New(rand.NewSource(0xdead)).Read(expected)
	got := make([]byte, total)

	var readBytes atomic.Int64
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		off := 0
		for off < total {
			p.sessB.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := p.sessB.Read(got[off:])
			if err != nil {
				return // parked out / starved; readBytes freezes here
			}
			off += n
			readBytes.Store(int64(off))
		}
	}()

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		off := 0
		const chunk = 64 << 10
		for off < total {
			end := off + chunk
			if end > total {
				end = total
			}
			n, err := p.sessA.Write(expected[off:end])
			if err != nil {
				return // window full + session closed at cleanup
			}
			off += n
		}
	}()

	// Stream on relay, then A flips send to direct while B still reads only
	// relay. B's reader must stall well short of total.
	spikeWaitRead(t, &readBytes, 256<<10, 30*time.Second)
	p.connA.sendDirect.Store(true)
	time.Sleep(1500 * time.Millisecond)

	if got := readBytes.Load(); got >= total {
		t.Fatalf("expected a stall without dual-read, but read %d/%d", got, total)
	} else {
		t.Logf("negative control OK: stalled at %d/%d without dual-read", got, total)
	}
	// Do not wait on writerDone: the writer is parked in sessA.Write on the
	// full window. Cleanup closes the sessions, which wakes it.
	<-readerDone
}
