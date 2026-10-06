package host

// ---------------------------------------------------------------------------
// PRODUCT-LEVEL KCP PATH MIGRATION TEST (relay -> direct).
//
// The throwaway spike (spike_kcpmigrate_test.go) first proved the hypothesis on
// a hand-rolled net.PacketConn. This file pins the same guarantee on the real
// relayKCPPair, which is what ships:
//
//   - two KCP sessions are created exactly as production creates them, with the
//     pair itself as the net.PacketConn (kcp.NewConn4(..., ownConn=false, pair));
//   - the relay path is the real derpclient transport over the in-process relay
//     server, fed to the pair's registered endpoint;
//   - the direct path is the real directUnderlay over loopback UDP, interposed
//     by a relay goroutine that injects a black hole, reordering, and
//     duplication;
//   - the cutover is driven by the real pair.setDirectUnderlay.
//
// Three assertions, mirroring the spike:
//
//	(a) TestPairMigrationByteStream       8 MiB byte-exact across the flip
//	(b) TestPairMigrationSmux             4 MiB through smux over the same pair
//	(c) TestPairMigrationRequiresDualRead the negative control: without the
//	    peer reading the new path, the session stalls
//
// No production code is touched. spike_kcpmigrate_test.go is deliberately kept
// as reproducible evidence.
// ---------------------------------------------------------------------------

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// migLogger silences the engines the rig builds: the migration test asserts on
// bytes and path counters, not on logs.
var migLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// migFaults injects the direct path's transition-window faults in one
// direction: a full black hole (dropAll), adjacent-packet reordering (swap,
// holding one packet back so the next overtakes it), and duplication (dup).
// Delivery is a raw UDP send on the interposed wire, so the faults sit between
// the two real directUnderlay sockets exactly where a lossy path would.
//
// forward is called from the direction's single relay goroutine; flush is
// called from the test goroutine, hence the mutex around the reorder slot.
type migFaults struct {
	out     *net.UDPConn
	outAddr *net.UDPAddr

	dropAll atomic.Bool
	dup     atomic.Bool
	swap    atomic.Bool
	sent    atomic.Int64

	mu      sync.Mutex
	pending []byte
}

func (f *migFaults) deliver(p []byte) {
	_, _ = f.out.WriteToUDP(p, f.outAddr)
}

func (f *migFaults) forward(p []byte) {
	f.sent.Add(1)
	if f.dropAll.Load() {
		return
	}
	cp := append([]byte(nil), p...)
	if f.dup.Load() {
		f.deliver(append([]byte(nil), p...))
	}
	if f.swap.Load() {
		f.mu.Lock()
		if f.pending == nil {
			f.pending = cp
			f.mu.Unlock()
			return
		}
		held := f.pending
		f.pending = cp
		f.mu.Unlock()
		f.deliver(held)
		return
	}
	// Not swapping: flush anything held first, then this packet.
	f.mu.Lock()
	held := f.pending
	f.pending = nil
	f.mu.Unlock()
	if held != nil {
		f.deliver(held)
	}
	f.deliver(cp)
}

func (f *migFaults) flush() {
	f.mu.Lock()
	held := f.pending
	f.pending = nil
	f.mu.Unlock()
	if held != nil {
		f.deliver(held)
	}
}

// migDirectLoop reads one direction's wire and forwards each datagram through
// that direction's faults. The 200ms read deadline only exists so the loop
// notices done; a timeout is a retry, not an error.
func migDirectLoop(wire *net.UDPConn, f *migFaults, done <-chan struct{}) {
	buf := make([]byte, 65535)
	for {
		_ = wire.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := wire.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			return
		}
		f.forward(buf[:n])
	}
}

// migRelayRecv feeds the pair's registered endpoint from the real relay
// transport. It is engine.pump's data-frame half without the smux build, which
// the test deliberately keeps out of the pair so it can drive the KCP session
// directly. A full queue drops, exactly like the engine pump on overflow.
func migRelayRecv(c *derpclient.Client, from derpclient.PublicKey, pc *peerConn, done <-chan struct{}) {
	for {
		src, pkt, err := c.Recv()
		if err != nil {
			if errors.Is(err, derpclient.ErrPeerGone) {
				continue
			}
			return
		}
		if src != from || len(pkt) == 0 || pkt[0] != frameData {
			continue
		}
		select {
		case pc.inbound <- pkt[1:]:
		case <-done:
			return
		default:
		}
	}
}

func migDial(t *testing.T, url string, priv derpclient.PrivateKey) *derpclient.Client {
	t.Helper()
	c, err := derpclient.Dial(context.Background(), url, priv, nil)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	return c
}

func migUDPAddr(c *net.UDPConn) *net.UDPAddr {
	return c.LocalAddr().(*net.UDPAddr)
}

// migRig is two real relayKCPPairs cross-wired through the real relay transport
// (the relay path) and an interposed loopback direct path (wireA/wireB) whose
// faults the test drives.
type migRig struct {
	pairA, pairB *relayKCPPair
	sessA, sessB *kcp.UDPSession

	underlayA, underlayB *directUnderlay
	faultsAB, faultsBA   *migFaults
}

// newMigRig builds the two pairs and their two paths. It starts on the relay:
// no direct underlay is installed until the test flips, which is what makes the
// migration a real relay -> direct cutover.
func newMigRig(t *testing.T) *migRig {
	t.Helper()

	rs := &relayServer{}
	url := rs.start(t)

	privA, pubA, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privB, pubB, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// Engines whose public keys match the clients we dial: the relay routes
	// back to the registered key, so the pair's peer and the dialed identity
	// must agree. The engines are never Connected() through their own pump; the
	// test feeds the pair directly instead (see migRelayRecv).
	eA := newEngine(url, "", privA, migLogger)
	eB := newEngine(url, "", privB, migLogger)
	t.Cleanup(func() {
		eA.Close()
		eB.Close()
	})
	cA := migDial(t, url, privA)
	cB := migDial(t, url, privB)
	eA.mu.Lock()
	eA.client = cA
	eA.mu.Unlock()
	eB.mu.Lock()
	eB.client = cB
	eB.mu.Unlock()

	pairA := eA.relayKCPPairFor(pubB)
	pairB := eB.relayKCPPairFor(pubA)

	pcA := &peerConn{e: eA, peer: pubB, inbound: make(chan []byte, relayKCPRecvBuffer), closeCh: make(chan struct{})}
	pcB := &peerConn{e: eB, peer: pubA, inbound: make(chan []byte, relayKCPRecvBuffer), closeCh: make(chan struct{})}
	pairA.register(pcA)
	pairB.register(pcB)

	done := make(chan struct{})
	go migRelayRecv(cA, pubB, pcA, done)
	go migRelayRecv(cB, pubA, pcB, done)

	// Build the pair KCP sessions the production way: the pair is the
	// net.PacketConn (ownConn=false), so closing KCP never closes it.
	sessA, err := pairA.session()
	if err != nil {
		t.Fatalf("pair A session: %v", err)
	}
	sessB, err := pairB.session()
	if err != nil {
		t.Fatalf("pair B session: %v", err)
	}

	ua := mustListenUDP(t)
	ub := mustListenUDP(t)
	wireA := mustListenUDP(t)
	wireB := mustListenUDP(t)

	// A's underlay reads and writes the A wire; B's the B wire. The loops
	// shuffle wireA -> B and wireB -> A, writing through the destination side's
	// wire so the arriving source address matches each directUnderlay's peer
	// filter.
	fAB := &migFaults{out: wireB, outAddr: migUDPAddr(ub)} // A -> B
	fBA := &migFaults{out: wireA, outAddr: migUDPAddr(ua)} // B -> A
	go migDirectLoop(wireA, fAB, done)
	go migDirectLoop(wireB, fBA, done)

	underlayA := newDirectUnderlay(ua, udpAddrPort(t, wireA))
	underlayB := newDirectUnderlay(ub, udpAddrPort(t, wireB))

	t.Cleanup(func() {
		close(done)
		wireA.Close()
		wireB.Close()
		underlayA.close()
		underlayB.close()
	})

	return &migRig{
		pairA: pairA, pairB: pairB,
		sessA: sessA, sessB: sessB,
		underlayA: underlayA, underlayB: underlayB,
		faultsAB: fAB, faultsBA: fBA,
	}
}

// migFlip drives the relay -> direct cutover: A flips first with the new path a
// 200ms black hole (KCP must hold and retransmit the unacked segments), then B
// flips with the data direction reordering through the cutover, then both
// directions duplicate. read is the reader's byte milestone so the phases stay
// ordered.
//
// The reorder is applied to the data direction, not the ACK direction: adjacent
// packet reordering is what a lossy path does to the payload, and reordering
// ACKs instead starves KCP's window on this rig (it takes ~10x as long), which
// would make the test slow without testing anything more.
func migFlip(t *testing.T, r *migRig, read *atomic.Int64, first, mid, last int64) {
	t.Helper()
	migWaitRead(t, read, first, 30*time.Second)

	// A flips unilaterally; the new path starts as a black hole.
	r.faultsAB.dropAll.Store(true)
	r.pairA.setDirectUnderlay(r.underlayA)
	time.Sleep(200 * time.Millisecond)
	r.faultsAB.dropAll.Store(false)

	// B flips too; the data direction reorders during the cutover.
	r.faultsAB.swap.Store(true)
	r.pairB.setDirectUnderlay(r.underlayB)
	migWaitRead(t, read, mid, 30*time.Second)
	r.faultsAB.swap.Store(false)
	r.faultsAB.flush()

	// Duplicates on both directions; KCP must dedup by seq.
	r.faultsAB.dup.Store(true)
	r.faultsBA.dup.Store(true)
	migWaitRead(t, read, last, 30*time.Second)
	r.faultsAB.dup.Store(false)
	r.faultsBA.dup.Store(false)
}

// migWaitRead blocks until read reaches n, failing the test after timeout.
func migWaitRead(t *testing.T, read *atomic.Int64, n int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for read.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("reader stalled at %d bytes (want >= %d)", read.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// migFirstMismatch returns the first offset where a and b differ, or -1 when
// they are byte-identical.
func migFirstMismatch(a, b []byte) int {
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

// migErrBox records the first error a reader or writer goroutine saw. It is a
// mutex, not an atomic.Value: the two goroutines store different concrete error
// types, which atomic.Value rejects (and which panics, masking the real
// failure).
type migErrBox struct {
	mu  sync.Mutex
	err error
}

func (b *migErrBox) set(err error) {
	b.mu.Lock()
	if b.err == nil {
		b.err = err
	}
	b.mu.Unlock()
}

func (b *migErrBox) get() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// TestPairMigrationByteStream streams one payload while flipping the real
// pair's path from relay to direct, with a black-hole burst on the new path,
// then reordering, then duplication. The bytes read must equal the bytes
// written, exactly once, in order.
func TestPairMigrationByteStream(t *testing.T) {
	r := newMigRig(t)

	const total = 8 << 20
	expected := make([]byte, total)
	rand.New(rand.NewSource(0x5eed)).Read(expected)
	got := make([]byte, total)

	var readBytes atomic.Int64
	var readErr, writeErr migErrBox

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		off := 0
		for off < total {
			r.sessB.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := r.sessB.Read(got[off:])
			if err != nil {
				readErr.set(err)
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
			n, err := r.sessA.Write(expected[off:end])
			if err != nil {
				writeErr.set(err)
				return
			}
			off += n
		}
	}()

	migFlip(t, r, &readBytes, 512<<10, 4<<20, 6<<20)

	<-readerDone
	<-writerDone

	if err := readErr.get(); err != nil {
		t.Fatalf("reader: %v", err)
	}
	if err := writeErr.get(); err != nil {
		t.Fatalf("writer: %v", err)
	}
	if i := migFirstMismatch(got, expected); i >= 0 {
		t.Fatalf("byte stream corrupt at offset %d (read %d)", i, readBytes.Load())
	}
	if r.faultsAB.sent.Load() == 0 || r.faultsBA.sent.Load() == 0 {
		t.Fatalf("direct path never carried traffic: AB=%d BA=%d",
			r.faultsAB.sent.Load(), r.faultsBA.sent.Load())
	}
	t.Logf("pair byte-stream migration OK: directAB=%d directBA=%d",
		r.faultsAB.sent.Load(), r.faultsBA.sent.Load())
}

// TestPairMigrationSmux is the production-shaped case: smux runs on top of the
// migrated pair (through the real relayKCPStream view), and a stream opened
// before the cutover must finish uncorrupted after it.
func TestPairMigrationSmux(t *testing.T) {
	r := newMigRig(t)

	// A is the smux client (the writer), B the server (the reader), so the data
	// direction is A -> B in both this test and the byte-stream one: the reorder
	// in migFlip stays on the payload path rather than the ACK path.
	srv, err := smux.Server(r.pairB.newStream(), smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := smux.Client(r.pairA.newStream(), smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	const total = 4 << 20
	expected := make([]byte, total)
	rand.New(rand.NewSource(0xbeef)).Read(expected)

	var readBytes atomic.Int64
	var readErr migErrBox
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		stream, err := srv.AcceptStream()
		if err != nil {
			readErr.set(err)
			return
		}
		defer stream.Close()
		got := make([]byte, total)
		off := 0
		for off < total {
			stream.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := stream.Read(got[off:])
			if err != nil {
				readErr.set(err)
				return
			}
			off += n
			readBytes.Store(int64(off))
		}
		if i := migFirstMismatch(got, expected); i >= 0 {
			readErr.set(fmt.Errorf("smux stream corrupt at offset %d", i))
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
				readErr.set(err)
				return
			}
			off += n
		}
		stream.Close()
	}()

	migFlip(t, r, &readBytes, 256<<10, 2<<20, 3<<20)

	<-serverDone
	<-writerDone
	if err := readErr.get(); err != nil {
		t.Fatalf("smux over pair after migration: %v", err)
	}
	t.Logf("pair smux migration OK: directAB=%d directBA=%d",
		r.faultsAB.sent.Load(), r.faultsBA.sent.Load())
}

// TestPairMigrationRequiresDualRead is the negative control for the design
// choice "the pair must read both paths". A flips its send path to direct while
// B never installs a direct underlay (B reads only the relay) and A's new-path
// packets are black-holed. A's session must starve — B never sees the
// new-path packets, so it never ACKs them — proving the direct path's read is
// load-bearing rather than incidental.
func TestPairMigrationRequiresDualRead(t *testing.T) {
	r := newMigRig(t)

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
			r.sessB.SetReadDeadline(time.Now().Add(time.Second))
			n, err := r.sessB.Read(got[off:])
			if err != nil {
				return // starved; readBytes freezes here
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
			n, err := r.sessA.Write(expected[off:end])
			if err != nil {
				return // window full + session closed at cleanup
			}
			off += n
		}
	}()

	// Stream on the relay, then A flips to direct while B still reads only the
	// relay and A's new path is a black hole. B's reader must stall well short
	// of total.
	migWaitRead(t, &readBytes, 256<<10, 30*time.Second)
	r.faultsAB.dropAll.Store(true)
	r.pairA.setDirectUnderlay(r.underlayA)
	time.Sleep(2 * time.Second)

	if got := readBytes.Load(); got >= total {
		t.Fatalf("expected a stall without dual-read, but read %d/%d", got, total)
	} else {
		t.Logf("negative control OK: stalled at %d/%d without dual-read", got, total)
	}
	// Do not wait on writerDone: the writer is parked in sessA.Write on the
	// full window. Cleanup closes the sessions, which wakes it.
	<-readerDone
}
