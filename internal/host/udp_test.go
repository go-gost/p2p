package host

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// newTestEngine builds an engine with no relay: enough for the link-level
// tests, which drive the edges by hand instead of dialling a peer.
func newTestEngine(t *testing.T) *engine {
	t.Helper()
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)
	return e
}

// failOpen is the injected opener for tests that drive the edges themselves:
// the presenter's attempts fail, so it never publishes one behind the test.
func failOpen(string) (net.Conn, error) { return nil, errors.New("test: no opener") }

// newTestLink creates a registered link whose presentation is driven by open.
func newTestLink(t *testing.T, e *engine, peer derpclient.PublicKey, open func(string) (net.Conn, error)) *link {
	t.Helper()
	e.openStream = open
	l := newLink(e, peer)
	e.addLink(l)
	t.Cleanup(func() {
		e.removeLink(l)
		l.close()
	})
	return l
}

// attachLocal attaches a pipe end as the link's local edge (standing in for a
// gost tunnel's stream) and returns the test's end.
func attachLocal(t *testing.T, l *link) net.Conn {
	t.Helper()
	local, side := net.Pipe()
	t.Cleanup(func() { side.Close() })
	l.attach(local)
	return side
}

// publishEdge publishes a pipe end as the link's presentation edge and returns
// the test's end.
func publishEdge(t *testing.T, l *link) net.Conn {
	t.Helper()
	edge, side := net.Pipe()
	t.Cleanup(func() { side.Close() })
	if !l.publishOwn(edge) {
		t.Fatal("link refused the presentation")
	}
	return side
}

// waitBuffered waits until the link holds n buffered bytes.
func waitBuffered(t *testing.T, l *link, n int) {
	t.Helper()
	waitFor(t, 3*time.Second, func() bool {
		l.wmu.Lock()
		defer l.wmu.Unlock()
		return len(l.wbuf) == n
	})
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// TestLinkBytePipe drives the link in both directions: bytes written on the
// local edge come out of the peer edge verbatim, and vice versa. The host
// never parses them (framing is the GOST side's job).
func TestLinkBytePipe(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	l := newTestLink(t, e, peerKey, failOpen)
	local := attachLocal(t, l)
	peerSide := publishEdge(t, l)

	go local.Write([]byte("first"))
	if got := string(readN(t, peerSide, 5)); got != "first" {
		t.Fatalf("peer received %q, want first", got)
	}
	go peerSide.Write([]byte("answer"))
	if got := string(readN(t, local, 6)); got != "answer" {
		t.Fatalf("local received %q, want answer", got)
	}
}

// TestLinkBuffersFirstDatagram is the R2 regression: the datagram that triggers
// a dial arrives before the presentation is up, and must not be lost. The link
// holds it until an edge is published, then flushes it in order.
func TestLinkBuffersFirstDatagram(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	l := newTestLink(t, e, peerKey, failOpen)
	local := attachLocal(t, l)

	go local.Write([]byte("first")) // no peer edge yet
	waitBuffered(t, l, 5)

	peerSide := publishEdge(t, l)
	if got := string(readN(t, peerSide, 5)); got != "first" {
		t.Fatalf("peer received %q, want first (the buffered datagram was dropped)", got)
	}

	// The buffer is drained: later datagrams ride the edge directly.
	go local.Write([]byte("second"))
	if got := string(readN(t, peerSide, 6)); got != "second" {
		t.Fatalf("peer received %q, want second", got)
	}
}

// TestLinkBufferCapDrops: the first-datagram buffer is bounded. Beyond the cap
// new bytes are dropped — the buffer keeps a dial's opening datagrams, it is
// not an unbounded queue.
func TestLinkBufferCapDrops(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	l := newTestLink(t, e, peerKey, failOpen)
	local := attachLocal(t, l)

	big := bytes.Repeat([]byte{'x'}, linkBufLimit+100)
	go local.Write(big)
	waitBuffered(t, l, linkBufLimit) // the tail is dropped, not queued

	peerSide := publishEdge(t, l)
	if got := readN(t, peerSide, linkBufLimit); !bytes.Equal(got, big[:linkBufLimit]) {
		t.Fatal("buffered payload mismatch")
	}
	peerSide.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := peerSide.Read(make([]byte, 8)); err == nil {
		t.Fatalf("read %d bytes past the cap, want nothing", n)
	}
}

// TestLinkAdoptReplacesPresentation: adopting an inbound edge supersedes the
// link's own presentation — the presentation is closed and the adopted edge
// carries both directions. An adopted edge is never displaced afterwards (see
// TestEngineAdoptableLink).
func TestLinkAdoptReplacesPresentation(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	l := newTestLink(t, e, peerKey, failOpen)
	local := attachLocal(t, l)
	own := publishEdge(t, l)

	adopted, adoptedSide := net.Pipe()
	t.Cleanup(func() { adoptedSide.Close() })
	if !l.adopt(adopted, "test") {
		t.Fatal("the link refused to adopt an inbound edge")
	}

	own.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := own.Read(make([]byte, 8)); err == nil {
		t.Fatal("the superseded presentation is still readable, want it closed")
	}

	go local.Write([]byte("out"))
	if got := string(readN(t, adoptedSide, 3)); got != "out" {
		t.Fatalf("adopted edge received %q, want out", got)
	}
	go adoptedSide.Write([]byte("in"))
	if got := string(readN(t, local, 2)); got != "in" {
		t.Fatalf("local received %q, want in", got)
	}
	if l.adoptable() {
		t.Fatal("a link holding an adopted edge is still adoptable")
	}
}

// TestEngineAdoptableLink covers the rendezvous rule: only the larger key
// adopts, and only a link that is waiting for an edge (none, or its own
// presentation). An adopted edge is never displaced, so a second inbound edge
// is served per stream instead of stealing the link.
func TestEngineAdoptableLink(t *testing.T) {
	e := newTestEngine(t)

	// e owns the larger key.
	var peer derpclient.PublicKey
	for {
		_, peer, _ = derpclient.Generate()
		if bytes.Compare(e.pub[:], peer[:]) > 0 {
			break
		}
	}
	l := newTestLink(t, e, peer, failOpen)
	if e.adoptableLink(peer) != l {
		t.Fatal("the larger key must adopt a link that is waiting for an edge")
	}

	publishEdge(t, l) // our own presentation: still adoptable
	if e.adoptableLink(peer) != l {
		t.Fatal("a link on its own presentation must still be adoptable")
	}

	adopted, adoptedSide := net.Pipe()
	t.Cleanup(func() { adoptedSide.Close() })
	if !l.adopt(adopted, "test") {
		t.Fatal("the link refused to adopt")
	}
	if got := e.adoptableLink(peer); got != nil {
		t.Fatal("a link holding an adopted edge must not be adoptable")
	}

	// The smaller key never adopts: it keeps its own presentation, and the
	// larger side adopts that one.
	e2 := newTestEngine(t)
	var peer2 derpclient.PublicKey
	for {
		_, peer2, _ = derpclient.Generate()
		if bytes.Compare(e2.pub[:], peer2[:]) < 0 {
			break
		}
	}
	newTestLink(t, e2, peer2, failOpen)
	if got := e2.adoptableLink(peer2); got != nil {
		t.Fatal("the smaller key must not adopt")
	}
}

// TestLinkRepresentsAfterEdgeDeath: when the presentation dies the link opens a
// new one (the peer restart / path-drop case), and it keeps presenting while it
// has no edge.
func TestLinkRepresentsAfterEdgeDeath(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()

	peerSides := make(chan net.Conn, 4)
	open := func(string) (net.Conn, error) {
		edge, side := net.Pipe()
		// The presenter writes the channel tag before handing the stream over
		// (openTaggedStream); on an unbuffered pipe that needs a reader.
		go func() {
			io.ReadFull(side, make([]byte, len(channelTag)))
		}()
		peerSides <- side
		return edge, nil
	}
	l := newTestLink(t, e, peerKey, open)

	first := <-peerSides
	waitFor(t, 3*time.Second, l.hasEdge) // the opener hands the edge out before publishing it

	first.Close() // the path drops
	select {
	case second := <-peerSides:
		if second == first {
			t.Fatal("the presenter re-published the dead edge")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the presenter did not re-present after the edge died")
	}
}

// TestPeekTag covers the stream classification: a tagged stream is reported as
// a channel, an untagged one is handed on with every byte it sent — including
// bytes consumed by a partial peek.
func TestPeekTag(t *testing.T) {
	// Tagged.
	c1, p1 := net.Pipe()
	defer c1.Close()
	defer p1.Close()
	go p1.Write([]byte(channelTag + "body"))
	if tagged, rest := peekTag(c1); !tagged {
		t.Fatal("tagged stream not recognised")
	} else {
		buf := make([]byte, 4)
		rest.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(rest, buf); err != nil || string(buf) != "body" {
			t.Fatalf("payload after tag = %q, %v", buf, err)
		}
	}

	// Untagged, whole prefix present: replayed byte for byte.
	c2, p2 := net.Pipe()
	defer c2.Close()
	go p2.Write([]byte("ping"))
	tagged, rest := peekTag(c2)
	if tagged {
		t.Fatal("untagged stream classified as a channel")
	}
	buf := make([]byte, 4)
	rest.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(rest, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("untagged payload = %q, %v (peeked bytes were not replayed)", buf, err)
	}
	p2.Close()

	// Untagged and idle: the peek must give up and hand the stream on, or a
	// protocol whose target speaks first would deadlock.
	old := channelTagTimeout
	channelTagTimeout = 50 * time.Millisecond
	defer func() { channelTagTimeout = old }()

	c3, p3 := net.Pipe()
	defer c3.Close()
	defer p3.Close()
	go p3.Write([]byte("ab")) // partial: never reaches 4 bytes
	start := time.Now()
	if tagged, _ := peekTag(c3); tagged {
		t.Fatal("idle stream classified as a channel")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("peek blocked for %s, want it bounded by channelTagTimeout", d)
	}
}

// startGreeter accepts and immediately writes a greeting, then holds the
// connection: the target-speaks-first shape that a blocking tag peek would
// deadlock.
func startGreeter(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.Write([]byte("hello"))
				io.Copy(io.Discard, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// TestEngineIdleStreamBridged proves an ordinary tunnel stream that stays
// silent is still bridged: the tag peek is bounded, so a target that speaks
// first is reached instead of waiting forever for client bytes.
func TestEngineIdleStreamBridged(t *testing.T) {
	old := channelTagTimeout
	channelTagTimeout = 100 * time.Millisecond
	defer func() { channelTagTimeout = old }()

	rs := &relayServer{}
	url := rs.start(t)
	greeter := startGreeter(t)

	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, greeter, privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	stream, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	buf := make([]byte, 5)
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read greeting: %v (silent stream was not bridged)", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("greeting = %q, want %q", buf, "hello")
	}
}

// TestLinkRetryDelay pins the presentation reconnect cadence: a stream that
// lived (peer restart / path drop) resets to the fast floor — that was the
// "tun-to-tun takes ~80s to reconnect" complaint — while an outright open
// failure doubles towards the punch backoff and never exceeds it. Assertions
// derive from the ambient backoffPeriod (TestMain shortens it for the package).
func TestLinkRetryDelay(t *testing.T) {
	if got := channelRetryDelay(backoffPeriod, false); got != channelRetryMin {
		t.Fatalf("after a live stream: delay = %v, want %v (fast reconnect)", got, channelRetryMin)
	}
	if got, want := channelRetryDelay(channelRetryMin, true), min(2*channelRetryMin, backoffPeriod); got != want {
		t.Fatalf("first open failure: delay = %v, want %v", got, want)
	}
	if got := channelRetryDelay(backoffPeriod, true); got != backoffPeriod {
		t.Fatalf("open failure at the cap: delay = %v, want %v", got, backoffPeriod)
	}
	if got := channelRetryDelay(backoffPeriod*4, true); got > backoffPeriod {
		t.Fatalf("open failure grew past the cap: %v > %v", got, backoffPeriod)
	}
}

// TestLinkCloseIdempotent: close is called by the record's drop and by the
// local pump's exit, so it must be safe twice and must end the carrier's park.
func TestLinkCloseIdempotent(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	l := newTestLink(t, e, peerKey, failOpen)
	local := attachLocal(t, l)

	l.close()
	l.close()

	select {
	case <-l.done:
	default:
		t.Fatal("close did not end the link")
	}
	// The local edge is closed with the link: a write fails.
	local.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := local.Write([]byte("x")); err == nil {
		t.Fatal("the local edge survived the link")
	}
}
