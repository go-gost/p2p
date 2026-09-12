package main

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// newTestEngine builds an engine with no relay: enough for the channel-level
// tests, which attach streams by hand instead of dialling a peer.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)
	return e
}

// newTestChannel creates a channel without starting the opener loop; the
// caller attaches the edges.
func newTestChannel(t *testing.T, e *Engine, peer derpclient.PublicKey) *channel {
	t.Helper()
	ch := &channel{
		e:    e,
		peer: peer,
		stop: make(chan struct{}),
	}
	t.Cleanup(func() { ch.teardown() })
	return ch
}

// attachStream serves c as the channel's peer edge (the real pump) and waits
// until the channel sees it.
func attachStream(t *testing.T, ch *channel, c net.Conn) {
	t.Helper()
	go ch.serveStream(c, "test")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ch.mu.Lock()
		up := ch.stream != nil
		ch.mu.Unlock()
		if up {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("channel peer edge was not published")
}

// attachLocal attaches a pipe end as the channel's local edge (standing in
// for a gost tunnel's stream) and returns the test's end.
func attachLocal(t *testing.T, ch *channel) net.Conn {
	t.Helper()
	local, side := net.Pipe()
	t.Cleanup(func() { side.Close() })
	ch.attachLocal(local)
	return side
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

// TestChannelBytePipe drives the channel in both directions: bytes written on
// the local edge come out of the peer edge verbatim, and vice versa. The host
// never parses them (framing is the GOST side's job).
func TestChannelBytePipe(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	ch := newTestChannel(t, e, peerKey)
	local := attachLocal(t, ch)

	upstream, peerSide := net.Pipe()
	t.Cleanup(func() { upstream.Close() })
	attachStream(t, ch, upstream)

	go local.Write([]byte("first"))
	if got := string(readN(t, peerSide, 5)); got != "first" {
		t.Fatalf("peer received %q, want first", got)
	}
	go peerSide.Write([]byte("answer"))
	if got := string(readN(t, local, 6)); got != "answer" {
		t.Fatalf("local received %q, want answer", got)
	}
}

// TestChannelLastLocalWins proves a newer gost dial takes over the channel's
// local edge: the previous edge is closed, and data follows the newest one.
func TestChannelLastLocalWins(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	ch := newTestChannel(t, e, peerKey)

	first := attachLocal(t, ch)
	upstream, peerSide := net.Pipe()
	t.Cleanup(func() { upstream.Close() })
	attachStream(t, ch, upstream)

	second := attachLocal(t, ch) // takes over; the previous edge ends

	first.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := first.Read(make([]byte, 8)); err == nil {
		t.Fatal("replaced local edge is still readable, want it closed")
	}

	go peerSide.Write([]byte("hello"))
	if got := string(readN(t, second, 5)); got != "hello" {
		t.Fatalf("new local received %q, want hello", got)
	}
	go second.Write([]byte("back"))
	if got := string(readN(t, peerSide, 4)); got != "back" {
		t.Fatalf("peer received %q, want back", got)
	}
}

// TestChannelDrops covers the lossy edges: bytes with no local are dropped
// (not buffered), bytes with the peer edge down are dropped, and flow resumes
// when the edge returns — IP tolerates loss.
func TestChannelDrops(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	ch := newTestChannel(t, e, peerKey)

	upstream, peerSide := net.Pipe()
	t.Cleanup(func() { upstream.Close() })
	attachStream(t, ch, upstream)

	// No local yet: peer bytes are dropped.
	go peerSide.Write([]byte("early"))
	time.Sleep(50 * time.Millisecond)

	local := attachLocal(t, ch)
	go peerSide.Write([]byte("late"))
	if got := string(readN(t, local, 4)); got != "late" {
		t.Fatalf("local received %q, want late (channel stopped serving)", got)
	}

	// Peer edge down: local bytes are dropped.
	upstream.Close()
	time.Sleep(50 * time.Millisecond) // let serveStream retire the edge
	go local.Write([]byte("void"))
	time.Sleep(50 * time.Millisecond)

	// Reconnected: flow resumes on the same local edge.
	upstream2, peerSide2 := net.Pipe()
	t.Cleanup(func() { upstream2.Close() })
	attachStream(t, ch, upstream2)
	go local.Write([]byte("again"))
	if got := string(readN(t, peerSide2, 5)); got != "again" {
		t.Fatalf("peer received %q, want again (flow did not resume)", got)
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

func waitStream(t *testing.T, ch *channel) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ch.mu.Lock()
		up := ch.stream != nil
		ch.mu.Unlock()
		if up {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("channel stream did not come up")
}

// TestEngineChannelRoundTrip is the happy path through two engines and the
// test relay: what one gost-side edge sends comes out of the other, bytes
// intact, in both directions.
func TestEngineChannelRoundTrip(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, "", privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	chA := engineA.openChannel(pubB)
	defer chA.release()
	chB := engineB.openChannel(pubA)
	defer chB.release()

	// The gost side: a pipe end per channel standing in for the tunnel stream.
	localA := attachLocal(t, chA)
	localB := attachLocal(t, chB)

	waitStream(t, chA)
	waitStream(t, chB)

	go localA.Write([]byte("one"))
	if got := string(readN(t, localB, 3)); got != "one" {
		t.Fatalf("A->B = %q, want one", got)
	}
	payload := bytes.Repeat([]byte{0x5a}, 3000)
	go localA.Write(payload)
	if got := readN(t, localB, len(payload)); !bytes.Equal(got, payload) {
		t.Fatal("A->B payload mismatch")
	}
	go localB.Write([]byte("back"))
	if got := string(readN(t, localA, 4)); got != "back" {
		t.Fatalf("B->A = %q, want back", got)
	}
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

// TestChannelRetryDelay pins the peer-edge reconnect cadence: a stream that
// lived (peer restart / path drop) resets to the fast floor — that was the
// "tun-to-tun takes ~80s to reconnect" complaint — while an outright open
// failure doubles towards the punch backoff and never exceeds it. Assertions
// derive from the ambient backoffPeriod (TestMain shortens it for the package).
func TestChannelRetryDelay(t *testing.T) {
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

// TestChannelFastRetryAfterRefusal: while the responder's gost has not opened
// a udp tunnel, the opener's peer-edge stream is refused at once; once the
// responder's channel appears the opener must recover quickly (the fast
// retry), not wait out the 30s punch backoff.
func TestChannelFastRetryAfterRefusal(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	// Force the opener role on A: the smaller public key opens the stream.
	var privA, privB derpclient.PrivateKey
	var pubA, pubB derpclient.PublicKey
	for {
		privA, pubA, _ = derpclient.Generate()
		privB, pubB, _ = derpclient.Generate()
		if bytes.Compare(pubA[:], pubB[:]) < 0 {
			break
		}
	}
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, "", privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	chA := engineA.openChannel(pubB) // the opener starts its loop at once
	defer chA.release()

	// B's channel (and so A's first attempt) is absent now: the attempt is
	// refused; B appears shortly after.
	time.Sleep(500 * time.Millisecond)
	chB := engineB.openChannel(pubA)
	defer chB.release()
	attachLocal(t, chB)

	deadline := time.Now().Add(8 * time.Second) // << backoffPeriod: guards the fast retry
	for time.Now().Before(deadline) {
		chA.mu.Lock()
		up := chA.stream != nil
		chA.mu.Unlock()
		if up {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("opener did not recover after the refusal (fast retry missing)")
}

// TestChannelRefcount covers the channel lifecycle: tunnels to the same peer
// share one channel, it survives until the last one closes, and the next open
// rebuilds it (with a fresh loop, so a stale one cannot feed it).
func TestChannelRefcount(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()

	ch := e.openChannel(peerKey)
	again := e.openChannel(peerKey)
	if again != ch {
		t.Fatal("second open created a new channel instead of sharing the peer's")
	}
	if e.channel(peerKey) != ch {
		t.Fatal("channel not registered for its peer")
	}

	ch.release()
	if e.channel(peerKey) == nil {
		t.Fatal("channel torn down while a reference was still held")
	}

	ch.release()
	if e.channel(peerKey) != nil {
		t.Fatal("channel still registered after its last reference")
	}

	rebuilt := e.openChannel(peerKey)
	defer rebuilt.release()
	if rebuilt == ch {
		t.Fatal("reused the torn-down channel")
	}
	if rebuilt.stop == ch.stop {
		t.Fatal("rebuilt channel shares the stale stop channel (a stale loop could feed it)")
	}
}
