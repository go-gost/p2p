package main

import (
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

// newTestChannel binds a channel endpoint on loopback without starting the
// opener loop; the caller attaches the upstream stream.
func newTestChannel(t *testing.T, e *Engine, peer derpclient.PublicKey) *channel {
	t.Helper()
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := &channel{
		e:    e,
		peer: peer,
		sock: sock,
		stop: make(chan struct{}),
	}
	t.Cleanup(func() { ch.teardown() })
	go ch.readLocal()
	return ch
}

// dialEndpoint dials the channel's endpoint the way gost does (a connected
// datagram socket, followed by an empty announcing datagram), so the test
// client's source address is what the channel sees.
func dialEndpoint(t *testing.T, ch *channel) net.Conn {
	t.Helper()
	c, err := net.Dial("udp", ch.sock.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Write(nil)
	t.Cleanup(func() { c.Close() })
	return c
}

func mustRecv(t *testing.T, c net.Conn) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, maxFrame)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	return buf[:n]
}

// attachStream serves c as the channel's upstream stream (the real pump) and
// waits until the channel sees it.
func attachStream(t *testing.T, ch *channel, c net.Conn) {
	t.Helper()
	go ch.serveStream(c)
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
	t.Fatal("channel stream was not published")
}

// drain discards frames read from c in the background, keeping the channel's
// writes moving (net.Pipe has no buffer).
func drain(c net.Conn) {
	go func() {
		for {
			if _, err := readFrame(c); err != nil {
				return
			}
		}
	}()
}

// TestChannelDatagramBoundaries drives the channel in both directions over a
// pipe standing in for the peer stream: datagrams written to the endpoint come
// out as frames, and frames read from the stream come out as datagrams to the
// last client — boundaries intact.
func TestChannelDatagramBoundaries(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	ch := newTestChannel(t, e, peerKey)
	client := dialEndpoint(t, ch)

	// Endpoint -> stream: datagrams, boundaries preserved (the empty one is
	// dropped, as is a datagram arriving on a bare endpoint).
	upstream, peerSide := net.Pipe()
	t.Cleanup(func() { upstream.Close() })
	attachStream(t, ch, upstream)

	for _, want := range []string{"first", "", "third"} {
		if _, err := client.Write([]byte(want)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"first", "third"} {
		peerSide.SetReadDeadline(time.Now().Add(3 * time.Second))
		got, err := readFrame(peerSide)
		if err != nil {
			t.Fatalf("readFrame: %v", err)
		}
		if string(got) != want {
			t.Fatalf("frame = %q, want %q", got, want)
		}
	}

	// Stream -> endpoint.
	go func() {
		for _, p := range []string{"hello", "world"} {
			writeFrame(peerSide, []byte(p))
		}
	}()
	for _, want := range []string{"hello", "world"} {
		if got := string(mustRecv(t, client)); got != want {
			t.Fatalf("datagram = %q, want %q", got, want)
		}
	}
}

// TestChannelLastClientWins proves a re-dial (a new source port) takes over
// the endpoint: datagrams follow the newest client.
func TestChannelLastClientWins(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	ch := newTestChannel(t, e, peerKey)

	first := dialEndpoint(t, ch)
	second := dialEndpoint(t, ch)

	upstream, peerSide := net.Pipe()
	t.Cleanup(func() { upstream.Close() })
	attachStream(t, ch, upstream)
	drain(peerSide)

	// The first client is heard, then the second.
	first.Write([]byte("a"))
	second.Write([]byte("b"))
	second.SetReadDeadline(time.Now().Add(3 * time.Second))
	first.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	// The datagram after the re-dial must reach the second client, and the
	// first must get nothing more.
	go func() {
		time.Sleep(50 * time.Millisecond)
		writeFrame(peerSide, []byte("answer"))
	}()
	if got := string(mustRecv(t, second)); got != "answer" {
		t.Fatalf("datagram = %q, want %q", got, "answer")
	}
	buf := make([]byte, 16)
	if n, err := first.Read(buf); err == nil {
		t.Fatalf("stale client received %q, want nothing", buf[:n])
	}
}

// TestChannelDropsWithoutClient covers frames arriving before the local gost
// has dialled the endpoint: they must be dropped rather than written to an
// unknown address, and the channel must keep serving.
func TestChannelDropsWithoutClient(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()
	ch := newTestChannel(t, e, peerKey)

	upstream, peerSide := net.Pipe()
	t.Cleanup(func() { upstream.Close() })
	attachStream(t, ch, upstream)
	drain(peerSide)

	writeFrame(peerSide, []byte("early")) // no client yet: dropped
	time.Sleep(50 * time.Millisecond)

	client := dialEndpoint(t, ch)
	client.Write([]byte("hi")) // the client address is learned here
	time.Sleep(50 * time.Millisecond)

	go writeFrame(peerSide, []byte("late"))
	if got := string(mustRecv(t, client)); got != "late" {
		t.Fatalf("datagram = %q, want %q (channel stopped serving)", got, "late")
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
// test relay: what one gost-side socket sends comes out of the other, with
// datagram boundaries intact.
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

	chA, err := engineA.openChannel(pubB)
	if err != nil {
		t.Fatal(err)
	}
	defer chA.release()
	chB, err := engineB.openChannel(pubA)
	if err != nil {
		t.Fatal(err)
	}
	defer chB.release()

	// The gost side: a connected datagram socket per endpoint.
	clientA := dialEndpoint(t, chA)
	clientB := dialEndpoint(t, chB)

	waitStream(t, chA)
	waitStream(t, chB)

	for _, want := range []string{"one", "a longer datagram that must stay in one piece"} {
		if _, err := clientA.Write([]byte(want)); err != nil {
			t.Fatal(err)
		}
		if got := string(mustRecv(t, clientB)); got != want {
			t.Fatalf("A->B datagram = %q, want %q", got, want)
		}
	}
	if _, err := clientB.Write([]byte("back")); err != nil {
		t.Fatal(err)
	}
	if got := string(mustRecv(t, clientA)); got != "back" {
		t.Fatalf("B->A datagram = %q, want %q", got, "back")
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

// TestChannelRefcount covers the channel lifecycle: tunnels to the same peer
// share one channel, the endpoint survives until the last one closes, and the
// next open rebuilds it (with a fresh loop, so a stale one cannot feed it).
func TestChannelRefcount(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()

	ch, err := e.openChannel(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.openChannel(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	if again != ch {
		t.Fatal("second open created a new channel instead of sharing the peer's")
	}
	if e.channel(peerKey) != ch {
		t.Fatal("channel not registered for its peer")
	}

	addr := ch.sock.LocalAddr().String()
	ch.release()
	if e.channel(peerKey) == nil {
		t.Fatal("channel torn down while a reference was still held")
	}
	if ch.sock.LocalAddr().String() != addr {
		t.Fatal("endpoint changed while the channel was still referenced")
	}

	ch.release()
	if e.channel(peerKey) != nil {
		t.Fatal("channel still registered after its last reference")
	}

	rebuilt, err := e.openChannel(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	defer rebuilt.release()
	if rebuilt == ch {
		t.Fatal("reused the torn-down channel")
	}
	if rebuilt.stop == ch.stop {
		t.Fatal("rebuilt channel shares the stale stop channel (a stale loop could feed it)")
	}
}
