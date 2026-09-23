package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

// tunnelCount reads the registry size under its lock.
func tunnelCount(h *Host) int {
	h.server.mu.Lock()
	defer h.server.mu.Unlock()
	return len(h.server.tunnels)
}

func waitTunnelCount(t *testing.T, h *Host, want int) {
	t.Helper()
	waitFor(t, 3*time.Second, func() bool { return tunnelCount(h) == want })
}

// TestPendingGC covers the record lifecycle around the GC: a record whose
// carrier never attaches is reclaimed, an attached record survives the TTL, and
// ending the carrier drops it.
func TestPendingGC(t *testing.T) {
	oldTTL, oldInterval := pendingTTL, gcInterval
	pendingTTL, gcInterval = 50*time.Millisecond, 10*time.Millisecond
	defer func() { pendingTTL, gcInterval = oldTTL, oldInterval }()

	h, err := New(&p2p.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Abandoned setup: OpenTunnel without a carrier must not leak.
	if _, err := h.OpenTunnel("tcp", "127.0.0.1:9999"); err != nil {
		t.Fatal(err)
	}
	if n := tunnelCount(h); n != 1 {
		t.Fatalf("tunnel count = %d, want 1", n)
	}
	waitTunnelCount(t, h, 0)

	// An attached record survives well past the TTL while its carrier is live.
	conn, err := h.Dial(context.Background(), "tcp", startEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // > TTL: several sweeps must skip it
	if n := tunnelCount(h); n != 1 {
		t.Fatalf("live tunnel was reclaimed: count = %d, want 1", n)
	}
	conn.Close()
	waitTunnelCount(t, h, 0)
}

// TestPipeSendCopiesCallerBuffer pins the net.Conn write contract on the
// in-process path: a caller may reuse its buffer once Write returns (io.Copy
// does exactly that), so the pipe must copy the payload instead of retaining
// the caller's slice in its queue.
func TestPipeSendCopiesCallerBuffer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientSide, serverSide := newPipePair(ctx)
	w := newStreamConn(clientSide, cancel)
	r := newStreamConn(serverSide, nil)

	buf := []byte("AAAA")
	if _, err := w.Write(buf); err != nil {
		t.Fatal(err)
	}
	copy(buf, "BBBB") // legal: Write has returned

	got := make([]byte, 4)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, got)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read timed out")
	}
	if string(got) != "AAAA" {
		t.Fatalf("read %q after the caller reused its buffer, want %q", got, "AAAA")
	}
}

// TestServeTunnelPeerUnreachable pins the classification a transport maps: a
// peer that cannot be opened reports p2p.ErrPeerUnreachable with the dial cause
// still wrapped (errors.As reaches it).
func TestServeTunnelPeerUnreachable(t *testing.T) {
	s := newServer(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, serverSide := newPipePair(ctx)

	tr := &tunnelRecord{
		id:        "unreachable",
		target:    "127.0.0.1:1", // nothing listens, and a non-root process cannot bind it
		network:   "tcp",
		createdAt: time.Now(),
		conns:     make(map[net.Conn]struct{}),
		log:       slog.Default(),
	}
	err := s.serveTunnel(tr, serverSide, cancel)
	if !errors.Is(err, p2p.ErrPeerUnreachable) {
		t.Fatalf("err = %v, want p2p.ErrPeerUnreachable", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("err = %v, want the dial cause wrapped", err)
	}
}

// TestUDPTunnelEndToEnd wires two hosts and engines through the test relay: a
// udp tunnel dialed on each side, then bytes written on one come out of the
// other — the datagram channel paired each peer edge with its local edge and
// piped the frames through untouched.
func TestUDPTunnelEndToEnd(t *testing.T) {
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

	// Both sides dial, so the pair is a rendezvous: the larger key adopts the
	// smaller's presentation (see waitRendezvous).
	hA := &Host{cfg: &p2p.Config{}, log: slog.Default(), engine: engineA, server: newServer(engineA)}
	hB := &Host{cfg: &p2p.Config{}, log: slog.Default(), engine: engineB, server: newServer(engineB)}
	defer hA.Close()
	defer hB.Close()

	keyA := base64.RawURLEncoding.EncodeToString(pubA[:])
	keyB := base64.RawURLEncoding.EncodeToString(pubB[:])

	connA, err := hA.Dial(context.Background(), "udp", keyB)
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connB, err := hB.Dial(context.Background(), "udp", keyA)
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()

	// Both sides dial, so the pair is a rendezvous: wait for the larger key to
	// adopt the smaller's presentation (one shared edge) before asserting.
	if bytes.Compare(pubA[:], pubB[:]) < 0 {
		waitRendezvous(t, engineLink(t, engineB, pubA))
	} else {
		waitRendezvous(t, engineLink(t, engineA, pubB))
	}

	connA.SetDeadline(time.Now().Add(5 * time.Second))
	connB.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connA.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(connB, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "one" {
		t.Fatalf("A->B = %q, want one", buf)
	}
	if _, err := connB.Write([]byte("back")); err != nil {
		t.Fatal(err)
	}
	buf2 := make([]byte, 4)
	if _, err := io.ReadFull(connA, buf2); err != nil {
		t.Fatal(err)
	}
	if string(buf2) != "back" {
		t.Fatalf("B->A = %q, want back", buf2)
	}

	// Closing one side tears its record (and link) down.
	connA.Close()
	waitTunnelCount(t, hA, 0)
}

// startUDPEcho returns a udp echo server plus its "udp://" target spec: every
// datagram is sent back to its sender, so a test can tell which stream a reply
// arrived on.
func startUDPEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, maxFrame)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return "udp://" + conn.LocalAddr().String()
}

// readDatagram reads one datagram (the frameConn's Read returns exactly one).
func readDatagram(t *testing.T, c net.Conn) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, maxFrame)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	return string(buf[:n])
}

// TestUDPTwoDialsIsolated is the R3 regression: one host dials the same peer
// twice (concurrent clients) and each dial's reply comes back on its own dial.
// The old per-peer channel replaced its local edge on the second dial, so the
// first client starved and the second received the first one's replies.
func TestUDPTwoDialsIsolated(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, startUDPEcho(t), privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	hA := &Host{cfg: &p2p.Config{}, log: slog.Default(), engine: engineA, server: newServer(engineA)}
	defer hA.Close()
	keyB := base64.RawURLEncoding.EncodeToString(pubB[:])

	c1, err := hA.Dial(context.Background(), "udp", keyB)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := hA.Dial(context.Background(), "udp", keyB)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	// Both clients write before either edge is up (the first datagram is
	// buffered) and each must read back its own echo.
	for i, c := range []net.Conn{c1, c2} {
		payload := []string{"one", "two"}[i]
		if _, err := c.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if got := readDatagram(t, c1); got != "one" {
		t.Fatalf("dial 1 read %q, want one (cross-talk between dials)", got)
	}
	if got := readDatagram(t, c2); got != "two" {
		t.Fatalf("dial 2 read %q, want two (cross-talk between dials)", got)
	}

	// A second round proves both links stay independent, not just the first
	// datagram's buffering.
	if _, err := c1.Write([]byte("three")); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Write([]byte("four")); err != nil {
		t.Fatal(err)
	}
	if got := readDatagram(t, c1); got != "three" {
		t.Fatalf("dial 1 read %q, want three", got)
	}
	if got := readDatagram(t, c2); got != "four" {
		t.Fatalf("dial 2 read %q, want four", got)
	}
}

// TestListenDeliversDatagramConn: a udp tunnel stream handed to the embedder is
// a datagram conn — net.PacketConn, frames parsed — stamped with the peer's
// key. That is the shape a consumer (x's local handler) tells udp by, and the
// contract wisper's reverse side builds on.
func TestListenDeliversDatagramConn(t *testing.T) {
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

	hA := &Host{cfg: &p2p.Config{}, log: slog.Default(), engine: engineA, server: newServer(engineA)}
	hB := &Host{cfg: &p2p.Config{}, log: slog.Default(), engine: engineB, server: newServer(engineB)}
	defer hA.Close()
	defer hB.Close()

	ln, err := hB.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	keyB := base64.RawURLEncoding.EncodeToString(pubB[:])
	connA, err := hA.Dial(context.Background(), "udp", keyB)
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	acc := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		acc <- accepted{c, err}
	}()

	var c net.Conn
	select {
	case a := <-acc:
		if a.err != nil {
			t.Fatal(a.err)
		}
		c = a.conn
	case <-time.After(10 * time.Second):
		t.Fatal("the udp tunnel was not delivered to the listener")
	}
	defer c.Close()

	if _, ok := c.(net.PacketConn); !ok {
		t.Fatal("a udp tunnel stream must be delivered as a datagram conn (net.PacketConn)")
	}
	keyA := base64.RawURLEncoding.EncodeToString(pubA[:])
	if got := c.RemoteAddr().String(); got != keyA {
		t.Fatalf("remote addr = %q, want the peer key %q", got, keyA)
	}

	if _, err := connA.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got := readDatagram(t, c); got != "ping" {
		t.Fatalf("listener read %q, want ping", got)
	}
	if _, err := c.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if got := readDatagram(t, connA); got != "pong" {
		t.Fatalf("dialer read %q, want pong", got)
	}
}
