package host

import (
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

	// Create both channels up front (the dials below reuse them), so the
	// opener's very first peer-edge attempt finds the responder's channel.
	chA := engineA.openChannel(pubB)
	defer chA.release()
	chB := engineB.openChannel(pubA)
	defer chB.release()

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

	// Both channels must have their peer edge up before data flows: bytes are
	// dropped while the opposite edge is down.
	waitStream(t, engineA.channel(pubB))
	waitStream(t, engineB.channel(pubA))

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

	// Closing one side tears its record (and channel reference) down.
	connA.Close()
	waitTunnelCount(t, hA, 0)
}
