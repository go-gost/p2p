package p2p

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestTunnelStubEcho exercises the in-process path end to end: a Host with no
// DERP and no gRPC control plane serves a tunnel straight to a stub peer over
// an in-memory stream. This is the embedding path — Dial reaches the
// same allocateTunnel/serveTunnel as the gRPC Tunnel RPC, only the carrier
// differs.
func TestTunnelStubEcho(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	host, err := New(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if host.PublicKey() != "" {
		t.Fatalf("PublicKey = %q, want empty in stub mode", host.PublicKey())
	}

	p := host.Tunnel()
	conn, err := p.Dial(context.Background(), "tcp4", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// gost's forward connector logs LocalAddr/RemoteAddr, so a tunnel conn must
	// return non-nil addresses (String on a nil net.Addr panics).
	if conn.LocalAddr() == nil || conn.RemoteAddr() == nil {
		t.Fatalf("nil conn addr: local=%v remote=%v", conn.LocalAddr(), conn.RemoteAddr())
	}
	_ = conn.LocalAddr().String()
	_ = conn.RemoteAddr().String()

	msg := []byte("hello over in-process p2p")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}

	// Close stops new tunnels without touching live ones.
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Dial(context.Background(), "tcp", echo.Addr().String()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("after Close: err = %v, want net.ErrClosed", err)
	}
}

// TestStartFailsOnBadForward pins the CLI-visible behavior: a forward that
// cannot be registered is a configuration error, so Start returns it instead
// of serving without the forward. A stub-mode host cannot hold a forward.
func TestStartFailsOnBadForward(t *testing.T) {
	host, err := New(&Config{Forwards: []ForwardConfig{{Listen: "127.0.0.1:0", Peer: "abc"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if _, err := host.Start(); err == nil {
		t.Fatal("Start with a stub-mode forward = nil error, want the registration failure")
	}
}

// TestStartServesWhenDerpUnreachable is the other half of the split: an
// unreachable relay is transient (the engine retries), so Start still listens
// and returns the address; only a forward failure is fatal.
func TestStartServesWhenDerpUnreachable(t *testing.T) {
	host, err := New(&Config{
		Derp:   "wss://127.0.0.1:1/derp", // refused: nothing listens on port 1
		KeyHex: strings.Repeat("11", 32), // in-memory key: no key file is written
		Addr:   "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	addr, err := host.Start()
	if err != nil {
		t.Fatalf("Start with an unreachable relay = %v, want serve anyway", err)
	}
	if addr == "" {
		t.Fatal("Start returned an empty addr")
	}
}

// patternReader yields size bytes where byte k is pattern(k), independent of
// how the reads are split, so a tunnel's output can be verified positionally.
type patternReader struct {
	off  int
	size int
}

// pattern maps a byte offset to its expected value: byte(k/chunkSize) turns
// each 4 KiB chunk into a self-identifying fill.
func pattern(k int) byte { return byte(k / 4096) }

func (r *patternReader) Read(p []byte) (int, error) {
	if r.off >= r.size {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.size-r.off {
		n = r.size - r.off
	}
	for i := 0; i < n; i++ {
		p[i] = pattern(r.off + i)
	}
	r.off += n
	return n, nil
}

// TestTunnelStreamIntegrityUnderBackpressure drives the in-process path with
// io.Copy's reusable buffer while the peer drains slower than the writer, so
// the tunnel queue fills and every queued chunk's payload must survive intact
// until the peer reads it. The window is small and the peer pauses
// periodically: without the pause the kernel's send buffer absorbs the whole
// transfer and the queue never fills, which is what made this corruption
// invisible to the round-trip tests.
func TestTunnelStreamIntegrityUnderBackpressure(t *testing.T) {
	const total = 8 << 20

	peer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	got := make(chan []byte, 1)
	go func() {
		c, err := peer.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetReadBuffer(256 << 10)
		}
		b := make([]byte, total)
		n := 0
		buf := make([]byte, 4096)
		for n < total {
			rn, err := c.Read(buf)
			copy(b[n:], buf[:rn])
			n += rn
			if err != nil {
				t.Errorf("peer read: %v", err)
				break
			}
			if (n / (512 << 10)) != ((n - rn) / (512 << 10)) {
				time.Sleep(50 * time.Millisecond) // let the tunnel queue back up
			}
		}
		got <- b[:n]
	}()

	host, err := New(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	conn, err := host.Tunnel().Dial(context.Background(), "tcp", peer.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go func() { _, _ = io.Copy(conn, &patternReader{size: total}) }()

	select {
	case b := <-got:
		for k := 0; k < len(b); k++ {
			if b[k] != pattern(k) {
				t.Fatalf("byte %d = %d, want %d (a queued chunk lost its payload)", k, b[k], pattern(k))
			}
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the peer to drain the tunnel")
	}
}
