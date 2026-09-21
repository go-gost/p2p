package p2p

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestProviderStubEcho exercises the in-process path end to end: a Host with no
// DERP and no gRPC control plane serves a tunnel straight to a stub peer over
// an in-memory stream. This is the embedding path — OpenTunnelStream reaches the
// same allocateTunnel/serveTunnel as the gRPC Tunnel RPC, only the carrier
// differs.
func TestProviderStubEcho(t *testing.T) {
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

	p := host.Provider()
	conn, err := p.OpenTunnelStream(context.Background(), "tcp4", echo.Addr().String())
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
	if _, err := p.OpenTunnelStream(context.Background(), "tcp", echo.Addr().String()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("after Close: err = %v, want net.ErrClosed", err)
	}
}
