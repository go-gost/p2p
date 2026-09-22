package endpoint

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/p2p"
)

// startEcho runs a loopback echo server and returns its address.
func startEcho(t *testing.T) string {
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
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// TestDialStubEcho is the in-process door end to end: a stub-mode endpoint
// dials a peer and the returned conn carries the bytes.
func TestDialStubEcho(t *testing.T) {
	ep, err := New(&p2p.Config{}, WithLogger(slog.Default()))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()

	if ep.PublicKey() != "" {
		t.Fatalf("PublicKey = %q, want empty in stub mode", ep.PublicKey())
	}
	if st := ep.Status(); st.Tunnels != 0 {
		t.Fatalf("Status = %+v, want a zero snapshot", st)
	}

	conn, err := ep.Dial(context.Background(), "tcp4", startEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}

	// Close shuts the endpoint down: Dial fails fast afterwards.
	if err := ep.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ep.Dial(context.Background(), "tcp", startEcho(t)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Dial after Close = %v, want net.ErrClosed", err)
	}
}

// TestListenNeedsRelay: Listen is relay-mode only (a peer is addressed by its
// public key) and mutually exclusive with inbound targets.
func TestListenNeedsRelay(t *testing.T) {
	ep, err := New(&p2p.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()
	if _, err := ep.Listen(); err == nil {
		t.Fatal("Listen in stub mode = nil error, want a failure")
	}
}

// TestNilConfigAndNilOption covers the constructor's tolerance: a nil config is
// an empty config, a nil option is ignored.
func TestNilConfigAndNilOption(t *testing.T) {
	ep, err := New(nil, nil, WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()
	if ep.Status().Tunnels != 0 {
		t.Fatal("fresh endpoint reports tunnels")
	}
}

// fakeTransport records that Close reached it.
type fakeTransport struct{ closed atomic.Bool }

func (f *fakeTransport) Close() error {
	f.closed.Store(true)
	return nil
}

// TestCloseClosesAttachedTransports pins the ownership rule: registering a
// transport makes it close with the endpoint, a nil registration is a no-op,
// and a closed endpoint refuses new attachments (so a transport can never be
// built whose listener nobody will close).
func TestCloseClosesAttachedTransports(t *testing.T) {
	ep, err := New(&p2p.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ft := &fakeTransport{}
	if err := ep.Attach(ft); err != nil {
		t.Fatal(err)
	}
	if err := ep.Attach(nil); err != nil {
		t.Fatalf("Attach(nil) = %v, want nil", err)
	}

	if err := ep.Close(); err != nil {
		t.Fatal(err)
	}
	if !ft.closed.Load() {
		t.Fatal("attached transport was not closed with the endpoint")
	}
	if err := ep.Attach(&fakeTransport{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Attach after Close = %v, want net.ErrClosed", err)
	}
}
