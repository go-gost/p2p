package p2p

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestHostListen: with Listen the host hands inbound peer streams to the
// embedder instead of bridging them to a target; the conn carries the peer's
// key as its remote address.
func TestHostListen(t *testing.T) {
	rs := &relayServer{} // engine_test.go's in-process DERP-style relay
	url := rs.start(t)
	a := newListenTestHost(t, url, strings.Repeat("aa", 32))
	b := newListenTestHost(t, url, strings.Repeat("bb", 32))

	ln, err := b.Tunnel().Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// A opens a tunnel to B; B accepts it and both ends exchange bytes.
	client, err := a.Tunnel().Dial(context.Background(), "tcp", b.PublicKey())
	if err != nil {
		t.Fatalf("open tunnel: %v", err)
	}
	defer client.Close()

	type res struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()

	var srv net.Conn
	select {
	case r := <-accepted:
		if r.err != nil {
			t.Fatalf("accept: %v", r.err)
		}
		srv = r.conn
	case <-time.After(10 * time.Second):
		t.Fatal("accept timed out")
	}
	defer srv.Close()

	if got := srv.RemoteAddr().String(); got != a.PublicKey() {
		t.Fatalf("RemoteAddr = %q, want A's key %q", got, a.PublicKey())
	}
	if got := srv.RemoteAddr().Network(); got != "p2p" {
		t.Fatalf("RemoteAddr network = %q, want p2p", got)
	}

	msg := []byte("hello inbound")
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(srv, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}
	if _, err := srv.Write([]byte("ack")); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	ack := make([]byte, 3)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("read ack: %v", err)
	}
}

// TestListenWithTargetsErrors: Targets and Listen are mutually exclusive.
func TestListenWithTargetsErrors(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	direct := false
	h, err := New(&Config{Derp: url, KeyHex: strings.Repeat("cc", 32), Direct: &direct, Targets: []string{"tcp://127.0.0.1:9"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if _, err := h.Tunnel().Listen(); err == nil {
		t.Fatal("Listen with configured targets = nil error, want a failure")
	}
}

// newListenTestHost builds a connected in-process host for the Listen tests.
func newListenTestHost(t *testing.T, url, keyHex string) *Host {
	t.Helper()
	direct := false
	h, err := New(&Config{Derp: url, KeyHex: keyHex, Direct: &direct})
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if err := h.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return h
}
