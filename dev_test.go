package main

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// fakeDevice is an in-memory chunk device: Read returns each chunk enqueued on
// in, Write captures chunks on out. writeCap (when > 0) caps each Write to that
// many bytes to exercise writeAll's partial-write loop.
type fakeDevice struct {
	in       chan []byte
	out      chan []byte
	writeCap int
	cur      []byte
	closed   chan struct{}
}

func newFakeDevice() *fakeDevice {
	return &fakeDevice{
		in:     make(chan []byte, 16),
		out:    make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func (d *fakeDevice) Read(p []byte) (int, error) {
	for len(d.cur) == 0 {
		select {
		case c := <-d.in:
			d.cur = c
		case <-d.closed:
			return 0, io.EOF
		}
	}
	n := copy(p, d.cur)
	d.cur = d.cur[n:]
	return n, nil
}

func (d *fakeDevice) Write(p []byte) (int, error) {
	n := len(p)
	if d.writeCap > 0 && n > d.writeCap {
		n = d.writeCap
	}
	b := make([]byte, n)
	copy(b, p[:n])
	d.out <- b
	return n, nil
}

func (d *fakeDevice) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

func TestFrameRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 2, 255, 256, 65535} {
		payload := bytes.Repeat([]byte{0xab}, n)
		var buf bytes.Buffer
		if err := writeFrame(&buf, payload); err != nil {
			t.Fatalf("n=%d writeFrame: %v", n, err)
		}
		got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("n=%d readFrame: %v", n, err)
		}
		if n == 0 {
			if got != nil {
				t.Fatalf("n=0: want nil, got %v", got)
			}
			continue
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("n=%d: payload mismatch", n)
		}
	}
}

// shortWriter writes at most one byte per call.
type shortWriter struct{ buf bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.buf.Write(p[:1])
	return 1, nil
}

func TestWriteAllShortWriter(t *testing.T) {
	w := &shortWriter{}
	want := []byte("partial writes must be completed")
	if err := writeAll(w, want); err != nil {
		t.Fatalf("writeAll: %v", err)
	}
	if !bytes.Equal(w.buf.Bytes(), want) {
		t.Fatalf("got %q want %q", w.buf.Bytes(), want)
	}
}

// TestReadFrameFragmented feeds a frame header + payload split across writes
// (and TCP-style arrivals) to prove io.ReadFull reassembly.
func TestReadFrameFragmented(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	go func() {
		c1.Write([]byte{0x00, 0x03, 'a'})
		time.Sleep(10 * time.Millisecond)
		c1.Write([]byte("b"))
		time.Sleep(10 * time.Millisecond)
		c1.Write([]byte("c"))
		c1.Close()
	}()
	got, err := readFrame(c2)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("got %q want %q", got, "abc")
	}
}

func mustReadFrame(t *testing.T, c net.Conn) []byte {
	t.Helper()
	type res struct {
		p   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		p, err := readFrame(c)
		ch <- res{p, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("readFrame: %v", r.err)
		}
		return r.p
	case <-time.After(2 * time.Second):
		t.Fatal("readFrame timeout")
		return nil
	}
}

func mustRecv(t *testing.T, ch chan []byte) []byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(2 * time.Second):
		t.Fatal("device write timeout")
		return nil
	}
}

// TestPumpBidirectional drives the real pump (devReadLoop + serveLink) with a
// fake device and a net.Pipe link, in both directions, and with a device that
// only accepts one byte per Write.
func TestPumpBidirectional(t *testing.T) {
	dev := newFakeDevice()
	dev.writeCap = 1 // force serveLink's writeAll loop
	defer dev.Close()

	e := &Engine{dev: dev, log: slog.Default()}
	c1, c2 := net.Pipe()
	defer c2.Close()

	go e.devReadLoop()
	go e.serveLink(c1)

	// Wait until serveLink has installed the stream, else devReadLoop would
	// drop the first chunk as "link down".
	for i := 0; e.currentLink() == nil; i++ {
		if i > 2000 {
			t.Fatal("link never came up")
		}
		time.Sleep(time.Millisecond)
	}

	// device -> link: irregular chunk sizes must arrive framed, whole.
	for _, s := range []string{"a", "bb", "ccc", "dddd"} {
		select {
		case dev.in <- []byte(s):
		case <-time.After(2 * time.Second):
			t.Fatal("enqueue chunk timeout")
		}
		if got := mustReadFrame(t, c2); string(got) != s {
			t.Fatalf("device->link: got %q want %q", got, s)
		}
	}

	// link -> device: a large frame must be reassembled despite 1-byte writes.
	payload := bytes.Repeat([]byte("x"), 1000)
	if err := writeFrame(c2, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	var got []byte
	for len(got) < len(payload) {
		got = append(got, mustRecv(t, dev.out)...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("link->device: payload mismatch (got %d bytes)", len(got))
	}
}

func TestParseLink(t *testing.T) {
	cases := []struct {
		spec string
		name string
		kind deviceKind
		peer string
		ok   bool
	}{
		{"p2p0=KEY", "p2p0", deviceTun, "KEY", true},
		{"tun:p2p0=KEY", "p2p0", deviceTun, "KEY", true},
		{"tap:veth0=KEY", "veth0", deviceTap, "KEY", true},
		{"foo:bar=KEY", "foo:bar", deviceTun, "KEY", true},
		{"noeq", "", 0, "", false},
		{"=KEY", "", 0, "", false},
		{"p2p0=", "", 0, "", false},
	}
	for _, c := range cases {
		name, kind, peer, err := parseLink(c.spec)
		if c.ok != (err == nil) {
			t.Fatalf("%q: err=%v want ok=%v", c.spec, err, c.ok)
		}
		if err != nil {
			continue
		}
		if name != c.name || kind != c.kind || peer != c.peer {
			t.Fatalf("%q: got (%q,%v,%q) want (%q,%v,%q)",
				c.spec, name, kind, peer, c.name, c.kind, c.peer)
		}
	}
}
