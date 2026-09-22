package host

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

// frameAt returns (payload length, frame length, ok); the payload bytes are
// b[2:total]. These tests pin that contract.

// TestAppendFrameRoundTrip: a frame written by appendFrame is parsed back by
// frameAt with its payload intact.
func TestAppendFrameRoundTrip(t *testing.T) {
	buf := appendFrame(nil, []byte("hello"))

	n, total, ok := frameAt(buf)
	if !ok {
		t.Fatal("frameAt did not recognise a complete frame")
	}
	if n != 5 {
		t.Fatalf("payload length = %d, want 5", n)
	}
	if total != len(buf) {
		t.Fatalf("frame length = %d, want %d (the whole buffer)", total, len(buf))
	}
	if !bytes.Equal(buf[2:total], []byte("hello")) {
		t.Fatalf("payload = %q, want hello", buf[2:total])
	}
}

// TestFrameAtMultipleFrames: one buffer holding several frames is drained frame
// by frame, each payload intact and in order.
func TestFrameAtMultipleFrames(t *testing.T) {
	var buf []byte
	buf = appendFrame(buf, []byte("one"))
	buf = appendFrame(buf, []byte("two"))
	buf = appendFrame(buf, []byte("three"))

	var got []string
	for len(buf) > 0 {
		_, total, ok := frameAt(buf)
		if !ok {
			t.Fatalf("frameAt stopped with %d bytes left", len(buf))
		}
		got = append(got, string(buf[2:total]))
		buf = buf[total:]
	}
	if want := []string{"one", "two", "three"}; !equalStrings(got, want) {
		t.Fatalf("frames = %q, want %q", got, want)
	}
}

// TestFrameAtIncomplete: a frame missing any byte — header or payload — is not
// reported as complete.
func TestFrameAtIncomplete(t *testing.T) {
	full := appendFrame(nil, []byte("hello")) // 7 bytes
	for _, b := range [][]byte{nil, full[:1], full[:len(full)-1]} {
		if _, _, ok := frameAt(b); ok {
			t.Fatalf("frameAt accepted an incomplete frame of %d bytes", len(b))
		}
	}
}

// TestFrameAtStopsAtFrameBoundary: a complete frame followed by a partial one
// yields only the first — frameAt never reports bytes past its frame.
func TestFrameAtStopsAtFrameBoundary(t *testing.T) {
	buf := appendFrame(nil, []byte("a"))
	buf = append(buf, 0x00, 0x05) // a second frame's header claiming 5 bytes, payload absent

	n, total, ok := frameAt(buf)
	if !ok {
		t.Fatal("frameAt did not recognise the leading complete frame")
	}
	if n != 1 || total != 3 {
		t.Fatalf("frameAt = (%d, %d), want (1, 3)", n, total)
	}
}

// TestFrameAtZeroLength: a zero-length frame is a valid frame of 2 bytes; the
// caller is the one that skips empty payloads.
func TestFrameAtZeroLength(t *testing.T) {
	buf := appendFrame(nil, nil)
	if len(buf) != 2 {
		t.Fatalf("zero-length frame is %d bytes, want 2", len(buf))
	}
	n, total, ok := frameAt(buf)
	if !ok || n != 0 || total != 2 {
		t.Fatalf("frameAt = (%d, %d, %v), want (0, 2, true)", n, total, ok)
	}
}

// TestFrameAtMaxPayload: the 16-bit length prefix carries a full-size payload.
func TestFrameAtMaxPayload(t *testing.T) {
	p := bytes.Repeat([]byte{0xab}, maxFrame)
	buf := appendFrame(nil, p)

	n, total, ok := frameAt(buf)
	if !ok || n != maxFrame || total != maxFrame+2 {
		t.Fatalf("frameAt = (%d, %d, %v), want (%d, %d, true)", n, total, ok, maxFrame, maxFrame+2)
	}
	if !bytes.Equal(buf[2:total], p) {
		t.Fatal("max-size payload mismatch")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFrameConnWriteWire pins the in-process provider's udp wire format: the
// carrier's conn must emit the same 2-byte big-endian length-prefixed frames
// as x/p2p/streamconn (and the outlet's dgramEdge), and report the payload
// length from Write, not the frame length.
func TestFrameConnWriteWire(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientRaw, serverRaw := newPipePair(ctx)
	w := newFrameConn(newStreamConn(clientRaw, nil))
	raw := newStreamConn(serverRaw, nil)

	if _, err := w.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(raw, buf); err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x00, 0x05, 'f', 'i', 'r', 's', 't'}; !bytes.Equal(buf, want) {
		t.Fatalf("frame = %v, want %v", buf, want)
	}

	n, err := w.Write([]byte("abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("Write = %d, want 6 (the payload length, not the frame length)", n)
	}
	if _, err := io.ReadFull(raw, make([]byte, 8)); err != nil {
		t.Fatal(err) // drain the second frame
	}

	if _, err := w.Write(make([]byte, maxFrame+1)); !errors.Is(err, errDatagramTooLarge) {
		t.Fatalf("oversized write err = %v, want errDatagramTooLarge", err)
	}
}

// TestFrameConnReadDatagrams pins the read side: one datagram per Read with
// boundaries preserved, and bytes beyond a short read buffer discarded as on a
// UDP socket — the following Read must return the next datagram, not the tail.
func TestFrameConnReadDatagrams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientRaw, serverRaw := newPipePair(ctx)
	w := newFrameConn(newStreamConn(clientRaw, nil))
	r := newFrameConn(newStreamConn(serverRaw, nil))

	for _, m := range []string{"first", "second", "0123456"} {
		if _, err := w.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}

	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "first" {
		t.Fatalf("Read = %q, want %q", got, "first")
	}

	small := make([]byte, 3)
	n, err = r.Read(small)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(small[:n]); got != "sec" {
		t.Fatalf("short Read = %q, want %q", got, "sec")
	}

	n, err = r.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "0123456" {
		t.Fatalf("Read after truncation = %q, want %q (the discarded tail must not reappear)", got, "0123456")
	}
}
