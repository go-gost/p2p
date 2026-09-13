package main

import (
	"bytes"
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
