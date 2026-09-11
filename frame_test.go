package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

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
