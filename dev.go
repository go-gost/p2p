package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Device-link mode: the p2p host opens an existing local device (tun/tap) and
// bridges it to the peer's same-kind device over one persistent stream. The
// device is treated as an opaque chunk device — each Read becomes one
// length-prefixed frame. This preserves packet boundaries for packet devices
// (tun/tap) and preserves the byte stream for stream devices (pipe/socket); the
// only unsupported pairing is stream source -> packet sink, so the two ends
// must be the same kind.
//
// Framing is mandatory: the data plane (smux) is a byte stream and does not
// preserve read boundaries.

// maxFrame is the largest chunk that fits the 2-byte length prefix.
const maxFrame = 65535

// deviceKind selects the open mode for a device.
type deviceKind int

const (
	deviceTun deviceKind = iota // IFF_TUN
	deviceTap                   // IFF_TAP
)

func (k deviceKind) String() string {
	if k == deviceTap {
		return "tap"
	}
	return "tun"
}

// writeFrame writes p as one length-prefixed frame.
func writeFrame(w io.Writer, p []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	bufs := net.Buffers{hdr[:], p}
	_, err := bufs.WriteTo(w)
	return err
}

// readFrame reads one length-prefixed frame. A zero-length frame returns
// (nil, nil); the caller should skip it.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, nil
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

// writeAll writes p in full. io.Writer permits short writes (n < len(p)), which
// a device may return; a single Write is not enough.
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// setLink records c as the active device-link stream.
func (e *Engine) setLink(c net.Conn) {
	e.linkMu.Lock()
	e.link = c
	e.linkMu.Unlock()
}

// clearLink clears the active stream if it is still c (a reconnect may already
// have replaced it).
func (e *Engine) clearLink(c net.Conn) {
	e.linkMu.Lock()
	if e.link == c {
		e.link = nil
	}
	e.linkMu.Unlock()
}

// currentLink returns the active device-link stream, or nil when the link is
// down.
func (e *Engine) currentLink() net.Conn {
	e.linkMu.Lock()
	defer e.linkMu.Unlock()
	return e.link
}

// startDevice begins reading the local device. dev must already be set.
func (e *Engine) startDevice() {
	if e.dev == nil {
		return
	}
	go e.devReadLoop()
}

// devReadLoop reads the local device and writes to the current link stream for
// the lifetime of the engine. It is a single goroutine because a device Read
// cannot be interrupted (tun has no deadline support), so a per-stream reader
// would leak a goroutine blocked in Read on every reconnect. Chunks read while
// the link is down are dropped (IP tolerates loss).
func (e *Engine) devReadLoop() {
	buf := make([]byte, maxFrame)
	for {
		n, err := e.dev.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				e.log.Debug("device read", "error", err)
			}
			return
		}
		if n <= 0 {
			continue
		}
		c := e.currentLink()
		if c == nil {
			continue // link down: drop
		}
		if err := writeFrame(c, buf[:n]); err != nil {
			// The stream is dead; its serveLink clears the link.
			e.log.Debug("device link: write stream", "error", err)
		}
	}
}

// serveLink bridges one device-link stream to the local device until the stream
// ends. Both the opener (linkLoop) and the responder (acceptLoop) run it.
func (e *Engine) serveLink(c net.Conn) {
	e.setLink(c)
	defer func() {
		e.clearLink(c)
		c.Close()
	}()
	for {
		p, err := readFrame(c)
		if err != nil {
			return
		}
		if len(p) == 0 {
			continue
		}
		if err := writeAll(e.dev, p); err != nil {
			e.log.Debug("device link: write device", "error", err)
			return
		}
	}
}
