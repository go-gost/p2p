package main

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// Datagram channel: the per-peer UDP tunnel. It has two byte-stream edges and
// pumps bytes between them:
//
//   - the peer edge — a persistent stream to the other host through the relay
//     or the hole-punched path (opener: the smaller key; responder: the
//     acceptLoop's tagged stream);
//   - the local edge — the Tunnel gRPC stream of the latest gost tunnel to
//     this peer (one per dial; last dial wins, as the endpoint's
//     last-client-wins did).
//
// The host never parses the data: the GOST-side conn frames datagrams into
// 2-byte-prefixed frames and the peer's GOST-side conn parses them, so the
// frames travel through verbatim. Bytes are dropped while the opposite edge
// is absent or down — IP tolerates loss, exactly like the endpoint model.
//
// Role by public-key ordering, the same rule as the mux session: the smaller
// key opens the stream (loop), the larger is served by acceptLoop.
type channel struct {
	e    *Engine
	peer derpclient.PublicKey

	stop chan struct{} // closed by teardown; ends loop

	mu     sync.Mutex
	stream net.Conn // peer edge: current upstream stream; nil while the channel is down
	local  net.Conn // local edge: the latest tunnel's stream; nil until a gost dials
	refs   int      // gost tunnels holding this channel open
	closed bool
}

// channelChunkSize bounds one pump read; frame bytes from the GOST side
// arrive in chunks at most this size.
const channelChunkSize = 32 * 1024

// openChannel returns the peer's channel, creating and starting it on first
// use, and takes a reference on it. The channel outlives individual gost
// tunnels: it is torn down when the last one closes.
func (e *Engine) openChannel(peer derpclient.PublicKey) *channel {
	e.mu.Lock()
	if ch, ok := e.chans[peer]; ok {
		ch.mu.Lock()
		if !ch.closed {
			ch.refs++
			ch.mu.Unlock()
			e.mu.Unlock()
			return ch
		}
		ch.mu.Unlock()
		delete(e.chans, peer) // drop the dead channel
	}

	ch := &channel{
		e:    e,
		peer: peer,
		stop: make(chan struct{}),
		refs: 1,
	}
	e.chans[peer] = ch
	e.mu.Unlock()

	if bytes.Compare(e.pub[:], peer[:]) < 0 {
		e.log.Info("channel role", "peer", keyName(peer), "role", "opener")
		go ch.loop()
	} else {
		e.log.Info("channel role", "peer", keyName(peer), "role", "responder")
	}
	return ch
}

// channel returns the peer's live channel, or nil when it has none (or its
// gost has already closed it).
func (e *Engine) channel(peer derpclient.PublicKey) *channel {
	e.mu.Lock()
	ch := e.chans[peer]
	e.mu.Unlock()
	if ch == nil {
		return nil
	}
	ch.mu.Lock()
	closed := ch.closed
	ch.mu.Unlock()
	if closed {
		return nil
	}
	return ch
}

// attachLocal publishes c as the channel's local edge and starts its pump.
// The returned channel is closed when this edge's tunnel ends: the gost
// closed its stream (the read fails and the pump exits), a newer dial
// replaced it, or the channel was torn down. Only the edge's own pump closes
// it, so it cannot double-close.
func (ch *channel) attachLocal(c net.Conn) <-chan struct{} {
	done := make(chan struct{})
	ch.mu.Lock()
	if ch.closed {
		ch.mu.Unlock()
		c.Close()
		close(done)
		return done
	}
	// Last dial wins: the previous edge is closed, which ends its pump.
	old := ch.local
	ch.local = c
	ch.mu.Unlock()
	if old != nil {
		old.Close()
	}
	go ch.pumpLocal(c, done)
	return done
}

// release drops one reference; the last one tears the channel down and removes
// it, so the next openChannel rebuilds it with a fresh peer edge. Reference
// count and map entry are updated under the engine lock, so an open racing a
// close sees either the live channel or a fresh one — never a torn-down one.
func (ch *channel) release() {
	ch.e.mu.Lock()
	ch.mu.Lock()
	ch.refs--
	if ch.refs > 0 || ch.closed {
		ch.mu.Unlock()
		ch.e.mu.Unlock()
		return
	}
	ch.closed = true
	stream := ch.stream
	ch.stream = nil
	local := ch.local
	ch.local = nil
	if ch.e.chans[ch.peer] == ch {
		delete(ch.e.chans, ch.peer)
	}
	ch.mu.Unlock()
	ch.e.mu.Unlock()

	ch.stopLoop(stream)
	if local != nil {
		local.Close() // its pump exits and closes the edge's done
	}
}

// teardown closes the channel regardless of references (engine shutdown).
// It runs once; false means the channel was already down.
func (ch *channel) teardown() bool {
	ch.mu.Lock()
	if ch.closed {
		ch.mu.Unlock()
		return false
	}
	ch.closed = true
	stream := ch.stream
	ch.stream = nil
	local := ch.local
	ch.local = nil
	ch.mu.Unlock()

	ch.stopLoop(stream)
	if local != nil {
		local.Close()
	}
	return true
}

// stopLoop stops the opener loop and unblocks the peer-edge reader.
func (ch *channel) stopLoop(stream net.Conn) {
	close(ch.stop)
	if stream != nil {
		stream.Close()
	}
}

// stopped reports whether the channel has been torn down.
func (ch *channel) stopped() bool {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.closed
}

// loop keeps exactly one channel stream to the peer alive: open, serve until
// it dies, back off, repeat. It exits when the channel is torn down — a rebuilt
// channel gets a fresh loop, so a stale one can never feed the new channel.
func (ch *channel) loop() {
	pname := keyName(ch.peer)
	for {
		c, err := ch.e.OpenStream(pname)
		if err == nil {
			// The channel may have been torn down while the stream was opening:
			// serving it would feed a dead channel.
			if ch.stopped() {
				c.Close()
				return
			}
			// The tag goes out before the stream is published (setStream /
			// serveStream), so a frame byte can never precede it and make the
			// responder read payload as the tag.
			_, err = c.Write([]byte(channelTag))
		}
		if err != nil {
			if c != nil {
				c.Close()
			}
			ch.e.log.Debug("channel: open stream", "peer", pname, "error", err)
		} else {
			transport := ""
			if tw, ok := c.(interface{ Transport() string }); ok {
				transport = tw.Transport()
			}
			ch.e.log.Info("channel up", "peer", pname, "transport", transport)
			ch.serveStream(c)
			ch.e.log.Info("channel down", "peer", pname)
		}

		select {
		case <-ch.stop:
			return
		case <-time.After(backoffPeriod):
		}
	}
}

// serveStream publishes c as the channel's peer edge and pumps bytes from it
// to the local edge until it dies. Bytes read while no local is attached are
// dropped: IP tolerates loss (the GOST-side frames are carried verbatim; the
// host never parses them).
func (ch *channel) serveStream(c net.Conn) {
	ch.setStream(c)
	defer func() {
		ch.clearStream(c)
		c.Close()
	}()

	buf := make([]byte, channelChunkSize)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			ch.mu.Lock()
			local := ch.local
			ch.mu.Unlock()
			if local != nil {
				if _, werr := local.Write(buf[:n]); werr != nil {
					// Drop and keep serving: a write error (e.g. the gost edge
					// just died) must not cost the whole channel a reconnect.
					ch.e.log.Debug("channel: write local", "peer", keyName(ch.peer), "error", werr)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// pumpLocal moves bytes from the local edge onto the peer edge; done is closed
// when the edge ends (gost closed the stream, or the edge was replaced/torn
// down). Bytes are dropped while the peer edge is down.
func (ch *channel) pumpLocal(c net.Conn, done chan struct{}) {
	defer func() {
		ch.clearLocal(c)
		c.Close()
		close(done)
	}()

	buf := make([]byte, channelChunkSize)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			ch.mu.Lock()
			s := ch.stream
			ch.mu.Unlock()
			if s != nil {
				if _, werr := s.Write(buf[:n]); werr != nil {
					ch.e.log.Debug("channel: write stream", "peer", keyName(ch.peer), "error", werr)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// setStream publishes c as the current peer edge, replacing (and closing) a
// predecessor.
func (ch *channel) setStream(c net.Conn) {
	ch.mu.Lock()
	old := ch.stream
	ch.stream = c
	ch.mu.Unlock()
	if old != nil && old != c {
		old.Close()
	}
}

// clearStream drops c if it is still the current peer edge (a reconnect may
// already have replaced it).
func (ch *channel) clearStream(c net.Conn) {
	ch.mu.Lock()
	if ch.stream == c {
		ch.stream = nil
	}
	ch.mu.Unlock()
}

// clearLocal drops c if it is still the current local edge (a newer dial may
// already have replaced it).
func (ch *channel) clearLocal(c net.Conn) {
	ch.mu.Lock()
	if ch.local == c {
		ch.local = nil
	}
	ch.mu.Unlock()
}

// channelTag marks a stream as carrying a datagram channel. An ordinary tunnel
// stream's payload is arbitrary bytes, so the responder needs an explicit
// marker to tell the two apart.
const channelTag = "P2PU"

// channelTagTimeout bounds the tag peek on an inbound stream. An untagged
// stream may legitimately be idle (a bridged protocol whose target speaks
// first), so waiting for its first bytes would deadlock that bridge.
// A var so tests can shorten it.
var channelTagTimeout = 2 * time.Second

// peekTag classifies an inbound stream by its leading bytes. Bytes consumed by
// a partial read are replayed through the returned conn, so an untagged stream
// is handed on byte-for-byte as it arrived.
func peekTag(c net.Conn) (tagged bool, rest net.Conn) {
	c.SetReadDeadline(time.Now().Add(channelTagTimeout))
	var tag [4]byte
	n, err := io.ReadFull(c, tag[:])
	c.SetReadDeadline(time.Time{})
	if err == nil && string(tag[:]) == channelTag {
		return true, c
	}
	if n == 0 {
		return false, c
	}
	return false, &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(tag[:n]), c)}
}

// prefixConn replays bytes already consumed from a stream before reading the
// stream itself.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }
