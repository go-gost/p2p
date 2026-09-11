package main

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// Datagram channel: the per-peer UDP tunnel. The local gost dials a UDP
// endpoint bound here; every datagram received on it is framed onto the peer's
// stream, and every frame read from that stream is written back to the last
// client address seen. This is what carries a tun link end to end: the tunnel
// is a byte stream, the endpoint is the datagram edge on each side, and the
// framing in between preserves packet boundaries.
//
// Role by public-key ordering, the same rule as the mux session: the smaller
// key opens the stream (loop), the larger is served by acceptLoop. Each side
// creates its channel when its own gost dials, so nothing has to be learned
// from the peer.
type channel struct {
	e    *Engine
	peer derpclient.PublicKey

	sock net.PacketConn
	stop chan struct{} // closed by teardown; ends loop

	mu     sync.Mutex
	stream net.Conn // current upstream stream; nil while the channel is down
	refs   int      // gost tunnels holding this channel open
	closed bool
	client net.Addr // last client address seen on the endpoint (nil until gost dials)
}

// openChannel returns the peer's channel, creating and starting it on first
// use, and takes a reference on it. The channel outlives individual gost
// tunnels: it is torn down when the last one closes.
func (e *Engine) openChannel(peer derpclient.PublicKey) (*channel, error) {
	e.mu.Lock()
	if ch, ok := e.chans[peer]; ok {
		ch.mu.Lock()
		if !ch.closed {
			ch.refs++
			ch.mu.Unlock()
			e.mu.Unlock()
			return ch, nil
		}
		ch.mu.Unlock()
		delete(e.chans, peer) // drop the dead channel
	}

	sock, err := net.ListenPacket("udp", net.JoinHostPort(e.bind, "0"))
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	ch := &channel{
		e:    e,
		peer: peer,
		sock: sock,
		stop: make(chan struct{}),
		refs: 1,
	}
	e.chans[peer] = ch
	e.mu.Unlock()

	go ch.readLocal()
	if bytes.Compare(e.pub[:], peer[:]) < 0 {
		e.log.Info("channel role", "peer", keyName(peer), "role", "opener",
			"endpoint", sock.LocalAddr().String())
		go ch.loop()
	} else {
		e.log.Info("channel role", "peer", keyName(peer), "role", "responder",
			"endpoint", sock.LocalAddr().String())
	}
	return ch, nil
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

// release drops one reference; the last one tears the channel down and removes
// it, so the next openChannel rebuilds it with a fresh endpoint. Reference
// count and map entry are updated under the engine lock, so an open racing a
// close sees either the live channel or a fresh one — never a torn-down
// endpoint.
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
	if ch.e.chans[ch.peer] == ch {
		delete(ch.e.chans, ch.peer)
	}
	ch.mu.Unlock()
	ch.e.mu.Unlock()

	ch.stopLoop(stream)
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
	ch.mu.Unlock()

	ch.stopLoop(stream)
	return true
}

// stopLoop stops the opener loop and unblocks the endpoint reader and the
// stream reader.
func (ch *channel) stopLoop(stream net.Conn) {
	close(ch.stop)
	ch.sock.Close()
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
			// serving it would feed a dead channel (and its endpoint socket is
			// already closed).
			if ch.stopped() {
				c.Close()
				return
			}
			// The tag goes out before the stream is published (setStream /
			// serveStream), so a datagram frame can never precede it and make
			// the responder read frame bytes as the tag.
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

// serveStream publishes c as the channel's upstream stream and pumps frames
// from it until it dies. Frames read while no client is known (the local gost
// has not dialled the endpoint yet) are dropped: IP tolerates loss.
func (ch *channel) serveStream(c net.Conn) {
	ch.setStream(c)
	defer func() {
		ch.clearStream(c)
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
		ch.mu.Lock()
		client := ch.client
		ch.mu.Unlock()
		if client == nil {
			continue
		}
		if _, err := ch.sock.WriteTo(p, client); err != nil {
			// Drop and keep serving: a datagram error (e.g. a stale client
			// address) must not cost the whole channel a reconnect.
			ch.e.log.Debug("channel: write endpoint", "peer", keyName(ch.peer), "error", err)
		}
	}
}

// readLocal pumps datagrams from the endpoint onto the current upstream stream
// for the lifetime of the channel. The last client seen wins: gost dials with
// a new source port on every re-dial. An empty datagram carries no payload but
// still announces the client (gost sends one right after dialling), which is
// how a peer that speaks first stays reachable.
func (ch *channel) readLocal() {
	buf := make([]byte, maxFrame)
	for {
		n, addr, err := ch.sock.ReadFrom(buf)
		if err != nil {
			return // endpoint closed
		}
		ch.mu.Lock()
		ch.client = addr
		s := ch.stream
		ch.mu.Unlock()
		if n <= 0 {
			continue
		}
		if s == nil {
			continue // channel down: drop
		}
		if err := writeFrame(s, buf[:n]); err != nil {
			ch.e.log.Debug("channel: write stream", "peer", keyName(ch.peer), "error", err)
		}
	}
}

// setStream publishes c as the current upstream stream, replacing (and
// closing) a predecessor.
func (ch *channel) setStream(c net.Conn) {
	ch.mu.Lock()
	old := ch.stream
	ch.stream = c
	ch.mu.Unlock()
	if old != nil && old != c {
		old.Close()
	}
}

// clearStream drops c if it is still the current stream (a reconnect may
// already have replaced it).
func (ch *channel) clearStream(c net.Conn) {
	ch.mu.Lock()
	if ch.stream == c {
		ch.stream = nil
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
