package host

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// A udp tunnel is a datagram link: one per dial, pairing the dial's tunnel
// stream (the local edge) with one peer edge — a tagged stream to the peer over
// the relay or the hole-punched path. The host never parses the data: the
// GOST-side conns frame the datagrams into 2-byte-prefixed frames and the
// peer's GOST-side conn parses them, so frame bytes travel through verbatim.
//
// The dialing side always presents: a link opens its own tagged edge as soon as
// it is allocated, so a one-sided link — the peer holds no dial of its own —
// works whatever the key order, and N concurrent dials to one peer never share
// an edge.
//
// Two dials, one on each side of the same pair, are a rendezvous on one edge,
// not two links: the larger key adopts the smaller key's presentation (its own
// presentation is provisional and is dropped at adoption). A link that holds an
// adopted edge is never displaced — an extra inbound edge from the peer is
// served per stream (embedder or udp target) instead of stealing it.
//
// Bytes are dropped while the opposite edge is absent or down, exactly like the
// endpoint model, with one exception: a link with no live peer edge buffers the
// local bytes it reads (bounded), so the datagram that triggered the dial is not
// lost while the presentation opens.
type link struct {
	e    *engine
	peer derpclient.PublicKey

	stop     chan struct{} // closed by close(); ends the presenter and the pumps
	stopOnce sync.Once
	done     chan struct{} // closed when the link is torn down; the carrier parks here
	doneOnce sync.Once
	edgeGone chan struct{} // buffered(1): a peer edge died, the presenter re-presents

	// wmu serializes everything written to the peer edge — payloads and the
	// first-datagram buffer drain — so the buffer can be flushed by the edge's
	// publisher without reordering bytes behind a payload in flight. It is
	// never held while taking mu.
	wmu  sync.Mutex
	wbuf []byte // local bytes held while no peer edge is live; capped

	mu       sync.Mutex
	local    net.Conn // this dial's tunnel stream; nil until the carrier attaches
	peerEdge net.Conn // current peer edge: our presentation or an adopted one
	own      net.Conn // our presentation edge; nil once adopted or when it dies
	closed   bool
}

// linkBufLimit caps the first-datagram buffer: it exists to keep the datagram
// that triggered a dial (and its first replies) while the presentation opens,
// not to become an unbounded queue. Beyond it, new bytes are dropped.
const linkBufLimit = 32 * 1024

// linkChunkSize bounds one pump read; frame bytes from the GOST side arrive in
// chunks at most this size.
const linkChunkSize = 32 * 1024

// channelTag marks a stream as carrying a datagram channel. An ordinary tunnel
// stream's payload is arbitrary bytes, so the responder needs an explicit
// marker to tell the two apart.
const channelTag = "P2PU"

// channelTagTimeout bounds the tag peek on an inbound stream. An untagged
// stream may legitimately be idle (a bridged protocol whose target speaks
// first), so waiting for its first bytes would deadlock that bridge.
// A var so tests can shorten it.
var channelTagTimeout = 2 * time.Second

// channelRetryMin is the presentation reconnect floor. A peer that just came
// back (restarted, or its path dropped) is picked up within seconds instead of
// waiting out the punch backoff; a stream the peer refused means the peer is
// there but its side is not serving datagrams yet, so that retries fast too.
// Only an outright open failure (peer unreachable) backs off.
const channelRetryMin = 2 * time.Second

// channelRetryDelay returns the next presentation reconnect delay: open
// failures grow towards the punch backoff, everything else resets to the floor.
func channelRetryDelay(prev time.Duration, openFailed bool) time.Duration {
	if openFailed {
		return min(2*prev, backoffPeriod)
	}
	return channelRetryMin
}

// newLink creates the datagram link of one udp dial and starts its presenter.
// The caller registers it on the engine so inbound edges can find it.
func newLink(e *engine, peer derpclient.PublicKey) *link {
	l := &link{
		e:        e,
		peer:     peer,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		edgeGone: make(chan struct{}, 1),
	}
	go l.presentLoop()
	return l
}

// attach publishes conn as the link's local edge (this dial's tunnel stream)
// and starts the local->peer pump. The gRPC carrier calls it when its stream
// arrives, the in-process carrier immediately. The returned channel is closed
// when the link is torn down, so the carrier can park for the tunnel's
// lifetime; the pump's exit closes the link, so a carrier that ends its stream
// ends the tunnel.
func (l *link) attach(conn net.Conn) <-chan struct{} {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		conn.Close()
		return l.done
	}
	l.local = conn
	l.mu.Unlock()
	go l.pumpLocal(conn)
	return l.done
}

// adoptable reports whether an inbound edge may replace this link's peer edge:
// only when the edge is absent or still our own presentation. An adopted edge is
// never displaced — a second inbound edge from the same peer is served per
// stream instead of stealing the link. The key-order half of the rule lives in
// engine.adoptableLink.
func (l *link) adoptable() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	return l.peerEdge == nil || l.peerEdge == l.own
}

// hasEdge reports whether a peer edge is live.
func (l *link) hasEdge() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.peerEdge != nil
}

// currentEdge returns the peer edge to write to, if any.
func (l *link) currentEdge() net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.peerEdge
}

// presentLoop keeps a presentation edge up while the link has none: open a
// tagged stream, publish it, wait for it to end (or be adopted), repeat. A link
// that holds an adopted edge presents nothing — the pair is already on one
// shared edge, and a second presenter would fight it.
func (l *link) presentLoop() {
	pname := keyName(l.peer)
	delay := channelRetryMin
	for {
		if l.hasEdge() {
			select {
			case <-l.stop:
				return
			case <-l.edgeGone:
			}
			continue
		}

		openFailed := false
		c, err := l.e.openTaggedStream(pname)
		if err == nil {
			if !l.publishOwn(c) {
				c.Close()
				if l.isClosed() {
					return
				}
				// An adopt raced the open and won: there is nothing to present,
				// and the loop's hasEdge check parks it on the adopted edge.
				continue
			}
			l.e.log.Info("datagram link up", "peer", pname)
			// Wait for this presentation to end before deciding the next delay:
			// a stream that lived (peer restart, path drop) resets the cadence
			// to the fast floor, an outright open failure backs off.
			select {
			case <-l.stop:
				return
			case <-l.edgeGone:
			}
		} else {
			openFailed = true
			if c != nil {
				c.Close()
			}
			l.e.log.Debug("link: open presentation", "peer", pname, "error", err)
		}

		select {
		case <-l.stop:
			return
		case <-time.After(delay):
		}
		delay = channelRetryDelay(delay, openFailed)
	}
}

// publishOwn makes c the link's presentation edge and starts its reader. It
// returns false when the link is closed or already holds an adopted edge (an
// adopt raced the open) — the caller still owns c and must close it.
func (l *link) publishOwn(c net.Conn) bool {
	l.mu.Lock()
	if l.closed || (l.peerEdge != nil && l.peerEdge != l.own) {
		l.mu.Unlock()
		return false
	}
	l.own, l.peerEdge = c, c
	l.mu.Unlock()
	go l.serveEdge(c)
	// Asynchronous: a flush can block on a peer that is not reading yet, and
	// the presenter must stay free to react to the edge dying. wmu keeps the
	// buffered bytes ahead of anything written later.
	go l.flush()
	return true
}

// adopt makes c the link's peer edge, replacing (and closing) the current one.
// It is the rendezvous half of the model: the larger key adopts the smaller
// key's presentation so the pair rides one shared edge. false means the link is
// closed or already holds an adopted edge — an adopted edge is never displaced,
// so the caller serves c per stream instead (and still owns c). The key-order
// half of the rule lives in engine.adoptableLink; this is the re-check that
// closes the window between that lookup and here.
func (l *link) adopt(c net.Conn, transport string) bool {
	l.mu.Lock()
	if l.closed || (l.peerEdge != nil && l.peerEdge != l.own) {
		l.mu.Unlock()
		return false
	}
	old, own := l.peerEdge, l.own
	l.peerEdge, l.own = c, nil
	l.mu.Unlock()
	// Our presentation is superseded; its reader retires it.
	if own != nil && own != c {
		own.Close()
	}
	if old != nil && old != c && old != own {
		old.Close()
	}
	l.e.log.Info("datagram link up", "peer", keyName(l.peer), "transport", transport)
	go l.serveEdge(c)
	go l.flush() // as in publishOwn: never block the adopter on a slow reader
	return true
}

// isClosed reports whether the link has been torn down.
func (l *link) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// serveEdge moves bytes from one peer edge to the local edge until it ends,
// then retires it. It is the edge's only reader, so the cleanup cannot race a
// second reader of the same conn.
func (l *link) serveEdge(c net.Conn) {
	defer func() {
		l.retireEdge(c)
		c.Close()
	}()

	buf := make([]byte, linkChunkSize)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			l.mu.Lock()
			local := l.local
			l.mu.Unlock()
			if local != nil {
				if _, werr := local.Write(buf[:n]); werr != nil {
					// Keep serving: a write error (e.g. the gost edge just died)
					// must not cost the link its peer edge.
					l.e.log.Debug("link: write local", "peer", keyName(l.peer), "error", werr)
				}
			}
			// No local yet: the carrier has not attached, so there is nobody to
			// deliver to — dropped, like any datagram loss.
		}
		if err != nil {
			return
		}
	}
}

// retireEdge clears c if it is still the link's edge and wakes the presenter.
// An adopted edge that dies is replaced by a fresh presentation; our own edge
// dying is the presenter's cue to reopen it.
func (l *link) retireEdge(c net.Conn) {
	l.mu.Lock()
	current := l.peerEdge == c
	if current {
		l.peerEdge = nil
		l.e.log.Info("datagram link down", "peer", keyName(l.peer))
	}
	if l.own == c {
		l.own = nil
	}
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return
	}
	select {
	case l.edgeGone <- struct{}{}:
	default:
	}
}

// pumpLocal moves the dial's bytes onto the current peer edge. Bytes read while
// no edge is live are buffered (bounded); bytes that do not fit are dropped.
// The pump's exit ends the link: the dial's stream ending IS the dial ending.
func (l *link) pumpLocal(c net.Conn) {
	defer l.close()

	buf := make([]byte, linkChunkSize)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			l.writeEdge(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// writeEdge appends p to the peer edge, draining the buffer first so bytes keep
// their order. With no live edge, p goes to the buffer instead.
func (l *link) writeEdge(p []byte) {
	l.wmu.Lock()
	defer l.wmu.Unlock()

	l.flushLocked()
	if e := l.currentEdge(); e != nil {
		if _, err := e.Write(p); err != nil {
			l.e.log.Debug("link: write peer edge", "peer", keyName(l.peer), "error", err)
		}
		return
	}
	if len(l.wbuf)+len(p) > linkBufLimit {
		l.e.log.Debug("link: first-datagram buffer full, dropping", "peer", keyName(l.peer))
		return
	}
	l.wbuf = append(l.wbuf, p...)
}

// flush drains the first-datagram buffer onto the current edge. It runs when an
// edge is published: the pump may be parked in Read and would otherwise hold
// the buffered bytes until the next datagram arrives.
func (l *link) flush() {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	l.flushLocked()
}

// flushLocked must be called with wmu held. Without a live edge the buffer is
// left for the next call.
func (l *link) flushLocked() {
	if len(l.wbuf) == 0 {
		return
	}
	e := l.currentEdge()
	if e == nil {
		return
	}
	if _, err := e.Write(l.wbuf); err != nil {
		l.e.log.Debug("link: flush buffer", "peer", keyName(l.peer), "error", err)
	}
	l.wbuf = nil
}

// close tears the link down: the presenter stops, the edges and the local
// stream are closed (their pumps exit), and done is closed so the carrier can
// return. Idempotent; the record's drop and the local pump's exit are the
// callers.
func (l *link) close() {
	l.stopOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		local, edge, own := l.local, l.peerEdge, l.own
		l.local, l.peerEdge, l.own = nil, nil, nil
		l.mu.Unlock()

		close(l.stop)
		if local != nil {
			local.Close()
		}
		if own != nil && own != edge {
			own.Close()
		}
		if edge != nil {
			edge.Close()
		}
		l.doneOnce.Do(func() { close(l.done) })
	})
}

// addLink registers l for its peer so inbound datagram edges can find it. A
// host may hold several links to one peer (concurrent dials); the rendezvous
// shape has exactly one.
func (e *engine) addLink(l *link) {
	e.mu.Lock()
	e.links[l.peer] = append(e.links[l.peer], l)
	e.mu.Unlock()
}

// removeLink drops l from its peer's list by identity, so a concurrent add of
// another link is never clobbered.
func (e *engine) removeLink(l *link) {
	e.mu.Lock()
	ls := e.links[l.peer]
	for i, x := range ls {
		if x == l {
			ls = append(ls[:i], ls[i+1:]...)
			break
		}
	}
	if len(ls) == 0 {
		delete(e.links, l.peer)
	} else {
		e.links[l.peer] = ls
	}
	e.mu.Unlock()
}

// adoptableLink returns the link that may adopt an inbound edge from peer, or
// nil: only the larger key adopts (the smaller keeps its own presentation, so
// the pair converges on one edge), and only a link that is waiting for one.
func (e *engine) adoptableLink(peer derpclient.PublicKey) *link {
	if bytes.Compare(e.pub[:], peer[:]) <= 0 {
		return nil
	}
	e.mu.Lock()
	ls := append([]*link(nil), e.links[peer]...)
	e.mu.Unlock()
	for _, l := range ls {
		if l.adoptable() {
			return l
		}
	}
	return nil
}

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

// serveTargetStream bridges one inbound datagram stream to a udp target from
// the pool: frame bytes from the stream become datagrams at the target, and
// each datagram comes back as a frame. It is the target half of a datagram
// link; nothing outlives the stream, so there is no per-peer state.
// Either direction ending tears the pair down.
func (e *engine) serveTargetStream(stream net.Conn, target string) {
	defer stream.Close()
	c, err := net.Dial("udp", target)
	if err != nil {
		e.log.Debug("datagram target dial", "target", target, "error", err)
		return
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		e.log.Debug("datagram target is not udp", "target", target)
		return
	}
	edge := newDgramEdge(uc)
	defer edge.Close()

	done := make(chan struct{}, 2)
	go func() { // stream frames -> target datagrams
		buf := make([]byte, linkChunkSize)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, werr := edge.Write(buf[:n]); werr != nil {
					e.log.Debug("datagram target write", "target", target, "error", werr)
				}
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() { // target datagrams -> stream frames
		buf := make([]byte, linkChunkSize)
		for {
			n, err := edge.Read(buf)
			if n > 0 {
				if _, werr := stream.Write(buf[:n]); werr != nil {
					e.log.Debug("datagram stream write", "target", target, "error", werr)
				}
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

// openTaggedStream opens a stream to peer and writes the datagram-channel tag
// before returning it: the tag must precede any frame byte, or the responder
// would read payload as the tag. The stream is closed on a tag-write failure,
// so a non-nil error never leaves the caller owning a stream.
func (e *engine) openTaggedStream(pname string) (net.Conn, error) {
	open := e.OpenStream
	if e.openStream != nil {
		open = e.openStream // test seam
	}
	c, err := open(pname)
	if err != nil {
		return nil, err
	}
	if _, werr := c.Write([]byte(channelTag)); werr != nil {
		c.Close()
		return nil, werr
	}
	return c, nil
}
