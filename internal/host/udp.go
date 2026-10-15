package host

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
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

	// sessionScoped: a peer edge that was already established is not re-presented
	// onto the session it died on — the consumer's registered state (the
	// addresses an "ip"/tun side registers, per session) is stale for it, so the
	// presenter waits for a newer session (see mayPresent and
	// engine.peerSessionEvents). The link itself is unaffected: it lives as long
	// as its local carrier does (see retireEdge).
	sessionScoped bool

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
	hadEdge  bool     // a peer edge has been established at least once

	// rodeGen is the peer relay session generation the current (or most recent)
	// peer edge rode, assigned when that edge was installed. A session-scoped
	// link re-presents only once the peer has built a newer generation (see
	// mayPresent): the state the consumer registered with the peer was scoped to
	// the session that edge rode, so presenting over the same one would ride a
	// session the peer no longer holds the state for. The engine bumps
	// sessionGen on every relay session build, so no embedder input is involved.
	rodeGen uint64
	// parkSince is when the presenter first held off presenting because the
	// generation had not moved. It bounds the hold: a link that is itself the
	// only traffic a peer sees would otherwise leave the generation frozen and
	// stall on its own buffer.
	parkSince time.Time
	closed    bool
	// edgeGen is bumped every time a peer edge is installed. serveEdge
	// captures it and stops feeding the local conn once it moves on: closing a
	// superseded edge is not the same as silencing it, because streamConn.Read
	// selects between a queued chunk and its closed channel and can still hand
	// one over. Those bytes belong to a retired stream, and writing them into
	// the tunnel splices two streams into one byte stream.
	edgeGen uint64

	// Observability for the supersede window. staleWrites counts writes dropped
	// because the edge was superseded; maxLocalWriters is the high-water mark of
	// serveEdge goroutines writing the local conn at once. Both ride the edge-end
	// log line, so the window shows up next to the traffic that flowed through
	// it instead of needing its own line.
	staleWrites     atomic.Int64
	localWriters    atomic.Int64
	maxLocalWriters atomic.Int64
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

// scopedRePresentGrace bounds how long a session-scoped link holds off
// presenting while the peer's relay session generation stays put. The
// generation is the signal that the peer holds fresh state for this link, but a
// link that is itself the only traffic a peer sees would leave it frozen — the
// bytes it is holding sit in the link's buffer rather than reaching the peer —
// so the hold has to give way eventually. Presenting over the same session is
// what the consumer asked for; staying parked is not.
var scopedRePresentGrace = 10 * time.Second

// channelRetryDelay returns the next presentation reconnect delay: open
// failures grow towards the punch backoff, everything else resets to the floor.
func channelRetryDelay(prev time.Duration, openFailed bool) time.Duration {
	if openFailed {
		return min(2*prev, backoffPeriod)
	}
	return channelRetryMin
}

// newLink creates the datagram link of one datagram dial and starts its
// presenter. The caller registers it on the engine so inbound edges can find it.
// sessionScoped marks a link whose consumer registered state with the peer per
// session (the "ip"/tun case): it waits for a fresh peer session before
// presenting an edge it lost, rather than riding a stale one. The link still
// lives as long as its local carrier does either way (see retireEdge).
func newLink(e *engine, peer derpclient.PublicKey, sessionScoped bool) *link {
	l := &link{
		e:             e,
		peer:          peer,
		sessionScoped: sessionScoped,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		edgeGone:      make(chan struct{}, 1),
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
		// A session-scoped link that has already ridden an edge holds off until
		// the peer builds a newer relay session: the state the consumer
		// registered with the peer was scoped to the session that edge rode
		// (see mayPresent). It does not spin: the hold is bounded, and an
		// outright open failure still backs off.
		if !l.mayPresent() {
			l.noteParked()
			select {
			case <-l.stop:
				return
			// Wake on the session event rather than only on the poll timer: the
			// 2s floor is the worst case, and a consumer re-registering on a new
			// session is waiting on this lane becoming usable.
			case <-l.e.peerSessionEvents(l.peer):
			case <-time.After(channelRetryMin):
			}
			continue
		}
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

// mayPresent reports whether the presenter may open an edge now.
//
// A session-scoped link waits for the peer's relay session generation to move
// past the edge it last rode: the engine bumps it on every session build
// (peerConn.sessionLocked), so a move means the peer holds fresh state for this
// link. Before the first edge there is nothing stale to ride, so it presents —
// that is how a peer that starts late converges.
//
// The hold is bounded (scopedRePresentGrace) so a link that is itself the only
// traffic a peer sees cannot stall on a frozen generation.
func (l *link) mayPresent() bool {
	if !l.sessionScoped {
		return true
	}
	l.mu.Lock()
	had, rode, parkedAt := l.hadEdge, l.rodeGen, l.parkSince
	l.mu.Unlock()
	if !had {
		return true
	}
	if rode < l.e.peerSessionGen(l.peer) {
		return true
	}
	return !parkedAt.IsZero() && time.Since(parkedAt) > scopedRePresentGrace
}

// noteRidden records the peer session generation the newly installed edge rode,
// and clears any park: an edge is up, so the link is no longer holding off.
func (l *link) noteRidden() {
	l.mu.Lock()
	l.rodeGen = l.e.peerSessionGen(l.peer)
	l.parkSince = time.Time{}
	l.mu.Unlock()
}

// noteParked marks the start of a hold-off, unless one is already running.
func (l *link) noteParked() {
	l.mu.Lock()
	if l.parkSince.IsZero() {
		l.parkSince = time.Now()
	}
	l.mu.Unlock()
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
	l.own, l.peerEdge, l.hadEdge = c, c, true
	l.edgeGen++
	gen := l.edgeGen
	l.mu.Unlock()
	l.noteRidden()
	go l.serveEdge(c, gen)
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
		closed, holdsAdopted := l.closed, l.peerEdge != nil && l.peerEdge != l.own
		l.mu.Unlock()
		l.e.log.Debug("link: inbound edge refused", "peer", keyName(l.peer), "transport", transport,
			"closed", closed, "holdsAdoptedEdge", holdsAdopted)
		return false
	}
	old, own := l.peerEdge, l.own
	l.peerEdge, l.own, l.hadEdge = c, nil, true
	l.edgeGen++
	gen := l.edgeGen
	l.mu.Unlock()
	l.noteRidden()
	// Our presentation is superseded; its reader retires it.
	if own != nil && own != c {
		own.Close()
	}
	if old != nil && old != c && old != own {
		old.Close()
	}
	l.e.log.Info("datagram link up", "peer", keyName(l.peer), "transport", transport)
	go l.serveEdge(c, gen)
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
//
// gen is the link's edge generation when this edge was installed. It is the
// fence that keeps a superseded edge off the local conn: the edge it replaced
// may still be readable for a moment (a queued chunk outlives Close), and those
// bytes belong to a different stream.
func (l *link) serveEdge(c net.Conn, gen uint64) {
	started := time.Now()
	var read, written, drops, stale int64
	var readErr error

	defer func() {
		l.retireEdge(c)
		c.Close()
		// One line closes out the edge, because "datagram link down" alone left
		// the only open question unanswered: did anything flow, and what broke
		// it. readErr carries the reason when there was one.
		l.logEdgeEnd(started, read, written, drops, stale, readErr)
	}()

	buf := make([]byte, linkChunkSize)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			read += int64(n)
			local, isCurrent := l.localFor(gen)
			switch {
			case !isCurrent:
				// Superseded while this read was in flight. Dropping is the
				// whole point: the far end is parsing one continuous byte
				// stream, and these bytes are not part of it.
				stale += int64(n)
				l.staleWrites.Add(1)
			case local == nil:
				// No local yet: the carrier has not attached, so there is nobody
				// to deliver to — dropped, like any datagram loss.
				drops += int64(n)
			default:
				// Track the overlap that the supersede window makes possible, so
				// a stream that ever saw two writers at once says so here
				// instead of leaving it to be inferred from a bad frame.
				l.noteLocalWriter()
				wn, werr := local.Write(buf[:n])
				l.localWriters.Add(-1)
				if werr != nil {
					// Keep serving: a write error (e.g. the gost edge just died)
					// must not cost the link its peer edge.
					l.e.log.Debug("link: write local", "peer", keyName(l.peer), "error", werr)
				} else {
					written += int64(wn)
				}
			}
		}
		if err != nil {
			readErr = err
			return
		}
		if stale > 0 {
			// Nothing this edge holds can reach the local conn any more, so
			// stop reading rather than spin on a retired stream.
			readErr = errEdgeSuperseded
			return
		}
	}
}

// localFor returns the local edge to write to, and whether this edge is still
// the link's current peer edge.
func (l *link) localFor(gen uint64) (net.Conn, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.local, l.edgeGen == gen
}

// noteLocalWriter records the high-water mark of goroutines writing the local
// conn. Compare-and-swap rather than a plain store: two writers racing can
// finish out of order, and a plain store would let the smaller one land last
// and overwrite the larger — hiding exactly the overlap this exists to surface.
func (l *link) noteLocalWriter() {
	w := l.localWriters.Add(1)
	for {
		m := l.maxLocalWriters.Load()
		if w <= m || l.maxLocalWriters.CompareAndSwap(m, w) {
			return
		}
	}
}

// errEdgeSuperseded ends a serveEdge loop whose edge was replaced. It is not a
// failure to report: the edge-end line already says what happened.
var errEdgeSuperseded = errors.New("edge superseded")

// logEdgeEnd reports how a peer edge ended. The byte counts are the point: every
// reader of this log asks whether anything flowed before the edge died, and
// answering that needed a packet capture before.
//
// stale and maxLocalWriters ride along because they answer the two questions
// the counts above cannot: whether a superseded edge wrote anything, and
// whether two edges were ever writing the local conn at once. Both stay 0 on a
// healthy link, so a non-zero value is the whole diagnosis in one line.
//
// The level follows the cause. A stream the peer ended (EOF) or that a teardown
// closed (ErrClosed) is the ordinary case the presenter recovers from by
// re-presenting, so it stays at debug; anything else means the edge broke while
// it was still supposed to work, and that is a warning.
func (l *link) logEdgeEnd(started time.Time, read, written, drops, stale int64, err error) {
	if l.e.log == nil {
		return
	}
	if err != nil && !isEdgeEndError(err) && !errors.Is(err, errEdgeSuperseded) {
		l.e.log.Warn("link: edge failed", l.edgeEndFields(started, read, written, drops, stale, err)...)
		return
	}
	l.e.log.Debug("link: edge ended", l.edgeEndFields(started, read, written, drops, stale, err)...)
}

func (l *link) edgeEndFields(started time.Time, read, written, drops, stale int64, err error) []any {
	fields := []any{
		"peer", keyName(l.peer),
		"age", time.Since(started).Round(time.Millisecond).String(),
		"read", read, "written", written, "dropped", drops,
	}
	if stale > 0 || l.maxLocalWriters.Load() > 1 {
		fields = append(fields, "staleWrites", stale,
			"maxLocalWriters", l.maxLocalWriters.Load())
	}
	if err != nil {
		fields = append(fields, "error", err)
	}
	return fields
}

// isEdgeEndError reports err as the peer or the path letting go rather than this
// edge breaking on its own. Both are recoverable by re-presenting. The framing
// failures the relay can produce — a lost record boundary, a bad length — are
// deliberately not here: those mean the byte stream no longer means what it did,
// which re-presenting cannot fix.
func isEdgeEndError(err error) bool {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrUnexpectedEOF):
		return true
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	return false
}

// retireEdge clears c if it is still the link's edge and wakes the presenter.
// An adopted edge that dies is replaced by a fresh presentation; our own edge
// dying is the presenter's cue to reopen it.
//
// A lost peer edge never ends the link. The link lives as long as its local
// carrier does: the carrier's stream ending is the dial ending (pumpLocal), and
// that is the only thing that closes the link. The carrier cannot tell "my
// tunnel is over" from "this link's edge died", so a link that ended here left
// it waiting forever for a re-dial it had no reason to make — the 45-minute
// blackhole. A session-scoped link still waits for a fresh peer session before
// presenting again (mayPresent), because the state the consumer registered with
// the peer was scoped to the session that edge rode.
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
			// The dial's stream ending IS the dial ending: this closes the link.
			l.e.log.Debug("link: local edge ended", "peer", keyName(l.peer), "error", err)
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

		l.e.log.Debug("link closed", "peer", keyName(l.peer), "local", local != nil,
			"edge", edge != nil, "own", own != nil)

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
	n := len(e.links[l.peer])
	e.mu.Unlock()
	e.log.Debug("link registered", "peer", keyName(l.peer), "links", n)
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
	n := len(ls)
	e.mu.Unlock()
	e.log.Debug("link unregistered", "peer", keyName(l.peer), "links", n)
}

// peerSessionGen returns the peer's relay session generation, or 0 when the
// engine holds no session for it. The generation advances on every relay
// session build (peerConn.sessionLocked), which is the embedder-agnostic signal
// that a peer holds fresh state: a link uses it to decide when it may present
// again (link.mayPresent).
func (e *engine) peerSessionGen(peer derpclient.PublicKey) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if pc, ok := e.peers[peer]; ok {
		return pc.sessionGen.Load()
	}
	return 0
}

// adoptableLink returns the link that may adopt an inbound edge from peer, or
// nil: only the larger key adopts (the smaller keeps its own presentation, so
// the pair converges on one edge), and only a link that is waiting for one.
func (e *engine) adoptableLink(peer derpclient.PublicKey) *link {
	if bytes.Compare(e.pub[:], peer[:]) <= 0 {
		// Smaller key: it never adopts, it presents. An inbound edge from this
		// peer is then served by the embedder/target, not paired with a link.
		e.log.Debug("adoptable link: none, we are the smaller key", "peer", keyName(peer))
		return nil
	}
	e.mu.Lock()
	ls := append([]*link(nil), e.links[peer]...)
	e.mu.Unlock()
	var reasons []string
	for _, l := range ls {
		if l.adoptable() {
			return l
		}
		l.mu.Lock()
		reasons = append(reasons, fmt.Sprintf("closed=%v edge=%v own=%v", l.closed, l.peerEdge != nil, l.own != nil))
		l.mu.Unlock()
	}
	e.log.Debug("adoptable link: none", "peer", keyName(peer), "links", len(ls), "states", reasons)
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
