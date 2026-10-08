package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/xtaci/kcp-go/v5"
)

// relayConv deterministically derives the KCP conversation ID for the relay
// plane from a sorted keypair. It mirrors directConn.conv but appends a domain
// tag so the relay underlay never collides with the direct-plane conv for the
// same pair.
func relayConv(a, b derpclient.PublicKey) uint32 {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	h := sha256.Sum256(append(append(a[:], b[:]...), []byte("p2p-relay-kcp")...))
	return binary.BigEndian.Uint32(h[:4])
}

// relayPacketConn adapts a peerConn into a net.PacketConn so KCP can run over
// the lossy DERP relay. Each inbound channel element is one datagram; writes
// become a single DERP SendPacket.
type relayPacketConn struct {
	pc *peerConn
	// kick, when set, ends the read early: the pair this adapter feeds has
	// swapped endpoints or closed (see relayKCPPair.ReadFrom), and a reader
	// parked here must not outlive the pair's interest in this queue. It is
	// nil for a standalone adapter, where the case never fires.
	kick <-chan struct{}
}

// newRelayPacketConn wraps pc for use as a KCP net.PacketConn underlay.
func newRelayPacketConn(pc *peerConn) *relayPacketConn {
	return &relayPacketConn{pc: pc}
}

// ReadFrom returns one queued datagram. Once closeCh is closed it drains one
// final queued packet before reporting io.EOF; the kick channel degrades the
// same way. If the caller's buffer is smaller than the datagram, the copy is
// truncated to len(p) exactly like UDP.
func (rc *relayPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var pkt []byte
	select {
	case pkt = <-rc.pc.inbound:
	case <-rc.pc.closeCh:
		select {
		case pkt = <-rc.pc.inbound:
		default:
			return 0, nil, io.EOF
		}
	case <-rc.kick:
		select {
		case pkt = <-rc.pc.inbound:
		default:
			return 0, nil, io.EOF
		}
	}
	n := copy(p, pkt)
	return n, dummyAddr{}, nil
}

// WriteTo forwards one datagram to pc.Write, which sends it as a single DERP
// SendPacket. The destination address is ignored because the peer is fixed.
func (rc *relayPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return rc.pc.Write(p)
}

// Close closes the underlying peerConn adapter.
func (rc *relayPacketConn) Close() error {
	return rc.pc.Close()
}

// LocalAddr returns a placeholder address.
func (rc *relayPacketConn) LocalAddr() net.Addr { return dummyAddr{} }

// RemoteAddr returns a placeholder address identifying the peer.
func (rc *relayPacketConn) RemoteAddr() net.Addr { return dummyAddr{rc.pc.peer} }

// SetDeadline is a no-op; deadlines are not meaningful for this adapter.
func (rc *relayPacketConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op.
func (rc *relayPacketConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op.
func (rc *relayPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// Relay-plane KCP tuning. Internal constants, deliberately not configurable:
// there is no trusted use case for a less reliable relay plane, so rollback
// is a revert, not a switch (same posture as the direct plane).
const (
	// relayKCPMtu keeps one KCP segment inside a single DERP packet, so a
	// relay drop costs exactly one segment's retransmission. Conservative
	// for the TCP-based client-relay hop, where there is no IP fragmentation
	// to account for.
	relayKCPMtu = 1400
	// relayKCPSndWnd bounds this side's segments in flight, so a bulk
	// transfer cannot overflow the relay's bounded per-client send queue.
	// relayKCPRcvWnd is the peer's ceiling on ours: a slow local reader now
	// shrinks the advertised receive window instead of drowning the relay
	// queue — the backpressure the raw byte-stream underlay never had.
	relayKCPSndWnd = 256
	relayKCPRcvWnd = 256
	// relayKCPRecvBuffer bounds the pair's fan-in channel: datagrams the pumps
	// have read from their underlays but KCP has not yet consumed. It matches
	// the receive window, so a pump can stay at most one window ahead of the
	// session without the channel itself becoming the backpressure.
	relayKCPRecvBuffer = 256
)

// directUnderlayIdle is how long a direct underlay may go without delivering an
// inbound datagram before it stops being preferred. It is 2x the smux keepalive
// interval (3s): a healthy but momentarily quiet direct path — an idle smux
// session still exchanges a keepalive every 3s — survives one missed keepalive,
// while a genuinely silent socket is demoted within a keepalive period of the
// second miss. The same bound is the H1 "live direct" predicate (Task 0) and the
// watchdog's fire threshold (Task 4). It is a var so tests can shorten it; the
// production default is 6s.
var directUnderlayIdle = 6 * time.Second

// relayIdleWindow is how long the pair may go without delivering an inbound
// datagram on either underlay before its idle watchdog reports it. It is 2x
// the smux keepalive interval (3s): a healthy session's NOPs cross in both
// directions every 3s, so a pair quiet past this window is not an idle link
// but a dead one. Relay-only quiet is not enough — a session living on
// direct sends nothing over relay — so the fire condition is pair silence
// (the freshest of the two stamps), while silentFor stays relay-measured as
// the evidence. The same bound is Task 2's relayLiveWindow (a separate var
// for the death handler's gate — same default, deliberate). It is a var so
// tests can shorten it; the production default is 6s.
var relayIdleWindow = 6 * time.Second

// relayIdleTick paces the relay idle watchdog: how often it compares
// lastRelayRecv against relayIdleWindow. A var so tests can shorten it; the
// production default is 1s. The tick never enters the read path — it only
// reads the stamp — because kcp-go's readLoop exits permanently on error.
var relayIdleTick = time.Second

// newRelayKCPPair builds the pair-level KCP holder for peer: the KCP session
// lives on the pair (like the pair's secure session — "one per (peer,
// transport), outliving this adapter"), and reads through the holder itself,
// which forwards to whichever adapter is currently registered as the pair's
// endpoint. KCP is the reliability layer between the lossy DERP packet path and
// the crypto record framing: one dropped relay packet used to desync the record
// stream permanently ("bad secure record length"), and now it is one lost
// segment that KCP retransmits — the same stack the direct plane already runs
// (KCP -> cryptoConn(secure) -> smux).
func newRelayKCPPair(e *engine, peer derpclient.PublicKey) *relayKCPPair {
	// No direct underlay is installed yet: a pre-closed directPumpDone keeps
	// ReadFrom's pair-end wait from parking on a pump that was never started.
	noDirect := make(chan struct{})
	close(noDirect)
	p := &relayKCPPair{
		e:              e,
		peer:           peer,
		recv:           make(chan []byte, relayKCPRecvBuffer),
		done:           make(chan struct{}),
		relayPumpDone:  make(chan struct{}),
		directPumpDone: noDirect,
		watchDone:      make(chan struct{}),
		wake:           make(chan struct{}),
		idle:           make(chan struct{}),
		// A fresh pair has no direct underlay, so its path starts on the relay;
		// recording that here makes the first direct install a real flip for the
		// O1/O2 migration history even before a KCP session exists.
		lastPath: "relay",
	}
	// The relay pump runs for the pair's lifetime: it parks until an endpoint
	// is registered, follows the pair across endpoint swaps, and ends only when
	// the pair itself does. It is what lets a second (direct) pump feed the same
	// fan-in in Task 3 without the pair's ReadFrom knowing which path delivered.
	go p.pumpRelay()
	// The relay idle watchdog shares the pair's lifetime: one ticker per pair,
	// ending with it on p.done. It never enters the read path (see
	// relayIdleTick): it only compares the stamp the pump maintains.
	go p.watchRelayIdle()
	return p
}

// signalIdleLocked wakes the retirement waits (see relayKCPStream.Close).
// Caller must hold p.mu.
func (p *relayKCPPair) signalIdleLocked() {
	close(p.idle)
	p.idle = make(chan struct{})
}

// relayKCPPair is one pair's relay KCP state: the KCP session, the adapter
// endpoint it currently reads from, and the single-reader bookkeeping for the
// per-mux-session stream views built on top. It doubles as the net.PacketConn
// the KCP session captures (ownConn=false, so closing KCP never closes it —
// the engine's pair store owns the lifecycle).
type relayKCPPair struct {
	e    *engine
	peer derpclient.PublicKey

	// claimMu serializes stream claims: each newStream retires its predecessor
	// before installing itself, so builds racing from different adapter
	// generations cannot both read the pair's stream.
	claimMu sync.Mutex
	mu      sync.Mutex
	sess    *kcp.UDPSession  // the pair's KCP session; built on first use
	ep      *relayPacketConn // the current registered adapter endpoint
	stream  *relayKCPStream  // the stream view the live mux session reads
	pending []byte           // bytes a retired view read but could not deliver
	closed  bool
	wake    chan struct{} // closed and replaced on every endpoint/end change
	idle    chan struct{} // closed and replaced on every read/write completion
	// recv is the pair's fan-in: the relay pump and the direct pump hand it
	// datagrams, and the pair's ReadFrom serves KCP from it. done is closed
	// exactly once by shutdown; both pumps select on it so neither can outlive
	// the pair. relayPumpDone and directPumpDone are closed by their pumps when
	// they exit, after draining their final datagrams into recv; ReadFrom waits
	// on both at pair end so a datagram either pump already read is delivered,
	// not dropped. directPumpDone starts closed (no underlay yet) and is replaced
	// on every setDirectUnderlay.
	recv           chan []byte
	done           chan struct{}
	relayPumpDone  chan struct{}
	directPumpDone chan struct{}
	// watchDone is closed by watchRelayIdle on exit; shutdown joins it, so a
	// pair's teardown never returns while its ticker can still read the
	// window/tick vars or dispatch a strike.
	watchDone chan struct{}

	// direct is the pair's installed direct (raw UDP) underlay, nil when none is
	// registered. directStop ends that underlay's pump; the pump closes
	// directPumpDone as it exits. lastDirectRecv is when the direct pump last
	// delivered an inbound datagram; preferredDirect compares its age against
	// directUnderlayIdle. All guarded by mu.
	direct         *directUnderlay
	directStop     chan struct{}
	lastDirectRecv time.Time

	// onDirectIdle, when set by the engine (Task 7), is invoked once per idle
	// episode when the direct pump observes the underlay silent past
	// directUnderlayIdle. It is read under mu and called outside it, from its own
	// goroutine, so the engine's retirement (clearDirectUnderlay) can never join
	// the pump that reported the idle. Guarded by mu.
	onDirectIdle func(*directUnderlay)

	// directIdleFiring bounds the callback dispatch to at most one in-flight
	// invocation: a new episode's callback is suppressed while the previous one
	// is still running, so a slow or blocking engine callback cannot accumulate
	// one goroutine per re-armed episode. It is atomic, not under mu, because it
	// is set and cleared on the dispatch path (the pump and the callback
	// goroutine) and must never be held across the callback itself.
	directIdleFiring atomic.Bool

	// onDirectInbound, when set by the engine, is invoked when the direct pump
	// delivers a datagram while the pair has no live mux consumer (p.stream ==
	// nil). A relay loss with a live direct path keeps the pair's KCP epoch and
	// settled keys but closes the per-build mux session on both ends; the
	// dialing side rebuilds on its next open, while the accepting side has no
	// relay pump to rebuild from — an inbound direct datagram is the only
	// signal that a peer wants a new stream. Read under mu and called outside
	// it, from its own goroutine, so the pump never blocks on the rebuild.
	// Guarded by mu.
	onDirectInbound func()

	// directInboundFiring bounds the onDirectInbound dispatch to at most one
	// in-flight invocation, exactly like directIdleFiring, so a burst of direct
	// datagrams cannot accumulate one rebuild goroutine per datagram.
	directInboundFiring atomic.Bool

	// appliedPath is the path whose KCP tuning is currently on p.sess ("direct"
	// or "relay"), "" before any session has been tuned. appliedNC is the
	// congestion-control flag last passed to SetNoDelay. Together they make the
	// tuning idempotent — applyPathTuningLocked only calls SetNoDelay when the
	// path changed — and appliedNC is the deterministic seam the Task 14 test
	// reads. Guarded by mu.
	appliedPath string
	appliedNC   int

	// pathChanges counts preferred-path flips over the pair's lifetime: the
	// cheap per-pair fallback for O6's stream-level "stream path-changed" log.
	// It is bumped at the one place a flip is detected (applyPathTuningLocked,
	// where the tuning actually changes), so it counts pair flips, not per-stream
	// observations. A stream that never did I/O across a flip still leaves its
	// mark here; a reader with logs can count the same event there instead.
	pathChanges atomic.Uint64

	// bytesSent/bytesRcvd count the pair's datagrams in bytes, on the paths the
	// pair already walks: bytesSent in WriteTo (whichever path it picks), and
	// bytesRcvd where a pump drains an underlay (readRelay for the relay pump,
	// pumpDirect for the direct pump). They are this pair's own counters —
	// deliberately NOT kcp-go's process-global DefaultSnmp, which aggregates
	// every KCP session including the direct plane. Atomic rather than under
	// p.mu: these sit on the pair's data path, and a status read must never
	// contend with it. The increment is one lock-free Add per datagram,
	// negligible next to the channel send/receive already on those paths.
	bytesSent atomic.Uint64
	bytesRcvd atomic.Uint64

	// Per-underlay byte counters (O3): the same datagram totals partitioned by
	// the underlay they rode. relay* in WriteTo's relay branch and readRelay;
	// direct* in WriteTo's direct branch and pumpDirect. Atomic for the same
	// reason as the totals.
	relayBytesSent  atomic.Uint64
	relayBytesRcvd  atomic.Uint64
	directBytesSent atomic.Uint64
	directBytesRcvd atomic.Uint64

	// lastRelayRecv is when the relay pump last delivered an inbound datagram —
	// the relay half of the per-underlay recency (O3), the counterpart of
	// lastDirectRecv. Guarded by mu.
	lastRelayRecv time.Time

	// relayIdleFired is the relay watchdog's episode latch, relayStrikes its
	// strike count: the pumpDirect idleFired pattern for the relay underlay.
	// A silence past relayIdleWindow fires once per episode (latch set,
	// strikes++ capped at 2); an inbound relay datagram closes the episode
	// (both cleared at readRelay's stamp site); a rebuild re-arms the latch
	// for the new session while the strikes carry (the episode continues).
	// Guarded by mu.
	relayIdleFired bool
	relayStrikes   int

	// lastPath is the last preferred path recorded for events/counters (O1/O2),
	// distinct from appliedPath, which is only the KCP tuning state and stays ""
	// until a session exists. It starts at "relay" (a fresh pair has no direct
	// underlay) so the first direct install is a relay→direct migration even
	// before the session is built. Guarded by mu.
	lastPath string
	// lastFallbackReason is the reason of the most recent direct→relay flip
	// (O4), a finite enum; empty until one happens. Guarded by mu.
	lastFallbackReason string
	// pathTrace is the bounded ring of recent path-change lines (O5), oldest
	// first, capped like directConn.trace. Allocated once, reused; guards by mu.
	pathTraceRing [punchTraceCap]string
	pathTracePos  int
	pathTraceN    int

	// Pair migration counters (O2), atomic because Status reads them without
	// p.mu on a path that must not contend with the data plane.
	migrations          atomic.Uint64 // relay->direct flips
	fallbacks           atomic.Uint64 // direct->relay flips
	directIdleEvictions atomic.Uint64 // the idle subset of fallbacks
	repunchAfterIdle    atomic.Uint64 // idle evictions that scheduled a re-punch
	seedFailures        atomic.Uint64 // failed seed handshakes
	relayLossSuppressed atomic.Uint64 // relay losses kept from resetting by a live direct
}

// relayKCPSnapshot is a point-in-time read of the pair's KCP session stats and
// datagram counters. present reports whether a KCP session actually exists, so
// a caller can tell "no session" from "a session with nothing measured yet".
type relayKCPSnapshot struct {
	conv      uint32
	srtt      int32
	rto       uint32
	rttVar    int32
	bytesSent uint64
	bytesRcvd uint64
	present   bool

	// Per-underlay attribution (O3): path is the current preferred path
	// ("direct"/"relay"), directAlive is preferredDirect, and the relay*/direct*
	// fields partition the datagram totals and recency by underlay.
	path            string
	directAlive     bool
	relayBytesSent  uint64
	relayBytesRcvd  uint64
	directBytesSent uint64
	directBytesRcvd uint64
	relayLastRecv   time.Time
	directLastRecv  time.Time
}

// session returns the pair's KCP session, building it on first use. The conv is
// the pair's (see relayConv), so both ends converge on one session without a
// handshake, and a rebuild keeps the same conv while the pair survives.
func (p *relayKCPPair) session() (*kcp.UDPSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sess != nil {
		return p.sess, nil
	}
	if p.closed {
		return nil, io.ErrClosedPipe
	}
	sess, err := kcp.NewConn4(relayConv(p.e.pub, p.peer), dummyAddr{}, nil, 0, 0, false, p)
	if err != nil {
		return nil, err
	}
	// nodelay=1 (on), 10ms interval, fast retransmit on the 2nd duplicate ACK.
	// Congestion control is per preferred path (see applyPathTuningLocked): off
	// (nc=1) on the relay, where a drop is a bounded-queue overflow rather than
	// a congestion signal, and on (nc=0) on the direct path, which rides the
	// public Internet and can genuinely congest.
	path := p.pathNameLocked()
	nc := pathNC(path)
	sess.SetNoDelay(1, 10, 2, nc)
	sess.SetMtu(relayKCPMtu)
	sess.SetWindowSize(relayKCPSndWnd, relayKCPRcvWnd)
	p.sess = sess
	p.appliedPath = path
	p.appliedNC = nc
	return sess, nil
}

// register installs pc as the pair's current endpoint: its inbound queue is
// what the pair's KCP session reads from now on, and its Write sends the
// segments. Registering the adapter that is already current is a no-op — a
// rebuild on the same adapter must not kick its own reader. The endpoint swap
// is what lets the pair's KCP session survive an adapter kill: the session's
// epoch continues while the queue it reads from is replaced underneath it.
func (p *relayKCPPair) register(pc *peerConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || (p.ep != nil && p.ep.pc == pc) {
		return
	}
	close(p.wake)
	p.wake = make(chan struct{})
	ep := newRelayPacketConn(pc)
	// The kick fires on the next endpoint change or on the pair's end, ending
	// a read parked on this adapter's queue (see relayPacketConn.ReadFrom).
	ep.kick = p.wake
	p.ep = ep
}

// newStream claims a fresh per-mux-session view of the pair's KCP stream,
// retiring whatever view the previous mux session held first. The view is what
// secure.conn wraps: it dies with the mux session built on it (smux closes its
// underlay), so a rebuilt mux session never reads alongside its predecessor,
// while the pair's KCP session below keeps streaming. The retirement is
// synchronous and serialized (claimMu): by the time this returns, the previous
// view's reader and writer are out of the KCP session and any bytes the reader
// had drawn are queued in pending for this one.
func (p *relayKCPPair) newStream() *relayKCPStream {
	p.claimMu.Lock()
	defer p.claimMu.Unlock()
	p.mu.Lock()
	old := p.stream
	p.mu.Unlock()
	if old != nil {
		old.Close()
	}
	s := &relayKCPStream{pair: p}
	p.mu.Lock()
	p.stream = s
	p.mu.Unlock()
	return s
}

// shutdown ends the pair: no endpoint is served again, the pumps stop, and the
// KCP session closes. A reader parked on the proxy wakes with io.EOF (the
// endpoint's kick fires with the wake channel), so the session's read loop
// cannot leak. done is closed exactly once, guarded by closed: a double close
// would panic.
func (p *relayKCPPair) shutdown() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	close(p.wake)
	close(p.done)
	sess := p.sess
	p.mu.Unlock()
	// Stop the direct pump and close its socket, or a read parked in readFrom
	// would not observe p.done for up to directUnderlayReadTimeout. Idempotent,
	// and safe here: p.mu is released.
	p.clearDirectUnderlay()
	if sess != nil {
		sess.Close()
	}
	// Join the watchdog: done is closed above, so it is already exiting;
	// waiting keeps a torn-down pair from firing a strike (or reading the
	// window vars) after its owner moved on. Never nested — the watchdog
	// dispatches strikes onto other goroutines and never calls shutdown.
	if p.watchDone != nil {
		<-p.watchDone
	}
}

// snapshot returns the pair's KCP session stats and its datagram counters. The
// session pointer is captured under p.mu and the getters are called after p.mu
// is released: GetSRTT/GetRTO/GetSRTTVar take the KCP session's own lock
// (s.mu), and the only lock order in this file is p.mu -> s.mu (session()
// holds p.mu while SetMtu/SetWindowSize/SetNoDelay take s.mu). KCP never takes
// p.mu while holding s.mu — its readLoop/postProcess call into the pair without
// s.mu, and update() holds s.mu only to do a non-blocking channel send — so
// this read follows the one established order and cannot invert. GetConv takes
// no lock; the getters read only integer fields, so a session being torn down
// concurrently still yields a well-defined (last observed) value.
func (p *relayKCPPair) snapshot() relayKCPSnapshot {
	p.mu.Lock()
	sess := p.sess
	s := relayKCPSnapshot{
		bytesSent:       p.bytesSent.Load(),
		bytesRcvd:       p.bytesRcvd.Load(),
		relayBytesSent:  p.relayBytesSent.Load(),
		relayBytesRcvd:  p.relayBytesRcvd.Load(),
		directBytesSent: p.directBytesSent.Load(),
		directBytesRcvd: p.directBytesRcvd.Load(),
		path:            p.pathNameLocked(),
		directAlive:     p.preferredDirectLocked(),
		relayLastRecv:   p.lastRelayRecv,
		directLastRecv:  p.lastDirectRecv,
	}
	p.mu.Unlock()
	if sess == nil {
		return s
	}
	s.conv = sess.GetConv()
	s.srtt = sess.GetSRTT()
	s.rto = sess.GetRTO()
	s.rttVar = sess.GetSRTTVar()
	s.present = true
	return s
}

// freshestRecv returns the later of the two underlays' last inbound datagram,
// and whether either has ever been stamped. Reading the MERGED recency is what
// makes this honest on both underlays: a peer that migrated to the direct path
// keeps the relay's stamp aging, so the relay-only read calls a live peer
// silent.
//
// There is deliberately no `present` gate here, unlike snapshot(). A zero
// KCP-stat set would read as "healthy idle session" (that is what present guards
// in relayKCPSnapshotAttrs), but here the consumer is asking how long the peer
// has been quiet, and the answers that matter are exactly the ones taken when
// the session is already gone: a kill that resets the pair's KCP epoch retires
// the session, and the recency is what explains the death.
func (p *relayKCPPair) freshestRecv() (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// lastRelayRecv/lastDirectRecv are stamped under p.mu, so this read is
	// race-free under -race.
	switch {
	case p.lastDirectRecv.After(p.lastRelayRecv):
		return p.lastDirectRecv, !p.lastDirectRecv.IsZero()
	case p.lastRelayRecv.After(p.lastDirectRecv):
		return p.lastRelayRecv, true
	default:
		// Equal: either both zero, or the two stamps coincide. Only the zero
		// case has nothing to report.
		return p.lastRelayRecv, !p.lastRelayRecv.IsZero()
	}
}

// relayKCPSnapshotAttrs renders a pair's KCP snapshot as stable slog attrs, or
// nil when there is no session (present=false). The configured MTU/window are
// included so a log reader can compare configured against observed SRTT/RTO;
// the names are stable and greppable.
func relayKCPSnapshotAttrs(s relayKCPSnapshot) []any {
	if !s.present {
		return nil
	}
	return []any{
		"kcpConv", s.conv,
		"kcpSrtt", s.srtt,
		"kcpRto", s.rto,
		"kcpRttVar", s.rttVar,
		"kcpMtu", relayKCPMtu,
		"kcpSndWnd", relayKCPSndWnd,
		"kcpRcvWnd", relayKCPRcvWnd,
		"kcpBytesSent", s.bytesSent,
		"kcpBytesRcvd", s.bytesRcvd,
	}
}

// readRelay serves one datagram from the current registered adapter to the
// pair's relay pump. Each endpoint degrades per relayPacketConn's
// drain-once-then-EOF contract; the forwarding adds the swap awareness the pair
// needs on top:
//
//   - no endpoint registered (nothing built yet, or the previous one is gone and
//     the replacement has not built): wait for one. Surfacing io.EOF across the
//     gap would end the KCP session's read loop for good — kcp-go exits the
//     reader on ANY read error — so io.EOF is reserved for the pair's own end.
//   - the pair is closing: the final endpoint is still drained to its end (its
//     queued datagrams are delivered first, the same contract the endpoint
//     itself follows) and only then does the pair report io.EOF.
func (p *relayKCPPair) readRelay(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		ep, wake, closed := p.ep, p.wake, p.closed
		p.mu.Unlock()
		if ep == nil {
			if closed {
				return 0, nil, io.EOF
			}
			<-wake
			continue
		}
		n, addr, err := ep.ReadFrom(b)
		if err == nil {
			p.bytesRcvd.Add(uint64(n))
			p.relayBytesRcvd.Add(uint64(n))
			p.mu.Lock()
			p.lastRelayRecv = time.Now()
			// Inbound traffic closes the idle episode: the next silence
			// starts over at strike 1, not at an escalation.
			p.relayIdleFired = false
			p.relayStrikes = 0
			p.mu.Unlock()
			return n, addr, nil
		}
		// io.EOF: this endpoint is gone and drained (its closeCh or the kick
		// fired, and both degrade only once the queue is empty).
		p.mu.Lock()
		if p.ep == ep {
			p.ep = nil
		}
		p.mu.Unlock()
		if closed {
			return 0, nil, io.EOF
		}
	}
}

// pumpRelay is the relay half of the pair's fan-in: it loops readRelay and
// copies every datagram onto p.recv for KCP. It runs for the pair's lifetime
// and exits only on readRelay's io.EOF (the pair ended). A datagram is copied
// out of the scratch buffer before being queued — the next read reuses it — and
// the send is preferred over p.done so a shutdown never discards a datagram the
// endpoint already drained; done is consulted only when recv is full, where the
// pump must not outlive the pair waiting for a consumer that is gone.
func (p *relayKCPPair) pumpRelay() {
	defer close(p.relayPumpDone)
	buf := make([]byte, relayKCPMtu)
	for {
		n, _, err := p.readRelay(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case p.recv <- pkt:
		default:
			select {
			case p.recv <- pkt:
			case <-p.done:
				return
			}
		}
	}
}

// reportRelayIdle is the relay idle watchdog's decision: when the PAIR has
// been silent past relayIdleWindow it opens (or continues) an episode and
// returns its strike (1, escalating to 2 while the silence continues across
// rebuilds) with the relay-measured silence. The fire condition is pair
// silence — either underlay carrying resets it — not relay silence: a
// session living on direct sends nothing over the relay underlay, and
// treating that quiet as an outage would kill every stable direct session's
// mux once per window. (0, 0) means no action: either the pair is carrying,
// or this episode already fired (the latch, same as pumpDirect's idleFired).
// A rebuild re-arms the latch for the new session (see rearmRelayIdle) while
// the strikes carry, so a silence that survives a rebuild escalates; traffic
// on either path clears both at its stamp site, ending the episode.
func (p *relayKCPPair) reportRelayIdle() (strike int, silentFor time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Pair silence, not relay silence: the freshest of the two underlays is
	// what says the link is carrying. silentFor below stays relay-measured
	// — it is the evidence, not the decision.
	fresh := p.lastRelayRecv
	if p.lastDirectRecv.After(fresh) {
		fresh = p.lastDirectRecv
	}
	if time.Since(fresh) < relayIdleWindow {
		return 0, 0
	}
	silentFor = time.Since(p.lastRelayRecv)
	if p.lastRelayRecv.IsZero() {
		// No relay datagram ever observed (a session raised on direct, or a
		// virgin pair): "since the zero time" is uptime-shaped noise, not a
		// measurement. Zero reads as "cannot say", matching silentFor=0's
		// standing meaning elsewhere.
		silentFor = 0
	}
	if p.relayIdleFired {
		return 0, 0
	}
	p.relayIdleFired = true
	if p.relayStrikes < 2 {
		p.relayStrikes++
	}
	return p.relayStrikes, silentFor
}

// rearmRelayIdle re-arms the watchdog's latch after a (re)build, for the new
// session. The strikes carry: a silence that continues past a rebuild is the
// episode continuing, and the next over-window report escalates. Called from
// sessionLocked, which holds pc.mu; the only lock order here is pc.mu -> p.mu
// (pair.register already runs under pc.mu in sessionLocked), so taking p.mu
// cannot invert.
func (p *relayKCPPair) rearmRelayIdle() {
	p.mu.Lock()
	p.relayIdleFired = false
	p.mu.Unlock()
}

// watchRelayIdle is the pair's relay-side silence ticker: every relayIdleTick
// it asks reportRelayIdle, and a strike is handed to the engine — on its own
// goroutine, outside p.mu — which decides (kill mux only, or kill the pair).
// It ends with the pair on p.done, like both pumps.
func (p *relayKCPPair) watchRelayIdle() {
	defer close(p.watchDone)
	ticker := time.NewTicker(relayIdleTick)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			strike, silentFor := p.reportRelayIdle()
			if strike == 0 {
				continue
			}
			if p.e == nil {
				continue
			}
			peer := p.peer
			go p.e.relayPathSilent(peer, p, strike, silentFor)
		}
	}
}

// setDirectUnderlay installs u as the pair's direct underlay: any previous
// underlay is retired (its pump stopped and its socket closed), a pump for u is
// started on the pair's fan-in, and lastDirectRecv is seeded to now so the new
// path is preferred immediately — a freshly punched direct socket is by
// definition live. Installing after the pair has closed closes u instead, so the
// caller's socket cannot leak. The lock is released before the old underlay is
// retired, so starting the replacement cannot block on the old pump.
func (p *relayKCPPair) setDirectUnderlay(u *directUnderlay) {
	if u == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		u.close()
		return
	}
	old, oldStop := p.direct, p.directStop
	stop := make(chan struct{})
	done := make(chan struct{})
	p.direct = u
	p.directStop = stop
	p.directPumpDone = done
	p.lastDirectRecv = time.Now()
	// A freshly installed direct path is preferred immediately, so the
	// session's congestion control must follow it there.
	ev := p.applyPathTuningLocked(pathChangeFirstDirect)
	p.mu.Unlock()

	p.logPathChange(ev)
	p.logUnderlayInstalled(u)
	if old != nil {
		close(oldStop)
		old.close()
		p.logUnderlayRetired(old, underlayReplaced)
	}
	go func() {
		defer close(done)
		p.pumpDirect(u, stop)
	}()
}

// clearDirectUnderlay stops the pair's direct pump and closes its socket exactly
// once. It is idempotent: a second call finds no underlay and returns. p.mu is
// released before stop is closed and u.close() runs, so a caller that reached
// here from inside the pump (an idle callback) cannot self-deadlock.
func (p *relayKCPPair) clearDirectUnderlay() { p.clearDirectUnderlayIf(nil, pathChangeClear) }

// clearDirectUnderlayIf clears the pair's direct underlay only while it is
// still want (want == nil means whatever is installed), testing and clearing in
// one critical section. It reports whether it cleared one. This is the
// compare-and-clear the idle watchdog needs: a plain check-then-clear races a
// re-punch that replaces the underlay between the check and the clear, and would
// retire the replacement — the new, good path (C1). An idle clear (reason
// pathChangeDirectIdle) additionally requires the underlay to be stale *at the
// moment of the clear*: the watchdog dispatches its callback from a goroutine,
// so a datagram can arrive after it observed silence and re-arm the path
// (reportDirectIdle/pumpDirect) before the callback runs — without the re-check
// that fresh datagram's clear would retire a healthy, just-recovered underlay.
// p.mu is released before stop is closed and u.close() runs, so a caller reached
// from inside the pump cannot self-deadlock. reason is the finite path-change
// enum the flip is attributed to; it also picks the underlay's own retire reason
// (idle vs replaced).
func (p *relayKCPPair) clearDirectUnderlayIf(want *directUnderlay, reason string) bool {
	p.mu.Lock()
	u, stop := p.direct, p.directStop
	if want != nil && u != want {
		p.mu.Unlock()
		return false
	}
	if reason == pathChangeDirectIdle && time.Since(p.lastDirectRecv) < directUnderlayIdle {
		// A datagram re-armed the path since the watchdog observed silence:
		// not ours to retire.
		p.mu.Unlock()
		return false
	}
	p.direct = nil
	p.directStop = nil
	// No underlay is preferred any more: fall the session's congestion control
	// back to the relay.
	ev := p.applyPathTuningLocked(reason)
	p.mu.Unlock()
	if u == nil {
		return false
	}
	p.logPathChange(ev)
	p.logUnderlayRetired(u, underlayRetireReason(reason))
	close(stop)
	u.close()
	return true
}

// underlayRetireReason maps a path-change reason to the finite
// event=direct-underlay reason set (punch/idle/replaced): an idle fallback
// retires the underlay as "idle", anything else (an engine clear or a
// replacement) as "replaced".
func underlayRetireReason(pathReason string) string {
	if pathReason == pathChangeDirectIdle {
		return underlayIdle
	}
	return underlayReplaced
}

// pumpDirect is the direct half of the pair's fan-in: it loops u.readFrom,
// stamps lastDirectRecv on every delivered datagram, and copies the datagram
// onto p.recv for KCP. stop is the underlay's own stop channel, closed when the
// pair retires or replaces it; p.done ends the pair. It exits on readFrom's
// error (u.close() makes readFrom return io.EOF) or on stop/done while pushing.
// Like pumpRelay, a datagram already drained is preferred over stop/done on the
// fast path, and done is consulted only when recv is full, where the pump must
// not outlive the pair waiting for a consumer that is gone.
//
// readFrom surfaces a silent socket as os.ErrDeadlineExceeded on its
// directUnderlayReadTimeout deadline (it is otherwise parked in the kernel and
// could never notice silence). This pump reads that tick as the idle watchdog:
// once the underlay has been silent past directUnderlayIdle it reports it to the
// engine through onDirectIdle, once per idle episode, and a fresh datagram
// re-arms it. The pump never clears the underlay itself — the engine decides.
func (p *relayKCPPair) pumpDirect(u *directUnderlay, stop <-chan struct{}) {
	buf := make([]byte, relayKCPMtu)
	// idleFired is the episode latch: set when the watchdog reports this
	// underlay silent, cleared the moment a datagram arrives, so each
	// uninterrupted silence fires onDirectIdle exactly once. It lives on the
	// pump's own goroutine and needs no lock.
	idleFired := false
	for {
		n, err := u.readFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// Silence tick: on the first silent tick of an episode, hand
				// the underlay to the engine outside p.mu. A tick with a
				// callback already in flight reports false and is retried on
				// the next tick, so dispatch stays bounded.
				if !idleFired && p.reportDirectIdle(u) {
					idleFired = true
				}
				continue
			}
			return
		}
		if n <= 0 {
			continue
		}
		// Per-path mute (Task 12 / O7): an inbound direct datagram is swallowed
		// before it re-arms the watchdog or re-seeds the recency, so a direct
		// path that is still receiving traffic (KCP's own keepalives and ACKs)
		// reads as silent and is retired — while the relay stays alive.
		if p.e != nil && p.e.faults.Load().muteDirect() {
			continue
		}
		// A datagram re-arms the watchdog, re-seeds the recency stamp, and
		// re-elects the direct path — so the session's congestion control
		// follows it back to direct.
		idleFired = false
		p.bytesRcvd.Add(uint64(n))
		p.directBytesRcvd.Add(uint64(n))
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		p.mu.Lock()
		var ev *pathChangeEvent
		needConsumer := false
		if p.direct == u {
			p.lastDirectRecv = time.Now()
			// Inbound direct traffic closes the idle episode like relay
			// traffic does (see readRelay): without this a path that flaps
			// direct-up then down again would never escalate, the latch
			// held from the first silence forever.
			p.relayIdleFired = false
			p.relayStrikes = 0
			ev = p.applyPathTuningLocked(pathChangeFirstDirect)
			// No live mux view: a suppressed relay loss closed the mux session
			// on top of this pair, and only inbound traffic tells the accepting
			// side a peer wants a new stream. Ask the engine to rebuild it.
			needConsumer = p.stream == nil && !p.closed
		}
		p.mu.Unlock()
		p.logPathChange(ev)
		if needConsumer {
			p.reportDirectInbound()
		}
		select {
		case p.recv <- pkt:
		default:
			select {
			case p.recv <- pkt:
			case <-p.done:
				return
			case <-stop:
				return
			}
		}
	}
}

// reportDirectIdle hands a silent direct underlay to the engine's callback (Task
// 7), if one is set, and reports whether a callback was dispatched. It performs
// every eligibility check in one critical section — u is still the installed
// underlay, the pair is not closing, and the underlay has been silent past
// directUnderlayIdle — so a retirement racing the tick cannot fire for an
// underlay the pair no longer holds (Minor #3/#6).
//
// The dispatch is bounded to at most one in-flight callback (directIdleFiring):
// a new episode's callback is suppressed while the previous one is still
// running, so a slow or blocking engine callback cannot accumulate goroutines
// across re-armed episodes. The callback runs in its own goroutine, outside
// p.mu, so the pump that observed the idle never blocks on it and the engine's
// retirement (clearDirectUnderlay) can never join that pump (H4).
//
// Observing staleness is also a preferred-path flip (direct -> relay), so the
// session's congestion control is re-tuned in the same critical section. That
// happens whether or not a callback is dispatched: a suppressed dispatch (an
// in-flight callback) must not leave the session tuned for a path it is no
// longer using.
func (p *relayKCPPair) reportDirectIdle(u *directUnderlay) bool {
	p.mu.Lock()
	ok := p.direct == u && !p.closed && time.Since(p.lastDirectRecv) >= directUnderlayIdle
	var ev *pathChangeEvent
	if ok {
		ev = p.applyPathTuningLocked(pathChangeDirectIdle)
	}
	cb := p.onDirectIdle
	p.mu.Unlock()
	p.logPathChange(ev)
	if !ok || cb == nil {
		return false
	}
	if !p.directIdleFiring.CompareAndSwap(false, true) {
		// A callback is still in flight: suppress this episode's dispatch.
		return false
	}
	go func() {
		defer p.directIdleFiring.Store(false)
		cb(u)
	}()
	return true
}

// reportDirectInbound hands a "direct datagram arrived with no live mux
// consumer" event to the engine's onDirectInbound callback, if one is set, and
// reports whether a callback was dispatched. The engine rebuilds the peer's mux
// session so an inbound stream can be accepted over the surviving pair (a
// suppressed relay loss closes the mux on both ends; the accepting side has no
// relay pump to rebuild from). The dispatch is bounded to one in-flight
// callback (directInboundFiring), like reportDirectIdle, so a burst of
// datagrams cannot accumulate goroutines. It runs in its own goroutine, outside
// p.mu, so the pump never blocks on the rebuild.
func (p *relayKCPPair) reportDirectInbound() bool {
	p.mu.Lock()
	cb := p.onDirectInbound
	closed := p.closed
	p.mu.Unlock()
	if cb == nil || closed {
		return false
	}
	if !p.directInboundFiring.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer p.directInboundFiring.Store(false)
		cb()
	}()
	return true
}

// preferredDirect reports whether the direct underlay is the path WriteTo should
// use: an underlay is installed and it delivered an inbound datagram within
// directUnderlayIdle. A direct that has gone silent past that bound is no longer
// preferred, so writes fall back to the relay even before the watchdog retires
// the socket (Task 4). This is also the H1 "live direct" predicate (Task 0).
func (p *relayKCPPair) preferredDirect() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.preferredDirectLocked()
}

// preferredDirectLocked is preferredDirect for callers already holding p.mu.
func (p *relayKCPPair) preferredDirectLocked() bool {
	return p.direct != nil && time.Since(p.lastDirectRecv) < directUnderlayIdle
}

// pathName names the pair's current preferred path for stats and diagnostics:
// "direct" while preferredDirect, else "relay".
func (p *relayKCPPair) pathName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pathNameLocked()
}

// pathNameLocked is pathName for callers already holding p.mu.
func (p *relayKCPPair) pathNameLocked() string {
	if p.preferredDirectLocked() {
		return "direct"
	}
	return "relay"
}

// pathNC returns the KCP SetNoDelay congestion-control flag for path: 0
// (control on) on the public direct path, 1 (control off) on the relay, whose
// loss is bounded-queue overflow rather than congestion.
func pathNC(path string) int {
	if path == "direct" {
		return 0
	}
	return 1
}

// Path-change reasons (O1): a closed enum, never free text, so a reader can
// group flips by reason without parsing prose. relay-lost and relay-restored are
// part of the enum the design fixes and are reserved here, but the pair's
// preference is driven by direct recency alone — a relay endpoint swap never
// flips it (the event's relayAlive attr carries that state instead), so only the
// three below are emitted today.
const (
	// pathChangeFirstDirect is a relay->direct flip: a direct underlay was
	// installed, or a datagram re-elected one after a silence.
	pathChangeFirstDirect = "first-direct-datagram"
	// pathChangeDirectIdle is a direct->relay flip: the watchdog saw the direct
	// underlay silent past directUnderlayIdle.
	pathChangeDirectIdle = "direct-idle"
	// pathChangeClear is a direct->relay flip: the underlay was retired.
	pathChangeClear = "clear"
	// pathChangeRelayLost / pathChangeRelayRestored are reserved by the O1 enum
	// (see the note above); not emitted by the pair today.
	pathChangeRelayLost     = "relay-lost"
	pathChangeRelayRestored = "relay-restored"
)

// Direct-underlay event reasons (O1), a closed enum for event=direct-underlay.
const (
	underlayPunch    = "punch"
	underlayIdle     = "idle"
	underlayReplaced = "replaced"
	underlayClear    = "clear"
)

// pathChangeEvent is one detected preferred-path flip, handed back from
// applyPathTuningLocked so the caller can log it after releasing p.mu. The
// counters are the post-bump values, so one log line carries the pair's whole
// migration history.
type pathChangeEvent struct {
	from, to      string
	reason        string
	directRecvAge time.Duration
	relayAlive    bool
	nc            int
	migrations    uint64
	fallbacks     uint64
}

// line renders the event as a PathTrace line (O5) and the log message suffix:
// "relay->direct first-direct-datagram".
func (e pathChangeEvent) line() string {
	return e.from + "->" + e.to + " " + e.reason
}

// applyPathTuningLocked records a preferred-path flip (O1/O2/O5) and keeps the
// pair's KCP session's congestion control in step with the path: nc=0 (control
// on) on direct, nc=1 (off) on relay. SetMtu and SetWindowSize are per-session
// and deliberately stay put — only the per-path flag moves.
//
// Flip detection is independent of the session: it compares the current path
// against lastPath, which starts "relay", so an install before a session exists
// still counts and logs. Tuning happens only when a session is live (a nil
// session is skipped because session() applies the current path when it builds
// one), and stays idempotent through appliedPath, so a per-datagram call costs
// nothing. reason is the finite enum above; the returned event is nil when the
// path did not change. It is called wherever the preferred path can flip
// (session creation, direct-underlay install and clear, a datagram re-electing
// direct, and the idle watchdog observing direct go stale).
//
// Caller must hold p.mu. The only lock order in this file is p.mu -> s.mu
// (session() already holds p.mu across SetNoDelay), so taking s.mu here cannot
// invert.
func (p *relayKCPPair) applyPathTuningLocked(reason string) *pathChangeEvent {
	path := p.pathNameLocked()
	var ev *pathChangeEvent
	if path != p.lastPath {
		from := p.lastPath
		p.lastPath = path
		if path == "direct" {
			p.migrations.Add(1)
		} else {
			p.fallbacks.Add(1)
			if reason == pathChangeDirectIdle {
				p.directIdleEvictions.Add(1)
			}
			p.lastFallbackReason = reason
		}
		// O6's per-pair flip counter, bumped at the one place a flip is
		// detected: a stream that never did I/O across a flip still leaves its
		// mark here.
		p.pathChanges.Add(1)
		ev = &pathChangeEvent{
			from:       from,
			to:         path,
			reason:     reason,
			relayAlive: p.ep != nil,
			nc:         pathNC(path),
			migrations: p.migrations.Load(),
			fallbacks:  p.fallbacks.Load(),
		}
		if !p.lastDirectRecv.IsZero() {
			ev.directRecvAge = time.Since(p.lastDirectRecv)
		}
		p.notePathTraceLocked(ev)
	}
	if sess := p.sess; sess != nil {
		if nc := pathNC(path); path != p.appliedPath {
			sess.SetNoDelay(1, 10, 2, nc)
			p.appliedPath = path
			p.appliedNC = nc
		}
	}
	return ev
}

// notePathTraceLocked appends one line to the pair's path-change ring (O5),
// dropping the oldest once full. Caller must hold p.mu.
func (p *relayKCPPair) notePathTraceLocked(ev *pathChangeEvent) {
	p.pathTraceRing[p.pathTracePos] = ev.line()
	p.pathTracePos = (p.pathTracePos + 1) % punchTraceCap
	if p.pathTraceN < punchTraceCap {
		p.pathTraceN++
	}
}

// pathTraceLines returns the pair's path-change trace oldest-first, as a copy so
// a caller (a status builder) never aliases the ring.
func (p *relayKCPPair) pathTraceLines() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pathTraceN == 0 {
		return nil
	}
	out := make([]string, p.pathTraceN)
	start := (p.pathTracePos - p.pathTraceN + punchTraceCap) % punchTraceCap
	for i := range out {
		out[i] = p.pathTraceRing[(start+i)%punchTraceCap]
	}
	return out
}

// pairDiag is the pair's O2/O4 snapshot: the migration counters, the last
// fallback reason, and the path-change trace. It is read without p.mu for the
// counters (atomics) and with it only for the reason/trace.
type pairDiag struct {
	fallbackReason      string
	migrations          uint64
	fallbacks           uint64
	directIdleEvictions uint64
	repunchAfterIdle    uint64
	seedFailures        uint64
	relayLossSuppressed uint64
	pathTrace           []string
}

// diag returns the pair's O2/O4/O5 diagnostic view for PeerDiagnostic/Status.
func (p *relayKCPPair) diag() pairDiag {
	p.mu.Lock()
	reason := p.lastFallbackReason
	p.mu.Unlock()
	return pairDiag{
		fallbackReason:      reason,
		migrations:          p.migrations.Load(),
		fallbacks:           p.fallbacks.Load(),
		directIdleEvictions: p.directIdleEvictions.Load(),
		repunchAfterIdle:    p.repunchAfterIdle.Load(),
		seedFailures:        p.seedFailures.Load(),
		relayLossSuppressed: p.relayLossSuppressed.Load(),
		pathTrace:           p.pathTraceLines(),
	}
}

// logPathChange emits the O1 path-change Info event. Called after p.mu is
// released; the attrs are the stable, greppable set the design fixes.
func (p *relayKCPPair) logPathChange(ev *pathChangeEvent) {
	if ev == nil || p.e == nil || p.e.log == nil {
		return
	}
	p.e.log.Info("pair path changed",
		"event", "path-change",
		"peer", keyName(p.peer),
		"from", ev.from,
		"to", ev.to,
		"reason", ev.reason,
		"directRecvAge", ev.directRecvAge.String(),
		"relayAlive", ev.relayAlive,
		"nc", ev.nc,
		"migrations", ev.migrations,
		"fallbacks", ev.fallbacks,
	)
}

// logUnderlayInstalled emits the O1 direct-underlay installed Info event.
func (p *relayKCPPair) logUnderlayInstalled(u *directUnderlay) {
	if u == nil || p.e == nil || p.e.log == nil {
		return
	}
	p.e.log.Info("direct underlay installed",
		"event", "direct-underlay",
		"peer", keyName(p.peer),
		"state", "installed",
		"reason", underlayPunch,
		"peerAddr", u.peer.String(),
	)
}

// logUnderlayRetired emits the O1 direct-underlay retired Info event, with the
// underlay's lifetime and the finite retirement reason.
func (p *relayKCPPair) logUnderlayRetired(u *directUnderlay, reason string) {
	if u == nil || p.e == nil || p.e.log == nil {
		return
	}
	p.e.log.Info("direct underlay retired",
		"event", "direct-underlay",
		"peer", keyName(p.peer),
		"state", "retired",
		"reason", reason,
		"peerAddr", u.peer.String(),
		"lifetime", time.Since(u.installedAt).String(),
	)
}

// noteSeed emits the O1 seed Info event and counts failures (O2). Called from
// the punch goroutine on each family's handshake result.
func (p *relayKCPPair) noteSeed(result, family, addr string) {
	if p == nil {
		return
	}
	if result != "ok" {
		p.seedFailures.Add(1)
	}
	if p.e == nil || p.e.log == nil {
		return
	}
	p.e.log.Info("direct punch seed",
		"event", "seed",
		"peer", keyName(p.peer),
		"result", result,
		"family", family,
		"addr", addr,
	)
}

// noteRelayLoss emits the O1 relay-loss Info event — the H1 signal — and counts
// suppressions (O2). suppressed is whether a live direct path kept the relay
// loss from resetting the pair.
func (p *relayKCPPair) noteRelayLoss(suppressed bool, reason string) {
	if p == nil {
		return
	}
	if suppressed {
		p.relayLossSuppressed.Add(1)
	}
	if p.e == nil || p.e.log == nil {
		return
	}
	p.e.log.Info("relay loss",
		"event", "relay-loss",
		"peer", keyName(p.peer),
		"suppressed", suppressed,
		"reason", reason,
	)
}

// ReadFrom returns one datagram from the pair's fan-in channel: the relay and
// direct pumps feed it, and every read reports the zero-value dummyAddr{} kcp-go
// locked its source to at NewConn4. On the pair's end it drains what the pumps
// left buffered before io.EOF, so an in-flight segment is never dropped at pair
// end; io.EOF is reserved for the pair itself, because kcp-go ends its read loop
// on any read error.
//
// The pumps are asynchronous, so at pair end either may still be draining its
// final datagram into recv when this is first called. Waiting only on done would
// race them and could report io.EOF with datagrams still queued — the drain
// test's failure mode. Instead, on done this loop serves recv until both pumps
// have signalled their exit (relayPumpDone and directPumpDone), then serves one
// last buffered datagram if present. Serving recv while waiting is also what
// lets a pump parked on a full channel finish, so the wait cannot deadlock.
func (p *relayKCPPair) ReadFrom(b []byte) (int, net.Addr, error) {
	var pkt []byte
	select {
	case pkt = <-p.recv:
	case <-p.done:
		p.mu.Lock()
		directDone := p.directPumpDone
		p.mu.Unlock()
		relayDone := p.relayPumpDone
		for {
			if relayDone == nil && directDone == nil {
				// Both pumps have exited: deliver one last buffered datagram
				// if any, then report the pair's end.
				select {
				case pkt = <-p.recv:
					n := copy(b, pkt)
					return n, dummyAddr{}, nil
				default:
					return 0, nil, io.EOF
				}
			}
			select {
			case pkt = <-p.recv:
				n := copy(b, pkt)
				return n, dummyAddr{}, nil
			case <-relayDone:
				relayDone = nil
			case <-directDone:
				directDone = nil
			}
		}
	}
	n := copy(b, pkt)
	return n, dummyAddr{}, nil
}

// WriteTo forwards one datagram to the pair's current preferred path: the direct
// underlay when it has delivered inbound traffic within directUnderlayIdle, else
// the registered relay adapter. A datagram dropped for want of a live path — or
// refused by one whose send failed — is a lost packet on a lossy path, the same
// outcome as a relay drop: the write reports success and KCP retransmits.
// Reporting the failure instead would be fatal in the other direction: kcp-go
// turns any WriteTo error into a permanent write failure for the session.
func (p *relayKCPPair) WriteTo(b []byte, _ net.Addr) (int, error) {
	// Fault injection (see faults): the data mute lives at the pair's write
	// path, so it covers both underlays (relay and direct) and a stream cannot
	// dodge it by migrating to the direct path. A dropped datagram is a lost
	// segment KCP retransmits; the write reports success, indistinguishable from
	// a path that ate it (Task 12's relocation from the old direct faultConn).
	if p.e != nil {
		// time.Now(), not clock.Now(): the silence window's origin is stamped
		// with time.Now() (newFaults), and the other fault checks
		// (sendControl/faultConn/handleControl) read time.Now() too. One clock
		// for the window, or its boundaries drift by the clock's resolution.
		if f := p.e.faults.Load(); f.muteDataArmed() && f.muteData(time.Now()) {
			return len(b), nil
		}
	}
	p.mu.Lock()
	direct := p.direct
	useDirect := p.preferredDirectLocked()
	ep, closed := p.ep, p.closed
	p.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	// Per-path mute (Task 12 / O7): the direct underlay alone is silenced, so
	// the pair can fall back to the relay and recover while the fault is live.
	// It is checked after the all-path mute above and before the counters, so
	// the two faults stay independent and the per-underlay counters remain a
	// partition of the total — a dropped direct datagram is counted on neither.
	if useDirect && p.e != nil && p.e.faults.Load().muteDirect() {
		return len(b), nil
	}
	p.bytesSent.Add(uint64(len(b)))
	if useDirect {
		p.directBytesSent.Add(uint64(len(b)))
		if _, err := direct.writeTo(b); err != nil {
			return len(b), nil
		}
		return len(b), nil
	}
	if ep == nil {
		return len(b), nil
	}
	p.relayBytesSent.Add(uint64(len(b)))
	if _, err := ep.WriteTo(b, nil); err != nil {
		return len(b), nil
	}
	return len(b), nil
}

// Close ends the pair through the engine's pair store, so the map entry goes
// with the session. kcp-go never calls it (ownConn=false); it completes the
// net.PacketConn interface.
func (p *relayKCPPair) Close() error {
	p.e.dropRelayKCP(p.peer, nil, errors.New("relay kcp pair closed"), 0)
	return nil
}

// LocalAddr returns a placeholder address.
func (p *relayKCPPair) LocalAddr() net.Addr { return dummyAddr{} }

// RemoteAddr returns a placeholder address identifying the peer.
func (p *relayKCPPair) RemoteAddr() net.Addr { return dummyAddr{p.peer} }

// SetDeadline is a no-op; deadlines are not meaningful for this proxy.
func (p *relayKCPPair) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op.
func (p *relayKCPPair) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op.
func (p *relayKCPPair) SetWriteDeadline(t time.Time) error { return nil }

// relayKCPStreamReadTimeout bounds one parked read on the pair's KCP session.
// The deadline is what lets a retired view's reader step out promptly (the
// deadline is moved into the past on retirement); the timeout is the fallback
// for the race where the wake lands before the read parks.
const relayKCPStreamReadTimeout = 100 * time.Millisecond

// relayKCPStreamWriteTimeout bounds one parked write on the pair's KCP session:
// a write parks when the send window is full, and it only unwinds on ACKs or a
// deadline set before it parked (kcp-go re-reads a changed deadline only for a
// write that parked with one). It is generous enough that a healthy path — the
// window draining within milliseconds of ACKs — never sees it; a write that
// does is on a path that stopped carrying anything.
const relayKCPStreamWriteTimeout = 10 * time.Second

// relayKCPStreamRetireTimeout bounds a retirement's wait for the view's
// in-flight read and write. Both normally land promptly (their deadlines are
// kicked into the past); the bound exists for the one race the kick can miss —
// a write that parked behind it — where waiting forever would stall the pump.
// A record that lands that late reorders the stream and the record layer's
// desync backstop resets the pair; a stuck retirement would freeze every peer.
const relayKCPStreamRetireTimeout = 500 * time.Millisecond

// relayKCPStream is one mux session's view of the pair's KCP stream: the
// per-build underlay handed to secure.conn. Closing a view retires exactly that
// mux session's reader and writer while the pair's session below survives —
// restoring the invariant the per-adapter underlay had (a mux session's
// underlay dies with it) without ending the pair's sequence epoch. It is a
// net.Conn.
type relayKCPStream struct {
	pair   *relayKCPPair
	closed atomic.Bool
	// reading and writing track this view's in-flight I/O, guarded by the
	// pair's mu (the idle signal lives there). Retirement waits for both: a
	// write that reaches the pair's stream after its successor's would reorder
	// the nonces the record stream is built on against its bytes.
	reading bool
	writing bool
}

// Read serves the pair's continuing byte stream. Exactly one view reads at a
// time: a view checks it still holds the pair's reader slot before drawing
// bytes, and Close retires it before the next view is claimed. Bytes a retired
// view had already drawn are not lost — they are queued on the pair and served
// to the next reader first, so the record stream stays in order across a mux
// session rebuild.
func (s *relayKCPStream) Read(b []byte) (int, error) {
	for {
		p := s.pair
		p.mu.Lock()
		if s.closed.Load() || p.closed || p.stream != s {
			p.mu.Unlock()
			return 0, net.ErrClosed
		}
		if n := copy(b, p.pending); n > 0 {
			p.pending = p.pending[n:]
			p.mu.Unlock()
			return n, nil
		}
		s.reading = true
		sess := p.sess
		p.mu.Unlock()

		deadline := time.Now().Add(relayKCPStreamReadTimeout)
		sess.SetReadDeadline(deadline)
		n, err := sess.Read(b)

		p.mu.Lock()
		s.reading = false
		p.signalIdleLocked()
		if s.closed.Load() || p.closed || p.stream != s {
			// Retired mid-read: these bytes belong to the continuing stream, so
			// hand them to the next reader instead of dropping them.
			if n > 0 {
				p.pending = append(p.pending, b[:n]...)
			}
			p.mu.Unlock()
			return 0, net.ErrClosed
		}
		p.mu.Unlock()
		if err != nil {
			if time.Now().Before(deadline) {
				// Failed before its own deadline: not a parked-out timeout, so
				// the session itself is broken — surface it.
				return 0, err
			}
			continue // parked out: re-check state and re-park
		}
		return n, nil
	}
}

// Write appends to the pair's stream. A retired view writes nothing: a record
// from a dead mux session landing after its successor's would reorder the nonce
// sequence the pair's record stream is built on. The write carries a deadline
// so a write parked on a full send window can be kicked out at retirement (see
// relayKCPStreamWriteTimeout).
func (s *relayKCPStream) Write(b []byte) (int, error) {
	p := s.pair
	p.mu.Lock()
	if s.closed.Load() || p.closed || p.stream != s {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	s.writing = true
	sess := p.sess
	p.mu.Unlock()

	sess.SetWriteDeadline(time.Now().Add(relayKCPStreamWriteTimeout))
	n, err := sess.Write(b)

	p.mu.Lock()
	s.writing = false
	p.signalIdleLocked()
	p.mu.Unlock()
	return n, err
}

// Close retires this view: a parked read is woken at once (its deadline is
// moved into the past), and Close waits for this view's in-flight read and
// write to land before returning, so the pair's next reader and writer start
// exactly where this one stopped — a write that reached the stream after its
// successor's would reorder the record stream's nonces against its bytes. The
// wait is bounded (see relayKCPStreamRetireTimeout): a write parked against an
// unresponsive peer's full window is terminated at the bound instead — it
// returns an error and hands its nonce back (see cryptoConn.Write), so it can
// never land after its successor's records — where waiting for ACKs that may
// never come would stall the pump that called this.
func (s *relayKCPStream) Close() error {
	p := s.pair
	p.mu.Lock()
	already := s.closed.Swap(true)
	if p.stream == s {
		p.stream = nil
	}
	p.signalIdleLocked()
	sess := p.sess
	idle := p.idle
	p.mu.Unlock()
	if sess != nil {
		sess.SetReadDeadline(time.Now())
	}
	deadline := time.Now().Add(relayKCPStreamRetireTimeout)
	for {
		p.mu.Lock()
		busy := s.reading || s.writing
		p.mu.Unlock()
		if !busy {
			break
		}
		if !time.Now().Before(deadline) {
			if sess != nil {
				sess.SetWriteDeadline(time.Now())
			}
			break
		}
		select {
		case <-idle:
		case <-time.After(time.Until(deadline)):
		}
		p.mu.Lock()
		idle = p.idle
		p.mu.Unlock()
	}
	if already {
		return net.ErrClosed
	}
	return nil
}

// LocalAddr returns a placeholder address.
func (s *relayKCPStream) LocalAddr() net.Addr { return dummyAddr{} }

// RemoteAddr returns a placeholder address identifying the peer.
func (s *relayKCPStream) RemoteAddr() net.Addr { return dummyAddr{s.pair.peer} }

// SetDeadline is a no-op; the view manages its own read deadline.
func (s *relayKCPStream) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op.
func (s *relayKCPStream) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op.
func (s *relayKCPStream) SetWriteDeadline(t time.Time) error { return nil }
