package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
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
	p := &relayKCPPair{
		e:             e,
		peer:          peer,
		recv:          make(chan []byte, relayKCPRecvBuffer),
		done:          make(chan struct{}),
		relayPumpDone: make(chan struct{}),
		wake:          make(chan struct{}),
		idle:          make(chan struct{}),
	}
	// The relay pump runs for the pair's lifetime: it parks until an endpoint
	// is registered, follows the pair across endpoint swaps, and ends only when
	// the pair itself does. It is what lets a second (direct) pump feed the same
	// fan-in in Task 3 without the pair's ReadFrom knowing which path delivered.
	go p.pumpRelay()
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
	// recv is the pair's fan-in: the relay pump (and, from Task 3, the direct
	// pump) hand it datagrams, and the pair's ReadFrom serves KCP from it. done
	// is closed exactly once by shutdown; both pumps select on it so neither can
	// outlive the pair. relayPumpDone is closed by pumpRelay when it exits,
	// after it has drained the final endpoint into recv; ReadFrom waits on it at
	// pair end so a datagram the endpoint already queued is delivered, not
	// dropped. A future direct pump that must preserve its final datagrams the
	// same way should signal its own exit and have ReadFrom wait on it too.
	recv          chan []byte
	done          chan struct{}
	relayPumpDone chan struct{}

	// bytesSent/bytesRcvd count the pair's relay datagrams in bytes, on the
	// paths the pair already walks (WriteTo/ReadFrom). They are this pair's own
	// counters — deliberately NOT kcp-go's process-global DefaultSnmp, which
	// aggregates every KCP session including the direct plane. Atomic rather
	// than under p.mu: these sit on the pair's data path, and a status read must
	// never contend with it. The increment is one lock-free Add per datagram,
	// negligible next to the channel send/receive already on those paths.
	bytesSent atomic.Uint64
	bytesRcvd atomic.Uint64
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
	// nodelay=1 (on), 10ms interval, fast retransmit on the 2nd duplicate ACK,
	// congestion control off: a relay drop is a bounded-queue overflow, not a
	// congestion signal, so halving the window on loss would only starve a
	// healthy path.
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetMtu(relayKCPMtu)
	sess.SetWindowSize(relayKCPSndWnd, relayKCPRcvWnd)
	p.sess = sess
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
	if sess != nil {
		sess.Close()
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
	p.mu.Unlock()
	s := relayKCPSnapshot{
		bytesSent: p.bytesSent.Load(),
		bytesRcvd: p.bytesRcvd.Load(),
	}
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

// ReadFrom returns one datagram from the pair's fan-in channel: the relay pump
// (and, from Task 3, the direct pump) feed it, and every read reports the
// zero-value dummyAddr{} kcp-go locked its source to at NewConn4. On the pair's
// end it drains what the relay pump left buffered before io.EOF, so an in-flight
// segment is never dropped at pair end; io.EOF is reserved for the pair itself,
// because kcp-go ends its read loop on any read error.
//
// The pump is asynchronous, so at pair end it may still be draining the final
// endpoint into recv when this is first called. Waiting only on done would race
// it and could report io.EOF with datagrams still queued — the drain test's
// failure mode. Instead, on done this loop serves recv until the pump signals it
// has exited (relayPumpDone), then serves one last buffered datagram if present.
// Serving recv while waiting is also what lets a pump parked on a full channel
// finish, so the wait cannot deadlock.
func (p *relayKCPPair) ReadFrom(b []byte) (int, net.Addr, error) {
	var pkt []byte
	select {
	case pkt = <-p.recv:
	case <-p.done:
		for {
			select {
			case pkt = <-p.recv:
				n := copy(b, pkt)
				return n, dummyAddr{}, nil
			case <-p.relayPumpDone:
				// The relay pump has exited: deliver one last buffered
				// datagram if any, then report the pair's end.
				select {
				case pkt = <-p.recv:
					n := copy(b, pkt)
					return n, dummyAddr{}, nil
				default:
					return 0, nil, io.EOF
				}
			}
		}
	}
	n := copy(b, pkt)
	return n, dummyAddr{}, nil
}

// WriteTo forwards one datagram to the current registered adapter. A datagram
// dropped for want of a live endpoint — or refused by one whose send failed —
// is a lost packet on a lossy path, the same outcome as a relay drop: the write
// reports success and KCP retransmits. Reporting the failure instead would be
// fatal in the other direction: kcp-go turns any WriteTo error into a permanent
// write failure for the session.
func (p *relayKCPPair) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.bytesSent.Add(uint64(len(b)))
	p.mu.Lock()
	ep, closed := p.ep, p.closed
	p.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if ep == nil {
		return len(b), nil
	}
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
