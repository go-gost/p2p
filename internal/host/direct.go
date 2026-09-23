package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/go-gost/p2p/internal/stun"
)

// Direct (hole-punched) data plane: after a relay smux session is established,
// both peers independently probe their NAT via STUN, exchange candidates over
// the relay's control channel, and — symmetrically — both dial the peer's
// candidate with the same KCP conv (mutual simultaneous open), confirming the
// path with an echo handshake before any stream rides it. When that succeeds,
// new streams prefer the direct smux session while the relay session stays up
// as fallback.
//
// The direct session is independent of the DERP transport: once established it
// keeps serving even if the relay drops (the control plane is gone, so a
// re-punch must wait for the relay to return, but existing traffic continues).
// A relay-reported PeerGone for the peer does not tear it down either — that
// notice is best-effort and says nothing about a path that does not run through
// the relay. The session answers for itself through its own keepalive
// (directSmuxKeepAliveTimeout), and dropIfGone reclaims its entry once it ends.

const (
	frameControl = 0x00 // [0x00][kind 1B][payload]
	frameData    = 0x01 // [0x01][smux byte stream]

	ctrlPunchCandidates = 0x02 // sealed candidate list
	ctrlCaps            = 0x04 // sealed capability bitfield (forward-looking seam)
	// 0x03 was the udp dial notice: a datagram link now always presents its own
	// edge, so no notice is sent and none is acted on. The kind stays unused.
)

// Capability bits exchanged via ctrlCaps. Bit 0 marks IPv6 awareness. The frame
// is a negotiation seam: IPv6 selection does NOT depend on it — the candidate
// list is the in-band signal (a peer that offers a v6 candidate supports v6) —
// so an unset bit changes no behavior there. It is re-sent with every candidate
// broadcast so a lost frame or a late-joining peer cannot permanently degrade
// negotiation; the receiver ORs the bits.
const capsIPv6 uint8 = 1 << 0

// capsTightKeepalive marks a peer that runs the direct session's own, tighter
// keepalive (timeouts.directSmux). It has to be negotiated, not assumed: smux
// answers a NOP with nothing, so a session's liveness is fed only by the frames
// the *peer* sends — a peer pinging every 10s cannot keep a 6s timeout alive,
// and would see its direct sessions torn down and re-punched every 6s. A peer
// that does not set this bit gets the relay's pair instead, which is what every
// peer got before the tighter one existed.
const capsTightKeepalive uint8 = 1 << 1

// v6AnnounceFunc maps the bound IPv6 punch socket's port to the endpoint to
// advertise. Production advertises the socket's own local address; tests
// override it to force an unreachable candidate.
type v6AnnounceFunc func(port uint16) netip.AddrPort

// Direct timing. Vars so tests can shorten them.
var (
	punchTimeout = 10 * time.Second
	// punchWaitTimeout bounds how long OpenStream blocks waiting for a hole
	// punch before falling back to the relay. Punching is sub-second to ~2s,
	// so the first connection rides the direct path instead of starting on
	// the relay.
	punchWaitTimeout = 5 * time.Second
	backoffPeriod    = 30 * time.Second
	stunTimeout      = 3 * time.Second
	// candidateGrace is how long a round holds after taking a peer's candidate
	// list, for a fresher one to supersede it. See the call site in punch.
	candidateGrace = 200 * time.Millisecond
	// seedTimeout bounds the symmetric echo handshake (both peers must see
	// their own token round-trip before streams ride the session).
	seedTimeout = 5 * time.Second
)

type directState int

const (
	directNone directState = iota
	directAttempting
	directUp
	directBackoff
)

// The values p2p.Status.PeerTransports reports, one per peer: a peer is
// connected through the relay, and these say whether it rides a hole-punched
// session instead — and, when it does not, why not. Keep the set and the doc
// on that field in sync.
const (
	transportDirect          = "direct"           // live hole-punched session
	transportPunching        = "punching"         // a punch for this peer is in flight
	transportFailed          = "failed"           // this peer's punch failed (usually a symmetric NAT)
	transportRelay           = "derp"             // on the relay, nothing in the way of a punch
	transportDisabled        = "disabled"         // the direct path is off (Config.Direct)
	transportNoCandidates    = "no-candidates"    // no STUN server and no IPv6 egress: nothing to punch with
	transportStunUnreachable = "stun-unreachable" // STUN configured but not answering, and no IPv6 fallback
)

// candidate is a single UDP endpoint offered by a peer.
type candidate struct {
	addr netip.AddrPort
}

// directConn is the per-peer hole-punch state, kept in a map separate from the
// relay peerConn so it survives DERP transport teardown.
type directConn struct {
	e    *engine
	peer derpclient.PublicKey

	cand chan []candidate // peer candidates (buffered)

	mu       sync.Mutex
	state    directState
	failed   bool           // a punch round has failed at least once (sticky)
	sess     *smux.Session  // direct smux session when up
	socket   *net.UDPConn   // punch socket; kcp closes it with the session (ownConn=true)
	peerAddr netip.AddrPort // peer's dialed endpoint (public cross-NAT, local same-NAT)
	mine     []candidate    // our candidates for the current punch, answered to the peer
	lastPeer []candidate    // peer candidates already acted on (dedupes re-announcements)
	peerCaps uint8          // capability bits the peer advertised via ctrlCaps
}

func (e *engine) directConn(peer derpclient.PublicKey) *directConn {
	e.mu.Lock()
	defer e.mu.Unlock()
	if dc, ok := e.directs[peer]; ok {
		return dc
	}
	dc := &directConn{
		e:    e,
		peer: peer,
		cand: make(chan []candidate, 1),
	}
	e.directs[peer] = dc
	return dc
}

func (e *engine) getDirect(peer derpclient.PublicKey) *directConn {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.directs[peer]
}

// directEnabled reports whether a punch has any candidate source: a configured
// STUN server (IPv4), a usable global IPv6 egress, or an explicit v6 override.
// Side-effect free, so it is safe on the OpenStream/status paths.
func (e *engine) directEnabled() bool {
	if !e.direct {
		return false
	}
	return e.stunAddr != "" || e.v6Addr != nil || e.v6Available
}

// maybeStartDirect kicks off hole punching when a candidate source exists.
// Idempotent: it only transitions directNone -> directAttempting, so concurrent
// triggers from OpenStream and pump converge on a single punch goroutine.
func (e *engine) maybeStartDirect(peer derpclient.PublicKey) {
	if !e.directEnabled() {
		return
	}
	e.directConn(peer).start()
}

// warm brings up the peer's relay session (a smux session over the DERP
// adapter, no stream on it) so the peer counts as connected and has a path in
// Status before any traffic — and, when punch is set, starts a hole punch for
// it too. See sessionLocked for why the two are separable.
func (e *engine) warm(peer derpclient.PublicKey, punch bool) error {
	pc := e.peerConn(peer)
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.closed {
		return p2p.ErrPeerUnreachable
	}
	_, err := pc.sessionLocked(punch)
	return err
}

// punchAndWait triggers hole punching when a candidate source exists and blocks
// until a direct session is up or punchWaitTimeout elapses. It returns nil so
// the caller falls back to the relay. Candidate exchange rides the DERP
// control channel, so it needs only the DERP connection — not a relay mux
// session — and completes well under the timeout.
//
// Only the call that starts the punch waits for it. A punch already in flight
// is unaffected by blocking here, and one that failed and is backing off cannot
// come up within the wait at all — so waiting would charge every stream the
// full timeout on a peer that cannot punch (symmetric NAT, STUN blocked),
// turning a relay-only path into a per-connection stall. For the same reason
// the wait ends as soon as the round it started has failed, rather than
// running out the clock on a session that is no longer coming.
func (e *engine) punchAndWait(peer derpclient.PublicKey) *smux.Session {
	if !e.directEnabled() {
		return nil
	}
	dc := e.directConn(peer)
	if !dc.start() {
		return nil
	}
	deadline := time.Now().Add(punchWaitTimeout)
	for time.Now().Before(deadline) {
		if sess := dc.session(); sess != nil {
			return sess
		}
		if dc.hasFailed() {
			return nil // a round already failed for this peer: the relay is the answer
		}
		select {
		case <-e.stop:
			return nil
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}

// start kicks off a punch when none is running, and reports whether this call
// started one: false when a punch is already in flight or backing off.
func (dc *directConn) start() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.state != directNone {
		return false
	}
	dc.state = directAttempting
	go dc.punch()
	return true
}

// session returns the live direct smux session, or nil. If the session was
// found dead it is torn down and a re-punch is scheduled.
func (dc *directConn) session() *smux.Session {
	dc.mu.Lock()
	if dc.sess == nil {
		dc.mu.Unlock()
		return nil
	}
	sess := dc.sess
	if !sess.IsClosed() {
		dc.mu.Unlock()
		return sess
	}
	dc.sess = nil
	sock := dc.socket
	dc.socket = nil
	dc.mine = nil // the socket backing them is closing
	if dc.state == directUp {
		dc.state = directNone
	}
	dc.mu.Unlock()
	if sock != nil {
		sock.Close()
	}
	if dc.e.dropIfGone(dc.peer, dc) {
		return nil // the peer is gone from the relay: nothing to re-punch with
	}
	go dc.start() // schedule re-punch
	return nil
}

// stateOf reports the punch state machine's current state, a plain read.
func (dc *directConn) stateOf() directState {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.state
}

// hasFailed reports whether any punch round for this peer has failed. It
// outlives the round: a retry in flight after a failure is still a peer whose
// direct path does not work, and reporting "punching" for it would hide that
// (the peer's own re-announcements restart rounds often enough that the state
// alone is no guide).
func (dc *directConn) hasFailed() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.failed
}

// live reports whether a usable direct session exists, without side effects.
// Unlike session() it never tears down a dead session or schedules a re-punch:
// a status query must not trigger connection churn.
func (dc *directConn) live() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.sess != nil && !dc.sess.IsClosed()
}

func (dc *directConn) onCandidates(cands []candidate) {
	dc.mu.Lock()
	if sameCandidates(cands, dc.lastPeer) {
		dc.mu.Unlock()
		return // a re-announcement of candidates we already acted on
	}
	dc.lastPeer = cands
	mine := dc.mine
	dc.mu.Unlock()

	dc.e.log.Debug("direct punch: peer candidates via relay", "peer", keyName(dc.peer), "candidates", candAddrs(cands))

	// Answer with our own candidates. A peer that started its punch after we
	// broadcast — or reconnected to the relay — missed our first announcement,
	// so without this it waits for candidates we already sent once and never
	// dials. Answering makes the exchange a request/response: both sides end up
	// with each other's candidates and dial in the same round. The dedupe above
	// keeps this from ping-ponging, since the peer's re-announcement of its own
	// candidates (the same list) is ignored.
	if mine != nil {
		if err := dc.e.sendCandidates(dc.peer, mine); err != nil {
			dc.e.log.Debug("direct punch: answer candidates failed", "peer", keyName(dc.peer), "error", err)
		}
	}

	// Latest wins: the slot holds one list and a round takes whatever is in it,
	// so an older list the round has not picked up yet must not shadow this
	// one. The superseded list is the more dangerous of the two — a peer
	// announces a new port every round, so the stale entry names a socket that
	// is already closed.
drain:
	for {
		select {
		case <-dc.cand:
		default:
			break drain
		}
	}
	select {
	case dc.cand <- cands:
	default:
	}
	// A live session is not disturbed by an announcement. The peer only
	// announces when it (re)started a round, which once meant "our session is
	// stale, tear it down" — but a peer whose rounds keep failing re-announces
	// with a new port every round, and tearing down a *working* session each
	// time is how both sides end up with nothing: the session that came up is
	// killed by the next announcement, and the round that replaces it fails.
	// A session that really is stale (the peer restarted and we missed its
	// PeerGone) dies on its own within a keepalive, and the re-punch below
	// happens then.
	//
	// A backoff, on the other hand, should be cut short: the peer is punching
	// now, and waiting it out means the two sides' windows miss each other.
	// start() only runs from directNone, so reset a backoff first.
	dc.mu.Lock()
	if dc.state == directUp || dc.state == directBackoff {
		// Let a round run. A live session is not torn down for it: session()
		// serves it whatever the punch state is, and markUp replaces it only
		// once a new punch actually succeeds. If this peer's session really is
		// stale (it restarted and we missed its PeerGone), the round is what
		// repairs it.
		dc.state = directNone
	}
	dc.mu.Unlock()
	dc.start()
}

// teardown closes the direct session and socket, returning to directNone
// without scheduling a re-punch (used on engine shutdown and in tests).
func (dc *directConn) teardown() {
	dc.mu.Lock()
	sess := dc.sess
	sock := dc.socket
	dc.sess = nil
	dc.socket = nil
	dc.mine = nil
	dc.state = directNone
	dc.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
	if sock != nil {
		sock.Close()
	}
}

// markUp stores the freshly-built session+token and marks the state up.
func (dc *directConn) markUp(sess *smux.Session, socket *net.UDPConn, peerAddr netip.AddrPort) {
	dc.mu.Lock()
	// A punch can succeed while an older session is still serving (it is
	// re-run on the peer's announcements): the new session replaces it, and
	// the old one and its socket are done.
	prevSess, prevSock := dc.sess, dc.socket
	dc.sess = sess
	dc.socket = socket
	dc.peerAddr = peerAddr
	dc.state = directUp
	dc.failed = false
	dc.mu.Unlock()
	if prevSess != nil && prevSess != sess {
		prevSess.Close()
	}
	if prevSock != nil && prevSock != socket {
		prevSock.Close()
	}
	dc.e.stats.punchSuccess.Add(1)
}

// markDead clears the direct-session state when the accept loop ends (session
// dead). The opening side notices death through session() and re-punches; the
// accepting side otherwise stays stuck in directUp and never answers the
// re-punch candidates, so the pair can never re-establish. The guard ignores a
// stale session so a concurrent re-punch (markUp) is not clobbered.
func (dc *directConn) markDead(sess *smux.Session) {
	dc.mu.Lock()
	if dc.sess != sess {
		dc.mu.Unlock()
		return
	}
	dc.sess = nil
	sock := dc.socket
	dc.socket = nil
	dc.mine = nil
	dc.state = directNone
	dc.mu.Unlock()
	if sock != nil {
		sock.Close()
	}
	dc.e.dropIfGone(dc.peer, dc)
}

// addCaps ORs the capability bits the peer advertised. Capabilities are
// cumulative: a re-announcement never clears a bit already set.
func (dc *directConn) addCaps(bits uint8) {
	dc.mu.Lock()
	dc.peerCaps |= bits
	dc.mu.Unlock()
}

// supports reports whether the peer has advertised all of the given capability
// bits. Kept for the negotiation seam; IPv6 selection does not depend on it
// (the candidate list is the in-band signal).
func (dc *directConn) supports(bits uint8) bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.peerCaps&bits == bits
}

// peerAddrString returns the peer's dialed endpoint, or "" when not punched.
func (dc *directConn) peerAddrString() string {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.peerAddr.String()
}

// backoff marks a failed punch and schedules a retry.
func (dc *directConn) backoff() {
	dc.mu.Lock()
	dc.state = directBackoff
	dc.failed = true
	// The round's sockets are gone, so its candidate list is not ours to offer
	// any more: onCandidates answers a peer's announcement with dc.mine, and
	// echoing a dead endpoint races the peer's own fresh list into its slot.
	dc.mine = nil
	dc.mu.Unlock()
	dc.e.log.Debug("direct punch: backoff", "peer", keyName(dc.peer), "retryIn", backoffPeriod.String())
	go func() {
		select {
		case <-dc.e.stop:
			return
		case <-time.After(backoffPeriod):
		}
		dc.mu.Lock()
		// Only reset if we're still backing off: onCandidates may have already
		// restarted a punch in response to a peer candidate.
		if dc.state == directBackoff {
			dc.state = directNone
		}
		dc.mu.Unlock()
		dc.start()
	}()
}

// conv deterministically derives the KCP conversation ID from the (sorted)
// keypair so both sides agree and retries reuse the same conv without a
// handshake. 4 bytes of sha256 is collision-free for the peer counts this
// host will see.
func (dc *directConn) conv() uint32 {
	a, b := dc.e.pub, dc.peer
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	h := sha256.Sum256(append(a[:], b[:]...))
	return binary.BigEndian.Uint32(h[:4])
}

func (dc *directConn) punch() {
	e := dc.e
	// The smux session role (smaller key = client) is independent of who
	// dials: both peers dial. See docs/2026-09-09-p2p-mutual-punch-design.md.
	roleIsClient := bytes.Compare(e.pub[:], dc.peer[:]) < 0
	pname := keyName(dc.peer)
	e.stats.punchAttempts.Add(1)

	// 1. Collect one socket + candidate set per available family. A family that
	// cannot be set up is dropped and the round continues on whatever remains,
	// so an unreachable STUN server no longer aborts a v6-capable punch.
	type family struct {
		name string
		v6   bool
		sock *net.UDPConn
		mine []candidate
	}
	var fams []family
	if e.stunAddr != "" {
		if sock, mine, err := e.collectV4(); err != nil {
			// Remember it for Status: a STUN server that does not answer is the
			// usual reason a peer is stuck on the relay, and it is not visible
			// per peer.
			e.stunFailed.Store(true)
			e.log.Debug("direct punch: v4 unavailable", "peer", pname, "error", err)
		} else {
			e.stunFailed.Store(false)
			fams = append(fams, family{name: "v4", sock: sock, mine: mine})
		}
	}
	// Resolve the IPv6 source for this round: an explicit override wins (tests),
	// otherwise re-probe — an egress that appeared or changed since startup is
	// then picked up on the next backoff retry without a restart.
	v6 := e.v6Addr
	if v6 == nil && e.v6Available {
		v6 = v6Egress()
	}
	if v6 != nil {
		if sock, mine, err := e.collectV6(v6); err != nil {
			e.log.Debug("direct punch: v6 unavailable", "peer", pname, "error", err)
		} else {
			fams = append(fams, family{name: "v6", v6: true, sock: sock, mine: mine})
		}
	}
	// Every socket is closed on all exits except the winner, which is handed to
	// markUp. Closing an already-closed socket (a failed family's session owns
	// it via ownConn=true) is a harmless no-op.
	closeFams := func() {
		for i := range fams {
			if fams[i].sock != nil {
				fams[i].sock.Close()
				fams[i].sock = nil
			}
		}
	}
	if len(fams) == 0 {
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: start", "peer", pname)

	// 2. Advertise our endpoints (v4 then v6) and our capabilities, then wait
	// for the peer's list (exchanged over the relay control channel, so this
	// works even while no UDP path exists yet).
	var mine []candidate
	for i := range fams {
		mine = append(mine, fams[i].mine...)
	}
	dc.mu.Lock()
	dc.mine = mine
	dc.mu.Unlock()
	if err := e.sendCaps(dc.peer, capsIPv6|capsTightKeepalive); err != nil {
		e.log.Debug("direct punch: send caps failed", "peer", pname, "error", err)
	}
	if err := e.sendCandidates(dc.peer, mine); err != nil {
		e.log.Debug("direct punch: send candidates failed", "peer", pname, "error", err)
		closeFams()
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: candidates sent", "peer", pname, "candidates", candAddrs(mine))

	ctx, cancel := context.WithTimeout(context.Background(), punchTimeout)
	defer cancel()
	cands, ok := dc.waitCandidates(ctx)
	if !ok {
		e.log.Debug("direct punch: no peer candidates", "peer", pname)
		closeFams()
		dc.backoff()
		return
	}
	// The list just taken can already be superseded: a peer that (re)connected
	// announces into our slot the moment it starts its round, and its own
	// exchange with us completes a few milliseconds later, so the round that
	// follows is the current one and the one we hold is a socket it has left.
	// Dialing it burns the round — and behind a symmetric NAT it also binds our
	// mapping to a port the peer is not listening on, so the packets that would
	// have converged go nowhere. Hold briefly for the fresher list.
	if newer, ok := dc.fresherCandidates(candidateGrace); ok {
		cands = newer
	}
	peerV4 := ipv4Addrs(cands)
	peerV6 := v6Addrs(cands)
	e.log.Debug("direct punch: peer candidates", "peer", pname, "candidates", candAddrs(cands))

	// 3. Family order: IPv6 when both sides offer it, otherwise IPv4. The
	// predicate uses only the two candidate lists, so both peers compute the
	// same order (docs/2026-09-20-p2p-ipv6-direct.md).
	i4, i6 := -1, -1
	for i := range fams {
		switch fams[i].name {
		case "v4":
			i4 = i
		case "v6":
			i6 = i
		}
	}
	has4 := i4 >= 0 && len(peerV4) > 0
	has6 := i6 >= 0 && len(peerV6) > 0
	var order []int
	if has6 {
		order = append(order, i6) // v6 preferred
	}
	if has4 {
		order = append(order, i4)
	}
	if len(order) == 0 {
		e.log.Debug("direct punch: no shared family", "peer", pname, "candidates", candAddrs(cands))
		closeFams()
		dc.backoff()
		return
	}

	// 4. Try each family once, in order. Per-family sockets preserve the kcp
	// "one socket, one session" rule; both families failing backs off. The seed
	// handshake requires a full own->peer->own round trip on both sides, so a
	// one-way v6 path fails on both peers and both fall back to v4 in this
	// round.
	for _, idx := range order {
		f := &fams[idx]
		var dial netip.AddrPort
		if f.v6 {
			// Both sides advertise their single egress address, so "first" is
			// unambiguous.
			dial = peerV6[0]
		} else {
			// Same hairpin rule as before: prefer the peer's public address,
			// but dial its local one when both share a NAT (same public IP).
			dial = peerV4[len(peerV4)-1]
			if len(peerV4) > 1 && f.mine[len(f.mine)-1].addr.Addr() == dial.Addr() {
				dial = peerV4[0]
			}
		}
		u := net.UDPAddrFromAddrPort(dial)
		e.log.Debug("direct punch: dial", "peer", pname, "family", f.name, "addr", u.String(), "conv", dc.conv())
		// ownConn=true: Close closes the socket, so session death tears down the
		// readLoop with no separate bookkeeping (kcp-go deep-dive R2).
		kcpConn, err := kcp.NewConn4(dc.conv(), u, nil, 0, 0, true, f.sock)
		if err != nil {
			e.log.Debug("direct punch: dial failed", "peer", pname, "family", f.name, "addr", u.String(), "error", err)
			continue
		}
		if err := seedHandshake(kcpConn, seedTimeout); err != nil {
			kcpConn.Close() // ownConn=true closes f.sock with it
			e.log.Debug("direct punch: seed failed", "peer", pname, "family", f.name, "addr", u.String(), "error", err)
			continue
		}

		// 5. smux over KCP; role by key order (external to who dialed).
		cfg := directSmuxConfig(dc.supports(capsTightKeepalive))
		var sess *smux.Session
		if roleIsClient {
			sess, err = smux.Client(kcpConn, cfg)
		} else {
			sess, err = smux.Server(kcpConn, cfg)
		}
		if err != nil {
			kcpConn.Close()
			e.log.Debug("direct punch: smux failed", "peer", pname, "family", f.name, "error", err)
			continue
		}

		sock := f.sock
		f.sock = nil // owned by the session
		closeFams()  // drop the unused family's socket
		// Only the winner's socket is still bound, so only its candidates are
		// ours to answer a peer's announcement with.
		dc.mu.Lock()
		dc.mine = f.mine
		dc.mu.Unlock()
		dc.markUp(sess, sock, dial)
		e.log.Debug("direct established", "peer", pname, "family", f.name,
			"mine", candAddrs(f.mine), "peerAddr", dial.String())
		go func() {
			e.acceptLoop(sess, "direct", dc.peer, dial.String())
			dc.markDead(sess)
		}()
		return
	}

	// Every available family failed this round.
	closeFams()
	dc.backoff()
}

// seedHandshake runs the symmetric echo handshake over a fresh KCP session.
// Both peers execute the same four steps — write own token, read the peer's
// token, echo it back, then require the own token's echo. Success therefore
// proves a full own->peer->own round trip on both sides; a half-open path
// (we can receive but our bytes never arrive) fails instead of producing a
// "false direct" session whose streams would blackhole. KCP retransmits the
// unacked bytes, so the window also covers a NAT mapping that only opens
// after the peer's first packet (k3s conntrack-assist).
func seedHandshake(c net.Conn, timeout time.Duration) error {
	c.SetDeadline(time.Now().Add(timeout))
	defer c.SetDeadline(time.Time{}) // clear: the session must outlive the seed

	var token [1]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	if _, err := c.Write(token[:]); err != nil {
		return err
	}
	var peer [1]byte
	if _, err := io.ReadFull(c, peer[:]); err != nil {
		return err
	}
	if _, err := c.Write(peer[:]); err != nil { // echo the peer's token
		return err
	}
	var echo [1]byte
	if _, err := io.ReadFull(c, echo[:]); err != nil {
		return err
	}
	if echo[0] != token[0] {
		return errors.New("derp engine: seed echo mismatch")
	}
	return nil
}

// fresherCandidates returns the newest candidate list to arrive within grace,
// or false when none did. It lets a round trade a fixed delay for the peer's
// current port: the lists are exchanged within milliseconds of each other
// (16-24 ms observed on a real relay), and the earlier of the two names a
// socket the peer has already replaced.
func (dc *directConn) fresherCandidates(grace time.Duration) ([]candidate, bool) {
	t := time.NewTimer(grace)
	defer t.Stop()
	var (
		latest []candidate
		ok     bool
	)
	for {
		select {
		case c := <-dc.cand:
			latest, ok = c, true
		case <-t.C:
			return latest, ok
		}
	}
}

func (dc *directConn) waitCandidates(ctx context.Context) ([]candidate, bool) {
	select {
	case cands := <-dc.cand:
		return cands, true
	default:
	}
	select {
	case cands := <-dc.cand:
		return cands, true
	case <-ctx.Done():
		return nil, false
	}
}

// ipv4Addrs returns the IPv4 candidate endpoints in the order offered.
func ipv4Addrs(cands []candidate) []netip.AddrPort {
	var out []netip.AddrPort
	for _, c := range cands {
		if c.addr.Addr().Is4() {
			out = append(out, c.addr)
		}
	}
	return out
}

// v6Addrs returns the IPv6 candidate endpoints in the order offered. A
// v4-mapped address (Is4In6) is excluded: encodeCandidates normalizes it to
// family 4, so it is an IPv4 endpoint and is handled by ipv4Addrs.
func v6Addrs(cands []candidate) []netip.AddrPort {
	var out []netip.AddrPort
	for _, c := range cands {
		if a := c.addr.Addr(); a.Is6() && !a.Is4In6() {
			out = append(out, c.addr)
		}
	}
	return out
}

// candAddrs renders candidate endpoints as strings for logs.
func candAddrs(cands []candidate) []string {
	s := make([]string, len(cands))
	for i, c := range cands {
		s[i] = c.addr.String()
	}
	return s
}

// sameCandidates reports whether two candidate lists carry the same endpoints,
// so a peer re-announcing its candidates (or answering ours with the same list)
// is not mistaken for a fresh punch.
func sameCandidates(a, b []candidate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].addr != b[i].addr {
			return false
		}
	}
	return len(a) > 0
}

// bindAddrFor returns a UDPAddr bound to the egress IP used to reach addr, or
// nil when it cannot be determined (the caller then binds the wildcard
// address). Binding a concrete IP makes the socket's local address a valid
// candidate for same-network peers.
func bindAddrFor(addr string) *net.UDPAddr {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil
	}
	probe, err := net.DialUDP("udp4", nil, ua)
	if err != nil {
		return nil
	}
	defer probe.Close()
	ip := probe.LocalAddr().(*net.UDPAddr).IP
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	return &net.UDPAddr{IP: ip}
}

// collectV4 binds an IPv4 punch socket to the egress IP toward the STUN server
// (so the local address we advertise is concrete and the NAT mapping is
// identical) and learns our public endpoint from STUN over that same socket.
func (e *engine) collectV4() (*net.UDPConn, []candidate, error) {
	sock, err := net.ListenUDP("udp4", bindAddrFor(e.stunAddr))
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), stunTimeout)
	pubEP, err := stun.Lookup(ctx, e.stunAddr, sock)
	cancel()
	if err != nil {
		sock.Close()
		return nil, nil, err
	}
	localEP := sock.LocalAddr().(*net.UDPAddr).AddrPort()
	mine := []candidate{{addr: localEP}, {addr: pubEP}}
	if localEP == pubEP {
		mine = mine[:1] // no NAT: local == public
	}
	return sock, mine, nil
}

// collectV6 binds the IPv6 punch socket to src, the host's egress address.
// IPv6 has no address translation, so the bound address is itself the reachable
// endpoint: binding it (rather than the wildcard) makes the send source
// deterministic, so kcp's strict source filter accepts the peer's replies even
// on a multi-homed host.
func (e *engine) collectV6(src *net.UDPAddr) (*net.UDPConn, []candidate, error) {
	sock, err := net.ListenUDP("udp6", &net.UDPAddr{IP: src.IP})
	if err != nil {
		return nil, nil, err
	}
	ap := sock.LocalAddr().(*net.UDPAddr).AddrPort()
	if e.v6Announce != nil {
		ap = e.v6Announce(ap.Port())
	}
	return sock, []candidate{{addr: ap}}, nil
}

// v6ProbeAddr is a global IPv6 address used only for a route lookup (no packet
// is sent): DialUDP reports the local source address the host would use to
// reach it, which is the egress address the direct path binds and advertises.
// ResolveUDPAddr wants a host:port, so the address must be bracketed; the port
// itself is never used.
const v6ProbeAddr = "[2001:4860:4860::8888]:53"

// v6Egress probes the host's IPv6 egress. A package var so tests can substitute;
// production uses detectV6Egress.
var v6Egress = detectV6Egress

// detectV6Egress returns the local IPv6 source address for a global destination,
// or nil when the host has no usable global IPv6 egress. A host with only
// on-link (e.g. ULA) addresses has no route to a global destination and gets
// nil, which is what we want: such an address is not reachable by a remote peer.
func detectV6Egress() *net.UDPAddr {
	ua, err := net.ResolveUDPAddr("udp6", v6ProbeAddr)
	if err != nil {
		return nil
	}
	probe, err := net.DialUDP("udp6", nil, ua)
	if err != nil {
		return nil
	}
	defer probe.Close()
	ip := probe.LocalAddr().(*net.UDPAddr).IP
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return nil
	}
	return &net.UDPAddr{IP: ip}
}

// sendCandidates seals our candidate list to the peer and ships it over the
// relay control channel.
func (e *engine) sendCandidates(peer derpclient.PublicKey, cands []candidate) error {
	return e.sendControl(peer, ctrlPunchCandidates, e.priv.SealTo(peer, encodeCandidates(cands)))
}

// directSmuxConfig is the smux configuration for a direct session. The tighter
// pair applies only when the peer advertised it (capsTightKeepalive): a session
// is kept alive by the frames the peer sends, so a timeout shorter than the
// peer's ping interval would tear the session down and re-punch it on a loop.
// A peer that did not advertise the bit gets the relay's pair — the behavior
// every peer had before the tighter one existed.
func directSmuxConfig(peerTight bool) *smux.Config {
	cfg := smux.DefaultConfig()
	if peerTight {
		cfg.KeepAliveInterval = directSmuxKeepAliveInterval
		cfg.KeepAliveTimeout = directSmuxKeepAliveTimeout
		return cfg
	}
	cfg.KeepAliveInterval = smuxKeepAliveInterval
	cfg.KeepAliveTimeout = smuxKeepAliveTimeout
	return cfg
}

// sendCaps advertises our capability bits to the peer. Re-sent with every
// candidate broadcast (idempotent) so a lost frame or a late-joining peer
// cannot permanently degrade negotiation; the peer ORs the bits.
func (e *engine) sendCaps(peer derpclient.PublicKey, caps uint8) error {
	return e.sendControl(peer, ctrlCaps, e.priv.SealTo(peer, []byte{caps}))
}

// sendControl sends a control frame ([frameControl][kind][payload]) to peer.
func (e *engine) sendControl(peer derpclient.PublicKey, kind byte, payload []byte) error {
	e.mu.Lock()
	c := e.client
	e.mu.Unlock()
	if c == nil {
		return errors.New("derp engine: no connection")
	}
	buf := make([]byte, 0, 2+len(payload))
	buf = append(buf, frameControl, kind)
	buf = append(buf, payload...)
	return c.SendPacket(peer, buf)
}

// encodeCandidates writes the candidate list as [count]([family][addr][port])*,
// choosing family 4 or 6 per address. A v4-mapped address is normalized to IPv4
// so it round-trips as family 4 (and As4 never sees a 16-byte address).
func encodeCandidates(cands []candidate) []byte {
	buf := make([]byte, 0, 1+len(cands)*19) // family + 16B addr + 2B port (v6 worst case)
	buf = append(buf, byte(len(cands)))
	for _, c := range cands {
		a := c.addr.Addr()
		if a.Is4In6() {
			a = a.Unmap()
		}
		if a.Is4() {
			buf = append(buf, 4)
			ip := a.As4()
			buf = append(buf, ip[:]...)
		} else {
			buf = append(buf, 6)
			ip := a.As16()
			buf = append(buf, ip[:]...)
		}
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], c.addr.Port())
		buf = append(buf, p[:]...)
	}
	return buf
}

func decodeCandidates(b []byte) ([]candidate, error) {
	if len(b) < 1 {
		return nil, errors.New("short candidate list")
	}
	n := int(b[0])
	b = b[1:]
	cands := make([]candidate, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < 1 {
			return nil, errors.New("short candidate")
		}
		family := b[0]
		b = b[1:]
		var ap netip.AddrPort
		switch family {
		case 4:
			if len(b) < 6 {
				return nil, errors.New("short ipv4 candidate")
			}
			ap = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[0:4])), binary.BigEndian.Uint16(b[4:6]))
			b = b[6:]
		case 6:
			if len(b) < 18 {
				return nil, errors.New("short ipv6 candidate")
			}
			ap = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[0:16])), binary.BigEndian.Uint16(b[16:18]))
			b = b[18:]
		default:
			return nil, errors.New("unknown candidate family")
		}
		cands = append(cands, candidate{addr: ap})
	}
	return cands, nil
}

// acceptLoop dispatches inbound streams on a session. Shared by the relay and
// direct sessions; transport names the path the stream arrived over ("derp"
// relay or "direct" hole punch), peerAddr is the peer's dialed endpoint
// (direct only).
func (e *engine) acceptLoop(sess *smux.Session, transport string, peer derpclient.PublicKey, peerAddr string) {
	start := time.Now()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if transport == "direct" {
				// Direct sessions die when the KCP path drops (e.g. NAT mapping
				// timeout). Log the lifetime + cause to distinguish that from an
				// orderly close.
				e.log.Debug("direct session ended", "peer", keyName(peer),
					"duration", time.Since(start).String(), "error", err)
			}
			return // session dead
		}
		e.stats.countStream(transport)
		// Classification reads the stream's leading bytes, so it runs in the
		// stream's own goroutine: a silent stream must not stall the accept
		// loop (and with it every other stream on the session).
		go e.serveInbound(stream, transport, peer, peerAddr)
	}
}

// serveInbound routes one inbound stream: a stream tagged with the datagram
// channel magic carries the peer's udp channel, anything else is a normal
// tunnel stream bridged to --target.
func (e *engine) serveInbound(stream net.Conn, transport string, peer derpclient.PublicKey, peerAddr string) {
	if tagged, c := peekTag(stream); tagged {
		// Three kinds of datagram end, resolved here:
		//   - the rendezvous (this host holds a local udp dial for peer and owns
		//     the larger key): the peer's edge pairs with that link, so the pair
		//     rides one shared edge -- the tun-to-tun shape. A link that already
		//     holds an adopted edge is not adoptable, so a second concurrent dial
		//     is served per stream instead of stealing the first one's edge;
		//   - the embedder (Listen mode): delivered as a datagram conn, the
		//     embedder's service owns it;
		//   - the target outlet (no local dial, no listener): served straight
		//     from the udp target pool for the stream's lifetime, zero per-peer
		//     state. Whether this peer may use the target is the caller's
		//     business (tun auther / firewall), not the transport's.
		if lnk := e.adoptableLink(peer); lnk != nil && lnk.adopt(c, transport) {
			return
		}
		if q := e.inbound.Load(); q != nil {
			q.deliverDatagram(c, keyName(peer), transport, peerAddr, e.log)
			return
		}
		target, ok := e.targets.pick("udp")
		if !ok {
			e.log.Debug("datagram stream refused (no link, no listener, no udp target)",
				"transport", transport, "peer", keyName(peer))
			c.Close()
			return
		}
		e.log.Info("datagram channel up", "transport", transport, "peer", keyName(peer))
		e.serveTargetStream(c, target)
		e.log.Info("datagram channel down", "transport", transport, "peer", keyName(peer))
		return
	} else if c != stream {
		stream = c // untagged: replay the bytes consumed by the partial peek
	}

	// Listen mode: the embedder owns the stream (and its target).
	if q := e.inbound.Load(); q != nil {
		q.deliver(stream, keyName(peer), transport, peerAddr, e.log)
		return
	}
	target, ok := e.targets.pick("tcp")
	if !ok {
		e.log.Warn("inbound tunnel refused", "transport", transport, "peer", keyName(peer))
		stream.Close()
		return
	}
	bridgeInbound(stream, transport, keyName(peer), peerAddr, target, e.log)
}
