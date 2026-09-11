package main

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

const (
	frameControl = 0x00 // [0x00][kind 1B][payload]
	frameData    = 0x01 // [0x01][smux byte stream]

	ctrlPunchCandidates = 0x02 // sealed candidate list
)

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

// candidate is a single UDP endpoint offered by a peer.
type candidate struct {
	addr netip.AddrPort
}

// directConn is the per-peer hole-punch state, kept in a map separate from the
// relay peerConn so it survives DERP transport teardown.
type directConn struct {
	e    *Engine
	peer derpclient.PublicKey

	cand chan []candidate // peer candidates (buffered)

	mu       sync.Mutex
	state    directState
	sess     *smux.Session  // direct smux session when up
	socket   *net.UDPConn   // punch socket; kcp closes it with the session (ownConn=true)
	peerAddr netip.AddrPort // peer's dialed endpoint (public cross-NAT, local same-NAT)
	mine     []candidate    // our candidates for the current punch, answered to the peer
	lastPeer []candidate    // peer candidates already acted on (dedupes re-announcements)
}

func (e *Engine) directConn(peer derpclient.PublicKey) *directConn {
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

func (e *Engine) getDirect(peer derpclient.PublicKey) *directConn {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.directs[peer]
}

// maybeStartDirect kicks off hole punching if STUN is configured. Idempotent:
// it only transitions directNone -> directAttempting, so concurrent triggers
// from OpenStream and pump converge on a single punch goroutine.
func (e *Engine) maybeStartDirect(peer derpclient.PublicKey) {
	if e.stunAddr == "" {
		return
	}
	e.directConn(peer).start()
}

// punchAndWait triggers hole punching (when STUN is configured) and blocks
// until a direct session is up or punchWaitTimeout elapses. It returns nil so
// the caller falls back to the relay. Candidate exchange rides the DERP
// control channel, so it needs only the DERP connection — not a relay mux
// session — and completes well under the timeout.
func (e *Engine) punchAndWait(peer derpclient.PublicKey) *smux.Session {
	if e.stunAddr == "" {
		return nil
	}
	dc := e.directConn(peer)
	dc.start()
	deadline := time.Now().Add(punchWaitTimeout)
	for time.Now().Before(deadline) {
		if sess := dc.session(); sess != nil {
			return sess
		}
		select {
		case <-e.stop:
			return nil
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}

func (dc *directConn) start() {
	dc.mu.Lock()
	if dc.state != directNone {
		dc.mu.Unlock()
		return
	}
	dc.state = directAttempting
	dc.mu.Unlock()
	go dc.punch()
}

// session returns the live direct smux session, or nil. If the session was
// found dead it is torn down and a re-punch is scheduled.
func (dc *directConn) session() *smux.Session {
	dc.mu.Lock()
	if dc.state != directUp || dc.sess == nil {
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
	dc.state = directNone
	dc.mu.Unlock()
	if sock != nil {
		sock.Close()
	}
	go dc.start() // schedule re-punch
	return nil
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

	select {
	case dc.cand <- cands:
	default:
	}
	// The peer is punching now: answer immediately instead of waiting out our
	// backoff, or the two sides' punch windows miss each other and every retry
	// fails. start() only runs from directNone, so reset a backoff first.
	//
	// A peer only sends candidates when it has (re)started a punch. If we still
	// hold a directUp session, it is stale — the peer restarted and we missed
	// its PeerGone — so tear it down before re-punching, or we'd never answer
	// the re-punch candidates.
	var staleSess *smux.Session
	var staleSock *net.UDPConn
	dc.mu.Lock()
	if dc.state == directUp {
		staleSess, staleSock = dc.sess, dc.socket
		dc.sess, dc.socket = nil, nil
		dc.state = directNone
	} else if dc.state == directBackoff {
		dc.state = directNone
	}
	dc.mu.Unlock()
	if staleSess != nil {
		staleSess.Close()
	}
	if staleSock != nil {
		staleSock.Close()
	}
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
	dc.sess = sess
	dc.socket = socket
	dc.peerAddr = peerAddr
	dc.state = directUp
	dc.mu.Unlock()
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
	dc.state = directNone
	dc.mu.Unlock()
	if sock != nil {
		sock.Close()
	}
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

	// Bind the punch socket to the egress IP toward the STUN server so the
	// local address we advertise is a concrete, peer-reachable endpoint
	// (same-NAT / same-LAN peers connect over it directly). Falls back to a
	// wildcard bind when the IP cannot be determined.
	socket, err := net.ListenUDP("udp4", bindAddrFor(e.stunAddr))
	if err != nil {
		e.log.Debug("direct punch: udp socket", "peer", pname, "error", err)
		dc.backoff()
		return
	}
	keep := false
	defer func() {
		if !keep {
			socket.Close() // idempotent: the kcp session may own the socket
		}
	}()

	e.log.Debug("direct punch: start", "peer", pname)

	// 1. Learn our own public endpoint from the same socket we'll punch with,
	// so the NAT mapping is identical.
	ctx, cancel := context.WithTimeout(context.Background(), stunTimeout)
	pubEP, err := stun.Lookup(ctx, e.stunAddr, socket)
	cancel()
	if err != nil {
		e.log.Debug("direct punch: stun failed", "peer", pname, "error", err)
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: stun ok", "peer", pname, "public", pubEP.String())

	// 2. Advertise our endpoints to the peer: the local socket address first
	// (directly reachable when the peers share a network — same NAT/LAN
	// hairpin), then the STUN public mapping for cross-NAT.
	localEP := socket.LocalAddr().(*net.UDPAddr).AddrPort()
	mine := []candidate{{addr: localEP}, {addr: pubEP}}
	if len(mine) == 2 && mine[0].addr == mine[1].addr {
		mine = mine[:1] // no NAT: local == public
	}
	// Remember our candidates so onCandidates can answer a peer that missed this
	// broadcast (it started its punch late or reconnected to the relay).
	dc.mu.Lock()
	dc.mine = mine
	dc.mu.Unlock()
	if err := e.sendCandidates(dc.peer, mine); err != nil {
		e.log.Debug("direct punch: send candidates failed", "peer", pname, "error", err)
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: candidates sent", "peer", pname, "candidates", candAddrs(mine))

	// 3. Wait for the peer's candidates (exchanged over the relay control
	// channel, so this works even while no UDP path exists yet).
	ctx, cancel = context.WithTimeout(context.Background(), punchTimeout)
	defer cancel()
	cands, ok := dc.waitCandidates(ctx)
	if !ok {
		e.log.Debug("direct punch: no peer candidates", "peer", pname)
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: peer candidates", "peer", pname, "candidates", candAddrs(cands))
	peerAddrs := ipv4Addrs(cands)
	if len(peerAddrs) == 0 {
		e.log.Debug("direct punch: no ipv4 candidate", "peer", pname, "candidates", candAddrs(cands))
		dc.backoff()
		return
	}

	// 4. Mutual dial: both peers build their KCP session with the same conv.
	// Only ONE candidate is dialed per side — kcp-go spawns one readLoop per
	// client session, so two sessions on one socket would steal each other's
	// packets. Same NAT (hairpin) dials the peer's local address, otherwise
	// its public one; the rule is symmetric, so both sides agree.
	dial := peerAddrs[len(peerAddrs)-1] // default: public (cross-NAT)
	if len(peerAddrs) > 1 && pubEP.Addr() == dial.Addr() {
		dial = peerAddrs[0] // same NAT: local (hairpin)
	}
	u := net.UDPAddrFromAddrPort(dial)
	e.log.Debug("direct punch: dial", "peer", pname, "addr", u.String(), "conv", dc.conv())
	// ownConn=true: Close closes the socket, so session death tears down the
	// readLoop with no separate bookkeeping (kcp-go deep-dive R2).
	kcpConn, err := kcp.NewConn4(dc.conv(), u, nil, 0, 0, true, socket)
	if err != nil {
		e.log.Debug("direct punch: dial failed", "peer", pname, "addr", u.String(), "error", err)
		dc.backoff()
		return
	}
	if err := seedHandshake(kcpConn, seedTimeout); err != nil {
		kcpConn.Close()
		e.log.Debug("direct punch: seed failed", "peer", pname, "addr", u.String(), "error", err)
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: seed ok", "peer", pname, "peerAddr", dial.String())

	// 5. smux over KCP; role by key order (external to who dialed).
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = smuxKeepAliveInterval
	cfg.KeepAliveTimeout = smuxKeepAliveTimeout
	var sess *smux.Session
	if roleIsClient {
		sess, err = smux.Client(kcpConn, cfg)
	} else {
		sess, err = smux.Server(kcpConn, cfg)
	}
	if err != nil {
		kcpConn.Close()
		e.log.Debug("direct punch: smux failed", "peer", pname, "error", err)
		dc.backoff()
		return
	}

	dc.markUp(sess, socket, dial)
	keep = true

	e.log.Debug("direct established", "peer", pname,
		"local", mine[0].addr.String(), "public", pubEP.String(), "peerAddr", dial.String())
	go func() {
		e.acceptLoop(sess, "direct", dc.peer, dial.String())
		dc.markDead(sess)
	}()
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

// sendCandidates seals our candidate list to the peer and ships it over the
// relay control channel.
func (e *Engine) sendCandidates(peer derpclient.PublicKey, cands []candidate) error {
	return e.sendControl(peer, ctrlPunchCandidates, e.priv.SealTo(peer, encodeCandidates(cands)))
}

// sendControl sends a control frame ([frameControl][kind][payload]) to peer.
func (e *Engine) sendControl(peer derpclient.PublicKey, kind byte, payload []byte) error {
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

func encodeCandidates(cands []candidate) []byte {
	buf := make([]byte, 0, 1+len(cands)*8)
	buf = append(buf, byte(len(cands)))
	for _, c := range cands {
		buf = append(buf, 4) // family: IPv4
		ip := c.addr.Addr().As4()
		buf = append(buf, ip[:]...)
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
func (e *Engine) acceptLoop(sess *smux.Session, transport string, peer derpclient.PublicKey, peerAddr string) {
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
		// Classification reads the stream's leading bytes, so it runs in the
		// stream's own goroutine: a silent stream must not stall the accept
		// loop (and with it every other stream on the session).
		go e.serveInbound(stream, transport, peer, peerAddr)
	}
}

// serveInbound routes one inbound stream: a stream tagged with the datagram
// channel magic carries the peer's udp channel, anything else is a normal
// tunnel stream bridged to --target.
func (e *Engine) serveInbound(stream net.Conn, transport string, peer derpclient.PublicKey, peerAddr string) {
	if tagged, c := peekTag(stream); tagged {
		ch := e.channel(peer)
		if ch == nil {
			// The local gost has not dialled its endpoint yet (a startup race,
			// not an error): drop the stream and let the opener's backoff retry.
			e.log.Debug("channel stream refused", "transport", transport, "peer", keyName(peer))
			c.Close()
			return
		}
		ch.serveStream(c)
		return
	} else if c != stream {
		stream = c // untagged: replay the bytes consumed by the partial peek
	}

	if e.target == "" {
		e.log.Warn("inbound tunnel refused", "transport", transport, "peer", keyName(peer))
		stream.Close()
		return
	}
	bridgeInbound(stream, transport, keyName(peer), peerAddr, e.target, e.log)
}
