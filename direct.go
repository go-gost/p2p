package main

import (
	"bytes"
	"context"
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
// the relay's control channel, and build a KCP session over a shared UDP
// socket. When that succeeds, new streams prefer the direct smux session while
// the relay session stays up as fallback.
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
	punchTimeout     = 10 * time.Second
	backoffPeriod    = 30 * time.Second
	stunTimeout      = 3 * time.Second
	candidateTimeout = 3 * time.Second // per-candidate KCP priming attempt (client dials)
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

	mu     sync.Mutex
	state  directState
	sess   *smux.Session // direct smux session when up
	socket *net.UDPConn  // punch socket; owned by us (kcp sets ownConn=false)
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
	dc.e.log.Debug("direct punch: peer candidates via relay", "peer", keyName(dc.peer), "candidates", candAddrs(cands))
	select {
	case dc.cand <- cands:
	default:
	}
	// The peer is punching now: answer immediately instead of waiting out our
	// backoff, or the two sides' punch windows miss each other and every retry
	// fails. start() only runs from directNone, so reset a backoff first.
	dc.mu.Lock()
	if dc.state == directBackoff {
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
func (dc *directConn) markUp(sess *smux.Session, socket *net.UDPConn) {
	dc.mu.Lock()
	dc.sess = sess
	dc.socket = socket
	dc.state = directUp
	dc.mu.Unlock()
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
	roleIsClient := bytes.Compare(e.pub[:], dc.peer[:]) < 0
	role := "server"
	if roleIsClient {
		role = "client"
	}
	pname := keyName(dc.peer)

	// Drain any stale candidate left by a previous attempt.
	select {
	case <-dc.cand:
	default:
	}

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
	keepSocket := false
	defer func() {
		if !keepSocket {
			socket.Close()
		}
	}()

	e.log.Debug("direct punch: start", "peer", pname, "role", role)

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
	if err := e.sendCandidates(dc.peer, mine); err != nil {
		e.log.Debug("direct punch: send candidates failed", "peer", pname, "error", err)
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: candidates sent", "peer", pname, "candidates", candAddrs(mine))

	// 3. Wait for the peer's candidates, then dial/accept them in the order
	// offered (its local address first, public second).
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

	// 4. Build the KCP session on the shared socket. KCP sends nothing until
	// there is data, so the client runs a priming round-trip per candidate
	// (triggers SYN, waits for echo) and moves to the next on failure.
	var kcpConn net.Conn
	peerEP := peerAddrs[0]
	if roleIsClient {
		for _, ep := range peerAddrs {
			u := net.UDPAddrFromAddrPort(ep)
			e.log.Debug("direct punch: dial", "peer", pname, "addr", u.String(), "conv", dc.conv())
			kcpConn, err = kcp.NewConn3(dc.conv(), u, nil, 0, 0, socket)
			if err == nil {
				err = primeKCP(kcpConn, candidateTimeout)
			}
			if err != nil {
				e.log.Debug("direct punch: dial failed", "peer", pname, "addr", u.String(), "error", err)
				kcpConn.Close()
				continue
			}
			peerEP = ep
			break
		}
		if err != nil {
			e.log.Debug("direct punch: kcp failed", "peer", pname, "error", err)
			dc.backoff()
			return
		}
	} else {
		// Server role: accept any client SYN; the dummy probe opens our NAT
		// toward every peer candidate (its public mapping included) so the
		// client's SYN can get through on the cross-NAT path. Probing only the
		// local candidate would leave the NAT closed to the peer's public
		// address — the hole punch would fail even between cone NATs.
		kcpConn, err = dc.kcpAccept(socket, peerAddrs)
		if err != nil {
			e.log.Debug("direct punch: kcp failed", "peer", pname, "error", err)
			dc.backoff()
			return
		}
	}
	e.log.Debug("direct punch: kcp primed", "peer", pname, "peerAddr", peerEP.String())

	// 5. smux over KCP; role matches the relay session (smaller key is client).
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
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

	dc.markUp(sess, socket)
	keepSocket = true

	e.log.Debug("direct established", "peer", pname, "role", role,
		"local", mine[0].addr.String(), "public", pubEP.String(), "peerAddr", peerEP.String())
	go e.acceptLoop(sess, "direct", pname)
}

// primeKCP writes a single byte and waits for it to be echoed back. KCP does
// not emit anything until data is written, so this both forces the client's
// SYN out and confirms the path is usable before routing tunnels onto it.
func primeKCP(c net.Conn, timeout time.Duration) error {
	c.SetDeadline(time.Now().Add(timeout))
	defer c.SetDeadline(time.Time{}) // clear: the session must outlive priming
	if _, err := c.Write([]byte{0}); err != nil {
		return err
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return err
	}
	return nil
}

// kcpAccept runs the server role: a KCP listener over the socket, plus a
// periodic dummy probe to every peer candidate to open our NAT mapping so the
// client's SYN can get through (the dummy is dropped by the peer's KCP input).
// It echoes the client's priming byte back to confirm the path.
func (dc *directConn) kcpAccept(socket *net.UDPConn, peers []netip.AddrPort) (net.Conn, error) {
	l, err := kcp.ServeConn(nil, 0, 0, socket)
	if err != nil {
		return nil, err
	}
	stopDummy := make(chan struct{})
	go dc.dummyProbe(socket, peers, stopDummy)
	defer close(stopDummy)

	l.SetReadDeadline(time.Now().Add(punchTimeout))
	sess, err := l.AcceptKCP()
	if err != nil {
		l.Close()
		return nil, err
	}
	sess.SetDeadline(time.Now().Add(punchTimeout))
	defer sess.SetDeadline(time.Time{}) // clear: the session must outlive the echo
	var b [1]byte
	if _, err := io.ReadFull(sess, b[:]); err != nil {
		sess.Close()
		return nil, err
	}
	if _, err := sess.Write(b[:]); err != nil {
		sess.Close()
		return nil, err
	}
	return sess, nil
}

func (dc *directConn) dummyProbe(socket *net.UDPConn, peers []netip.AddrPort, stop <-chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	dummy := []byte{0, 0, 0, 0}
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			for _, p := range peers {
				socket.WriteToUDP(dummy, net.UDPAddrFromAddrPort(p))
			}
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

// candAddrs renders candidate endpoints as strings for logs.
func candAddrs(cands []candidate) []string {
	s := make([]string, len(cands))
	for i, c := range cands {
		s[i] = c.addr.String()
	}
	return s
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

// acceptLoop bridges inbound streams on a session to the local target. Shared
// by the relay and direct sessions; transport names the path the stream
// arrived over ("derp" relay or "direct" hole punch).
func (e *Engine) acceptLoop(sess *smux.Session, transport, peer string) {
	start := time.Now()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if transport == "direct" {
				// Direct sessions die when the KCP path drops (e.g. NAT mapping
				// timeout). Log the lifetime + cause to distinguish that from an
				// orderly close.
				e.log.Debug("direct session ended", "peer", peer,
					"duration", time.Since(start).String(), "error", err)
			}
			return // session dead
		}
		if e.target == "" {
			e.log.Warn("inbound tunnel refused", "transport", transport, "peer", peer)
			stream.Close()
			continue
		}
		go bridgeInbound(stream, transport, peer, e.target, e.log)
	}
}
