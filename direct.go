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

	"p2p/internal/derpclient"
	"p2p/internal/stun"
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
	punchTimeout  = 10 * time.Second
	backoffPeriod = 30 * time.Second
	stunTimeout   = 3 * time.Second
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
	select {
	case dc.cand <- cands:
	default:
	}
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
	go func() {
		select {
		case <-dc.e.stop:
			return
		case <-time.After(backoffPeriod):
		}
		dc.mu.Lock()
		dc.state = directNone
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

	// Drain any stale candidate left by a previous attempt.
	select {
	case <-dc.cand:
	default:
	}

	socket, err := net.ListenUDP("udp4", nil)
	if err != nil {
		dc.backoff()
		return
	}
	keepSocket := false
	defer func() {
		if !keepSocket {
			socket.Close()
		}
	}()

	// 1. Learn our own public endpoint from the same socket we'll punch with,
	// so the NAT mapping is identical.
	ctx, cancel := context.WithTimeout(context.Background(), stunTimeout)
	pubEP, err := stun.Lookup(ctx, e.stunAddr, socket)
	cancel()
	if err != nil {
		e.log.Debug("direct punch: stun", "peer", dc.peer, "error", err)
		dc.backoff()
		return
	}

	// 2. Advertise our public endpoint to the peer. (A local candidate would
	// serve same-NAT hairpin; M2 punches via the public endpoint only.)
	if err := e.sendCandidates(dc.peer, []candidate{{addr: pubEP}}); err != nil {
		dc.backoff()
		return
	}

	// 3. Wait for the peer's candidates.
	ctx, cancel = context.WithTimeout(context.Background(), punchTimeout)
	defer cancel()
	cands, ok := dc.waitCandidates(ctx)
	if !ok {
		e.log.Debug("direct punch: no candidates", "peer", dc.peer)
		dc.backoff()
		return
	}
	peerEP, ok := firstIPv4(cands)
	if !ok {
		dc.backoff()
		return
	}
	peerUDP := net.UDPAddrFromAddrPort(peerEP)

	// 4. Build the KCP session on the shared socket. KCP sends nothing until
	// there is data, so both sides run a priming round-trip below to force the
	// first packets out and confirm the path end-to-end.
	var kcpConn net.Conn
	if roleIsClient {
		kcpConn, err = kcp.NewConn3(dc.conv(), peerUDP, nil, 0, 0, socket)
		if err == nil {
			err = primeKCP(kcpConn, punchTimeout) // triggers SYN, waits for echo
		}
	} else {
		kcpConn, err = dc.kcpAccept(socket, peerUDP) // AcceptKCP + echo priming byte
	}
	if err != nil {
		if kcpConn != nil {
			kcpConn.Close()
		}
		dc.backoff()
		return
	}

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
		dc.backoff()
		return
	}

	dc.markUp(sess, socket)
	keepSocket = true

	e.log.Debug("direct established", "peer", dc.peer)
	go e.acceptLoop(sess)
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
// periodic dummy probe to the peer's candidate to open our NAT mapping so the
// client's SYN can get through (the dummy is dropped by the peer's KCP input).
// It echoes the client's priming byte back to confirm the path.
func (dc *directConn) kcpAccept(socket *net.UDPConn, peer *net.UDPAddr) (net.Conn, error) {
	l, err := kcp.ServeConn(nil, 0, 0, socket)
	if err != nil {
		return nil, err
	}
	stopDummy := make(chan struct{})
	go dc.dummyProbe(socket, peer, stopDummy)
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

func (dc *directConn) dummyProbe(socket *net.UDPConn, peer *net.UDPAddr, stop <-chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	dummy := []byte{0, 0, 0, 0}
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			socket.WriteToUDP(dummy, peer)
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

func firstIPv4(cands []candidate) (netip.AddrPort, bool) {
	for _, c := range cands {
		if c.addr.Addr().Is4() {
			return c.addr, true
		}
	}
	return netip.AddrPort{}, false
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
// by the relay and direct sessions.
func (e *Engine) acceptLoop(sess *smux.Session) {
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return // session dead
		}
		if e.target == "" {
			e.log.Warn("inbound tunnel refused: --target not configured")
			stream.Close()
			continue
		}
		go bridgeInbound(stream, e.target, e.log)
	}
}
