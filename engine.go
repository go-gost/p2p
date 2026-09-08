package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/xtaci/smux"
)

// Engine connects the host to a DERP rendezvous/relay server and turns
// relayed packets into one smux session per peer. The peer address is the
// base64 (raw URL) encoding of its 32-byte curve25519 public key — the same
// string GOST passes to OpenTunnel as "peer".
//
// Data path: every OpenStream on the session is one tunnel; the local
// endpoint listener bridges onto it exactly like the stub bridges onto a
// dialed TCP conn. Both peers keep an accept loop and pipe inbound streams
// to the local --target, so either side can open tunnels.
//
// Session role (smux.Client vs smux.Server) is decided by public-key
// ordering so both ends always agree on exactly one session per pair
// regardless of who dials first. smux allows either side to open streams.
type Engine struct {
	url      string
	target   string      // local bridge target for inbound streams ("" = refuse inbound)
	stunAddr string      // STUN server (host:port); "" disables hole punching
	tlsCfg   *tls.Config // relay TLS options; nil = default verification
	priv     derpclient.PrivateKey
	pub      derpclient.PublicKey
	log      *slog.Logger

	mu      sync.Mutex
	client  *derpclient.Client
	peers   map[derpclient.PublicKey]*peerConn
	directs map[derpclient.PublicKey]*directConn
	gone    map[derpclient.PublicKey]bool // peers reported gone (DERP connection dropped)
	stop    chan struct{}
}

// peerConn is the per-peer packet adapter: smux sees it as a net.Conn, whose
// writes become DERP SendPackets and whose reads drain packets routed by the
// connection pump.
type peerConn struct {
	e       *Engine
	peer    derpclient.PublicKey
	inbound chan []byte

	mu        sync.Mutex
	sess      *smux.Session
	accepting bool
	closed    bool
	closeCh   chan struct{}
	remainder []byte // partially consumed packet from inbound
	current   []byte
}

const (
	// inboundQueueSize bounds queued packets per peer (~256KiB of smux
	// frames); overflowing kills the session rather than silently corrupting
	// the stream.
	inboundQueueSize = 256
	// streamOpenTimeout caps OpenStream (SYN + ack round trip through the
	// relay).
	streamOpenTimeout = 10 * time.Second
	// goneOpenTimeout caps OpenStream to a peer whose DERP connection just
	// dropped; short so a down peer fails fast instead of burning the full
	// stream timeout on every attempt.
	goneOpenTimeout = 3 * time.Second
	// goneProbeTimeout bounds a request to a peer marked gone (DERP only
	// notifies PeerGone once): if no traffic from the peer arrives within the
	// bound the session is torn down so the request fails fast.
	goneProbeTimeout = 5 * time.Second
	// dialTimeout caps the DERP connection establishment.
	dialTimeout = 10 * time.Second
	// keepAlivePeriod pings the DERP server well below typical proxy idle
	// timeouts (e.g. Cloudflare's ~100s).
	keepAlivePeriod = 30 * time.Second
)

func newEngine(url, target string, priv derpclient.PrivateKey, log *slog.Logger) *Engine {
	e := &Engine{
		url:     url,
		target:  target,
		priv:    priv,
		pub:     priv.Public(),
		peers:   make(map[derpclient.PublicKey]*peerConn),
		directs: make(map[derpclient.PublicKey]*directConn),
		gone:    make(map[derpclient.PublicKey]bool),
		log:     log,
		stop:    make(chan struct{}),
	}
	// The host is a rendezvous node: it must be connected to the relay for
	// peers to reach it, and it must recover after the connection drops.
	go e.reconnect()
	return e
}

// reconnect redials the relay whenever there is no live connection. It runs
// for the lifetime of the engine; OpenStream also triggers a dial on demand.
func (e *Engine) reconnect() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-ticker.C:
			e.mu.Lock()
			if e.client == nil {
				e.ensureClientLocked()
			}
			e.mu.Unlock()
		}
	}
}

// Connect dials the relay eagerly (used at startup so inbound tunnels work
// immediately instead of waiting for the reconnect ticker).
func (e *Engine) Connect() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ensureClientLocked()
	if e.client == nil {
		return errors.New("derp engine: connect failed")
	}
	return nil
}

// PublicKey returns the engine's public key, base64 (raw URL) encoded — the
// string other hosts put in their GOST node addr.
func (e *Engine) PublicKey() string {
	return base64.RawURLEncoding.EncodeToString(e.pub[:])
}

// OpenStream opens a tunnel stream to the peer, establishing the DERP
// connection and mux session on first use. An established direct (hole-punched)
// session is preferred; on any failure it falls back to the relay session. The
// returned connection is tagged with the transport it uses ("direct" or
// "derp") so the caller can log which path the tunnel took.
func (e *Engine) OpenStream(peerB64 string) (net.Conn, error) {
	peer, err := parsePeerKey(peerB64)
	if err != nil {
		return nil, err
	}
	if dc := e.getDirect(peer); dc != nil {
		if sess := dc.session(); sess != nil {
			if c, err := openStream(sess, streamOpenTimeout); err == nil {
				return &openedStream{Conn: c, transport: "direct"}, nil
			}
		}
	}

	pc := e.peerConn(peer)
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return nil, errors.New("derp engine: peer session closed")
	}
	sess, err := pc.ensureSessionLocked()
	pc.mu.Unlock()
	if err != nil {
		return nil, err
	}
	// A peer whose DERP connection just dropped gets a short window so opens
	// fail quickly instead of burning the full stream timeout per attempt.
	// The gone mark is sticky: only a packet from the peer (pump) clears it.
	wasGone := e.isGone(peer)
	to := streamOpenTimeout
	if wasGone {
		to = goneOpenTimeout
	}
	c, err := openStream(sess, to)
	if err != nil {
		return nil, fmt.Errorf("derp engine: open stream to %s: %w", peerB64, err)
	}
	if wasGone {
		// Bound the probe: smux opens are fire-and-forget, so a request to a
		// still-down peer would otherwise hang until the smux keepalive. If no
		// peer traffic cleared the gone mark by the bound, kill this session so
		// the request fails fast.
		go func() {
			time.Sleep(goneProbeTimeout)
			if e.isGone(peer) {
				pc.kill(errors.New("derp engine: peer gone probe timeout"))
			}
		}()
	}
	return &openedStream{Conn: c, transport: "derp"}, nil
}

// openedStream is a tunnel stream tagged with the transport it uses, so the
// opening side can log whether the tunnel rode the direct path or the relay.
type openedStream struct {
	net.Conn
	transport string
}

// Transport returns the path this stream used: "direct" or "derp".
func (c *openedStream) Transport() string { return c.transport }

// openStream opens a smux stream bounded by timeout (smux.OpenStream has no
// context form; bound it externally).
func openStream(sess *smux.Session, timeout time.Duration) (net.Conn, error) {
	type openResult struct {
		c   net.Conn
		err error
	}
	ch := make(chan openResult, 1)
	go func() {
		s, err := sess.OpenStream()
		ch <- openResult{s, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// peerConn returns (creating if needed) the adapter for peer, dialing the
// DERP server and starting the pump on first use. A cached adapter that was
// closed (e.g. the peer process died and its relay session broke) is replaced
// with a fresh one so the next stream rebuilds instead of failing forever.
func (e *Engine) peerConn(peer derpclient.PublicKey) *peerConn {
	e.mu.Lock()
	defer e.mu.Unlock()
	if pc, ok := e.peers[peer]; ok {
		pc.mu.Lock()
		closed := pc.closed
		pc.mu.Unlock()
		if !closed {
			return pc
		}
		delete(e.peers, peer) // drop the dead adapter
	}
	e.ensureClientLocked()
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, inboundQueueSize),
		closeCh: make(chan struct{}),
	}
	e.peers[peer] = pc
	return pc
}

// ensureClientLocked dials the DERP server and starts the pump + keepalive
// goroutines. Caller must hold e.mu.
func (e *Engine) ensureClientLocked() {
	if e.client != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	c, err := derpclient.Dial(ctx, e.url, e.priv, e.tlsCfg)
	if err != nil {
		e.log.Error("derp dial", "url", e.url, "error", err)
		return
	}
	e.client = c
	e.log.Debug("derp connected", "url", e.url, "server", keyName(c.ServerPublicKey()))
	go e.pump(c)
	go e.keepalive(c)
}

// pump routes inbound packets to the owning peer adapter; a transport error
// tears down the connection and all sessions (the next OpenStream redials).
func (e *Engine) pump(c *derpclient.Client) {
	for {
		src, pkt, err := c.Recv()
		if errors.Is(err, derpclient.ErrPeerGone) {
			e.peerGone(src)
			continue
		}
		if err != nil {
			e.teardown(c, err)
			return
		}
		// A packet from the peer proves it is reachable again.
		e.clearGone(src)
		e.mu.Lock()
		stale := e.client != c
		e.mu.Unlock()
		if stale {
			// A teardown replaced this connection while Recv was holding a
			// packet; routing it into the new session would corrupt it.
			return
		}
		if len(pkt) == 0 {
			continue
		}
		if pkt[0] == frameControl {
			e.handleControl(src, pkt[1:])
			continue
		}
		if pkt[0] != frameData {
			continue // unknown frame type: drop (forward compatibility)
		}
		pkt = pkt[1:]

		e.mu.Lock()
		pc := e.peers[src]
		e.mu.Unlock()
		if pc == nil {
			// Packets from unknown peers: create the adapter so an inbound
			// tunnel (the other side opening a stream) can be served.
			pc = e.peerConn(src)
		}
		// Ensure a session exists on this side too: inbound packets must be
		// consumed by smux (which then accepts streams) even when this host
		// never opens a tunnel to the peer itself.
		if _, err := pc.ensureSessionLocked(); err != nil {
			pc.kill(err)
			continue
		}
		select {
		case pc.inbound <- pkt:
		case <-pc.closeCh:
			// session already dead; drop
		default:
			// Queue overflow: the session is unrecoverable (smux needs
			// lossless delivery) — kill it and let the peer redial.
			pc.kill(errors.New("derp engine: inbound queue overflow"))
		}
	}
}

// handleControl dispatches a control frame ([kind 1B][payload]) received from
// src. The source key is relay-authenticated; candidate payloads are
// additionally sealed to the peer so a malicious relay cannot inject them.
func (e *Engine) handleControl(src derpclient.PublicKey, body []byte) {
	if len(body) < 1 {
		return
	}
	switch body[0] {
	case ctrlPunchCandidates:
		clear, ok := e.priv.OpenFrom(src, body[1:])
		if !ok {
			e.log.Debug("direct punch: bad candidate box", "peer", keyName(src))
			return
		}
		cands, err := decodeCandidates(clear)
		if err != nil {
			e.log.Debug("direct punch: bad candidate payload", "peer", keyName(src), "error", err)
			return
		}
		e.directConn(src).onCandidates(cands)
	}
}

// keepalive keeps the DERP connection alive through proxy/CDN idle timeouts.
func (e *Engine) keepalive(c *derpclient.Client) {
	ticker := time.NewTicker(keepAlivePeriod)
	defer ticker.Stop()
	for range ticker.C {
		if err := c.KeepAlive(); err != nil {
			e.teardown(c, err)
			return
		}
	}
}

// peerGone drops everything to a peer whose DERP connection just closed (the
// DERP server told us). Subsequent streams rebuild against a fresh session, and
// opens use a short timeout until the peer is reachable again.
func (e *Engine) peerGone(peer derpclient.PublicKey) {
	e.mu.Lock()
	e.gone[peer] = true
	pc := e.peers[peer]
	delete(e.peers, peer)
	dc := e.directs[peer]
	delete(e.directs, peer)
	e.mu.Unlock()
	if pc != nil {
		pc.kill(errors.New("derp engine: peer gone"))
	}
	if dc != nil {
		dc.teardown()
	}
	e.log.Debug("derp peer gone", "peer", keyName(peer))
}

func (e *Engine) isGone(peer derpclient.PublicKey) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gone[peer]
}

func (e *Engine) clearGone(peer derpclient.PublicKey) {
	e.mu.Lock()
	delete(e.gone, peer)
	e.mu.Unlock()
}

// teardown drops the transport and every session built on it.
func (e *Engine) teardown(c *derpclient.Client, cause error) {
	e.mu.Lock()
	if e.client != c {
		e.mu.Unlock()
		return
	}
	e.client = nil
	peers := make([]*peerConn, 0, len(e.peers))
	for _, pc := range e.peers {
		peers = append(peers, pc)
	}
	e.peers = make(map[derpclient.PublicKey]*peerConn)
	e.mu.Unlock()
	e.log.Error("derp connection lost", "error", cause)
	c.Close()
	for _, pc := range peers {
		pc.kill(cause)
	}
}

// Close shuts the engine down.
func (e *Engine) Close() {
	e.mu.Lock()
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
	c := e.client
	e.client = nil
	peers := make([]*peerConn, 0, len(e.peers))
	for _, pc := range e.peers {
		peers = append(peers, pc)
	}
	e.peers = make(map[derpclient.PublicKey]*peerConn)
	directs := make([]*directConn, 0, len(e.directs))
	for _, dc := range e.directs {
		directs = append(directs, dc)
	}
	e.directs = make(map[derpclient.PublicKey]*directConn)
	e.mu.Unlock()
	for _, pc := range peers {
		pc.kill(errors.New("engine closed"))
	}
	for _, dc := range directs {
		dc.teardown()
	}
	if c != nil {
		c.Close()
	}
}

// ensureSessionLocked creates the mux session if needed. The role is fixed
// by public-key ordering so both ends converge on one session per pair.
// Caller must hold pc.mu.
func (pc *peerConn) ensureSessionLocked() (*smux.Session, error) {
	if pc.sess != nil && pc.sess.IsClosed() {
		pc.sess = nil
	}
	if pc.sess != nil {
		return pc.sess, nil
	}
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	roleIsClient := bytes.Compare(pc.e.pub[:], pc.peer[:]) < 0
	if roleIsClient {
		pc.sess, _ = smux.Client(pc, cfg)
	} else {
		pc.sess, _ = smux.Server(pc, cfg)
	}
	if pc.sess == nil {
		return nil, errors.New("derp engine: cannot establish mux session")
	}
	pc.startAccept()
	// Kick off hole punching in the background now that the relay session
	// exists (idempotent; a no-op when direct is already up or attempting).
	pc.e.maybeStartDirect(pc.peer)
	return pc.sess, nil
}

// startAccept launches the inbound stream loop (once per relay session).
func (pc *peerConn) startAccept() {
	if pc.accepting {
		return
	}
	pc.accepting = true
	go func() {
		defer func() {
			pc.mu.Lock()
			pc.accepting = false
			pc.mu.Unlock()
		}()
		pc.e.acceptLoop(pc.sess, "derp", keyName(pc.peer))
	}()
}

// kill marks the adapter dead and tears down its session. Safe for
// concurrent use and for already-dead adapters.
func (pc *peerConn) kill(cause error) {
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return
	}
	pc.closed = true
	close(pc.closeCh)
	sess := pc.sess
	pc.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
	pc.e.log.Debug("peer session killed", "peer", keyName(pc.peer), "cause", cause)
}

// Read implements net.Conn: drain queued packets, honoring partial reads.
func (pc *peerConn) Read(p []byte) (int, error) {
	for {
		if len(pc.remainder) > 0 {
			n := copy(p, pc.remainder)
			pc.remainder = pc.remainder[n:]
			return n, nil
		}
		if len(pc.current) > 0 {
			n := copy(p, pc.current)
			pc.current = pc.current[n:]
			return n, nil
		}
		select {
		case pkt := <-pc.inbound:
			pc.current = pkt
		case <-pc.closeCh:
			// drain remaining queued packets before reporting EOF
			select {
			case pkt := <-pc.inbound:
				pc.current = pkt
			default:
				return 0, io.EOF
			}
		}
	}
}

// Write implements net.Conn: each write is one DERP SendPacket.
func (pc *peerConn) Write(p []byte) (int, error) {
	pc.mu.Lock()
	closed := pc.closed
	pc.mu.Unlock()
	if closed {
		return 0, errors.New("derp engine: peer session closed")
	}
	e := pc.e
	e.mu.Lock()
	c := e.client
	e.mu.Unlock()
	if c == nil {
		return 0, errors.New("derp engine: no connection")
	}
	// Prefix a data-frame type byte so the peer's pump can distinguish smux
	// data from control frames.
	buf := make([]byte, 0, len(p)+1)
	buf = append(buf, frameData)
	buf = append(buf, p...)
	if err := c.SendPacket(pc.peer, buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements net.Conn: closing the adapter kills the session (streams
// and all). It does not touch the shared DERP transport.
func (pc *peerConn) Close() error {
	pc.kill(errors.New("adapter closed"))
	return nil
}

func (pc *peerConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (pc *peerConn) RemoteAddr() net.Addr               { return dummyAddr{pc.peer} }
func (pc *peerConn) SetDeadline(t time.Time) error      { return nil }
func (pc *peerConn) SetReadDeadline(t time.Time) error  { return nil }
func (pc *peerConn) SetWriteDeadline(t time.Time) error { return nil }

// dummyAddr is a placeholder net.Addr for the adapter.
type dummyAddr struct{ peer any }

func (dummyAddr) Network() string { return "derp" }
func (a dummyAddr) String() string {
	if p, ok := a.peer.(derpclient.PublicKey); ok {
		return "derp:" + base64.RawURLEncoding.EncodeToString(p[:])
	}
	return "derp"
}

// bridgeInbound pipes an inbound tunnel stream to the local target with the
// same half-close semantics as the stub bridge, logging connect/disconnect in
// gost style ("<peer> <-> <target>", ">-<" + duration on close).
func bridgeInbound(stream net.Conn, transport, peer, target string, log *slog.Logger) {
	defer stream.Close()
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Debug("inbound bridge dial failed", "transport", transport, "peer", peer, "target", target, "error", err)
		return
	}
	defer up.Close()

	// peer is the remote p2p host key, endpoint the local service the stream
	// is bridged to (the --target).
	start := time.Now()
	log.Info(fmt.Sprintf("%s <-> %s", peer, target),
		"transport", transport, "peer", peer, "endpoint", target)
	defer func() {
		log.Info(fmt.Sprintf("%s >-< %s", peer, target),
			"transport", transport, "peer", peer, "endpoint", target,
			"duration", time.Since(start).String())
	}()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, stream)
		halfCloseWrite(up)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(stream, up)
		halfCloseWrite(stream)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// parsePeerKey decodes a peer address (base64 raw URL of a 32-byte public
// key) and validates its shape.
func parsePeerKey(s string) (derpclient.PublicKey, error) {
	var p derpclient.PublicKey
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return p, fmt.Errorf("derp engine: peer %q is not a valid base64 key", s)
	}
	if len(b) != 32 {
		return p, fmt.Errorf("derp engine: peer %q is not a 32-byte key", s)
	}
	copy(p[:], b)
	return p, nil
}

// keyName is the base64 (raw URL) form of a public key used in logs, matching
// the peer address GOST passes to OpenTunnel.
func keyName(k derpclient.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(k[:])
}
