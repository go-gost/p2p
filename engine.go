package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"
	"p2p/internal/derpclient"
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
	url    string
	target string // local bridge target for inbound streams ("" = refuse inbound)
	priv   derpclient.PrivateKey
	pub    derpclient.PublicKey
	log    *slog.Logger

	// services are the names this host announces to connected peers; empty
	// means a pure dialing host that never announces.
	services []string
	// announcePeriod is the name-announcement interval (shortened in tests).
	announcePeriod time.Duration

	mu     sync.Mutex
	client *derpclient.Client
	peers  map[derpclient.PublicKey]*peerConn
	// online tracks peers present on the current DERP connection; it is the
	// announcement target set and is repopulated on every reconnect.
	online map[derpclient.PublicKey]time.Time
	// svc caches service-name -> announcing key (newest wins per name), with
	// a TTL backstop for peers that vanish without a PeerGone.
	svc  map[string]svcEnt
	stop chan struct{}
}

// svcEnt is one cached service name: the announcing peer's key and when the
// last announcement refreshed it.
type svcEnt struct {
	key      derpclient.PublicKey
	lastSeen time.Time
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
	// dialTimeout caps the DERP connection establishment.
	dialTimeout = 10 * time.Second
	// keepAlivePeriod pings the DERP server well below typical proxy idle
	// timeouts (e.g. Cloudflare's ~100s).
	keepAlivePeriod = 30 * time.Second
	// defaultAnnouncePeriod is the interval between name announcements to
	// every online peer; per-peer instantaneous announcements fire on new
	// presence, so this is only the backstop cadence.
	defaultAnnouncePeriod = 15 * time.Second
	// svcEntryTTL evicts cached names that stop being announced (silent peer
	// disappearance or a partition where PeerGone never arrives).
	svcEntryTTL = 60 * time.Second
	// maxNameLen bounds a service name in an announce frame. It is a protocol
	// sanity bound, NOT a collision safeguard: key/name precedence in
	// OpenTunnel's peer string already makes parsing unambiguous (see the
	// discovery plan's boundary notes).
	maxNameLen = 64
)

// Application-layer framing above DERP: every relayed packet starts with a
// type byte the receiving pump dispatches on before session routing. Session
// data is the smux byte stream under type 0x01; type 0x00 carries engine
// control frames (name announcements), which never enter the mux session.
const (
	frameTypeControl = 0x00
	frameTypeData    = 0x01

	kindAnnounce = 0x01 // name-announce: [0x00][kind][name bytes]
	// kind 0x02 reserved for M2 address candidates — not implemented.
)

func newEngine(url, target string, priv derpclient.PrivateKey, services []string, log *slog.Logger) *Engine {
	e := &Engine{
		url:            url,
		target:         target,
		priv:           priv,
		pub:            priv.Public(),
		services:       services,
		peers:          make(map[derpclient.PublicKey]*peerConn),
		online:         make(map[derpclient.PublicKey]time.Time),
		svc:            make(map[string]svcEnt),
		log:            log,
		stop:           make(chan struct{}),
		announcePeriod: defaultAnnouncePeriod,
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
// connection and mux session on first use.
func (e *Engine) OpenStream(peerB64 string) (net.Conn, error) {
	peer, err := parsePeerKey(peerB64)
	if err != nil {
		return nil, err
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
	// smux.OpenStream has no context form; bound it externally.
	type openResult struct {
		c   net.Conn
		err error
	}
	ch := make(chan openResult, 1)
	go func() {
		s, err := sess.OpenStream()
		ch <- openResult{s, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), streamOpenTimeout)
	defer cancel()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("derp engine: open stream to %s: %w", peerB64, ctx.Err())
	}
}

// peerConn returns (creating if needed) the adapter for peer, dialing the
// DERP server and starting the pump on first use.
func (e *Engine) peerConn(peer derpclient.PublicKey) *peerConn {
	e.mu.Lock()
	defer e.mu.Unlock()
	pc, ok := e.peers[peer]
	if !ok {
		e.ensureClientLocked()
		pc = &peerConn{
			e:       e,
			peer:    peer,
			inbound: make(chan []byte, inboundQueueSize),
			closeCh: make(chan struct{}),
		}
		e.peers[peer] = pc
	}
	return pc
}

// ensureClientLocked dials the DERP server and starts the pump, keepalive,
// presence, and announce goroutines. Caller must hold e.mu. Each connect
// gets its own presence/announcer bound to this client: when the connection
// dies, its presence channel closes (ending the goroutine) and the announcer
// notices on the next tick.
func (e *Engine) ensureClientLocked() {
	if e.client != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	c, err := derpclient.Dial(ctx, e.url, e.priv, nil)
	if err != nil {
		e.log.Error("derp dial", "url", e.url, "error", err)
		return
	}
	e.client = c
	e.log.Debug("derp connected", "url", e.url, "server", c.ServerPublicKey())
	go e.pump(c)
	go e.keepalive(c)
	go e.runPresence(c)
	go e.runAnnouncer(c)
}

// pump routes inbound packets: control frames are dispatched by our
// application-layer type byte (never entering a session), while session data
// gets its type byte stripped once and routed to the owning peer adapter; a
// transport error tears down the connection and all sessions (the next
// OpenStream redials).
func (e *Engine) pump(c *derpclient.Client) {
	for {
		src, pkt, err := c.Recv()
		if err != nil {
			e.teardown(c, err)
			return
		}
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
		switch pkt[0] {
		case frameTypeControl:
			e.handleControl(src, pkt[1:])
			continue
		case frameTypeData:
			pkt = pkt[1:] // strip once; peerConn.Read never re-strips
		default:
			// Unknown application frame type: drop (forward compatibility).
			continue
		}

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

// runPresence folds PeerPresent/PeerGone events into the online set and the
// service cache, and announces this host's services to a newly-present peer
// for low-latency discovery. It lives for one DERP connection: the client's
// Presence channel is closed on disconnect, ending this range.
func (e *Engine) runPresence(c *derpclient.Client) {
	for ev := range c.Presence() {
		e.mu.Lock()
		if ev.Present {
			e.online[ev.Key] = time.Now()
		} else {
			delete(e.online, ev.Key)
			for name, ent := range e.svc {
				if ent.key == ev.Key {
					delete(e.svc, name)
				}
			}
		}
		e.mu.Unlock()
		if ev.Present {
			e.announceOn(c, []derpclient.PublicKey{ev.Key})
		}
	}
}

// runAnnouncer re-announces this host's services to every online peer each
// tick. It is per-connection; once the connection is replaced or closed the
// stale check on the next tick ends it.
func (e *Engine) runAnnouncer(c *derpclient.Client) {
	t := time.NewTicker(e.announcePeriod)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			e.mu.Lock()
			if e.client != c {
				e.mu.Unlock()
				return
			}
			keys := make([]derpclient.PublicKey, 0, len(e.online))
			for k := range e.online {
				keys = append(keys, k)
			}
			e.mu.Unlock()
			e.announceOn(c, keys)
		}
	}
}

// announceOn sends this host's current service set to each key via c. The
// key list and service snapshot are taken under e.mu; SendPacket runs
// outside the lock. Announcements carry no auth: any peer can announce any
// name on an open relay — the inner dialer is the real gate.
func (e *Engine) announceOn(c *derpclient.Client, keys []derpclient.PublicKey) {
	if c == nil || len(keys) == 0 {
		return
	}
	e.mu.Lock()
	if e.client != c {
		e.mu.Unlock()
		return // connection already replaced; this goroutine is stale
	}
	services := append([]string(nil), e.services...)
	e.mu.Unlock()
	if len(services) == 0 {
		return
	}
	for _, k := range keys {
		for _, name := range services {
			if err := c.SendPacket(k, announcePacket(name)); err != nil {
				e.log.Debug("announce",
					"peer", base64.RawURLEncoding.EncodeToString(k[:]),
					"name", name, "error", err)
			}
		}
	}
}

// announcePacket frames a name-announce control packet for a peer.
func announcePacket(name string) []byte {
	return append([]byte{frameTypeControl, kindAnnounce}, name...)
}

// handleControl processes an engine control frame from src. Only the
// announce kind is defined; reserved kinds (M2 address candidates) and empty
// or oversized names are ignored.
func (e *Engine) handleControl(src derpclient.PublicKey, body []byte) {
	if len(body) < 2 || body[0] != kindAnnounce {
		return
	}
	name := body[1:]
	if len(name) == 0 || len(name) > maxNameLen {
		return
	}
	e.mu.Lock()
	e.svc[string(name)] = svcEnt{key: src, lastSeen: time.Now()}
	e.mu.Unlock()
}

// Lookup resolves a service name to the announcing peer's public key if a
// recent announcement is on record. Entries older than svcEntryTTL (≈4
// announce ticks) expire even without a PeerGone to bound staleness after
// partition or derper restart.
func (e *Engine) Lookup(name string) (derpclient.PublicKey, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.svc[name]
	if !ok {
		return derpclient.PublicKey{}, false
	}
	if time.Since(ent.lastSeen) > svcEntryTTL {
		delete(e.svc, name)
		return derpclient.PublicKey{}, false
	}
	return ent.key, true
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
	// The connection is gone: every online peer and cached name on it is
	// stale; they are re-learned after the redial.
	e.online = make(map[derpclient.PublicKey]time.Time)
	e.svc = make(map[string]svcEnt)
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
	e.online = make(map[derpclient.PublicKey]time.Time)
	e.svc = make(map[string]svcEnt)
	e.mu.Unlock()
	for _, pc := range peers {
		pc.kill(errors.New("engine closed"))
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
	return pc.sess, nil
}

// startAccept launches the inbound stream loop (once per session).
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
		for {
			stream, err := pc.sess.AcceptStream()
			if err != nil {
				return // session dead
			}
			if pc.e.target == "" {
				pc.e.log.Warn("inbound tunnel refused: --target not configured")
				stream.Close()
				continue
			}
			go bridgeInbound(stream, pc.e.target, pc.e.log)
		}
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
	pc.e.log.Debug("peer session killed", "peer", pc.peer, "cause", cause)
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

// Write implements net.Conn: each write is one DERP SendPacket carrying the
// session-data type byte so the receiving pump can route it past control
// frames.
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
	pkt := make([]byte, 0, len(p)+1)
	pkt = append(pkt, frameTypeData)
	pkt = append(pkt, p...)
	if err := c.SendPacket(pc.peer, pkt); err != nil {
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
// same half-close semantics as the stub bridge.
func bridgeInbound(stream net.Conn, target string, log *slog.Logger) {
	defer stream.Close()
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Debug("inbound bridge dial failed", "target", target, "error", err)
		return
	}
	defer up.Close()

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
