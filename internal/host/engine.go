package host

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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/xtaci/smux"
)

// engine connects the host to a DERP rendezvous/relay server and turns
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
type engine struct {
	url         string
	targets     *targetPool                            // inbound bridge targets; an empty tcp pool refuses inbound tunnels
	direct      bool                                   // master direct switch (--direct); false = relay-only
	stunAddr    string                                 // STUN server (host:port); "" disables the IPv4 direct path
	v6Addr      *net.UDPAddr                           // explicit IPv6 egress override (tests); nil = probe each round
	v6Available bool                                   // host had a global IPv6 egress at startup (gates direct)
	v6Announce  v6AnnounceFunc                         // test seam: overrides the advertised IPv6 endpoint
	openStream  func(peerB64 string) (net.Conn, error) // test seam: overrides OpenStream for link presentation
	tlsCfg      *tls.Config                            // relay TLS options; nil = default verification
	priv        derpclient.PrivateKey
	pub         derpclient.PublicKey
	log         *slog.Logger

	// inbound is the embedder's inbound-stream queue, set once by
	// Tunnel.Listen (nil = no listener; inbound tunnel streams are bridged to
	// a target instead). An atomic because Listen is callable at any time
	// while the pump goroutines run.
	inbound atomic.Pointer[inboundQueue]

	// faults is the debug-only injection state, set once from the config by
	// host.New. An atomic pointer for the same reason as inbound: it is read on
	// the pump, punch and smux write paths, so it can be handed in without a
	// race against a goroutine already running (tests swap it to open a silence
	// window on demand; nothing in production ever changes it).
	faults atomic.Pointer[faults]

	// stunFailed records whether the last IPv4 candidate collection failed
	// (an unreachable STUN server, or no socket to ask from). It is only
	// meaningful when STUN is configured; Status turns it into the
	// "stun-unreachable" transport reason.
	stunFailed atomic.Bool

	mu      sync.Mutex
	client  *derpclient.Client
	dialErr error // the last dial failure, surfaced by Connect
	peers   map[derpclient.PublicKey]*peerConn
	directs map[derpclient.PublicKey]*directConn
	links   map[derpclient.PublicKey][]*link // per-peer datagram links (one per udp dial)
	gone    map[derpclient.PublicKey]bool    // peers reported gone (DERP connection dropped)
	// secure holds one security session per (peer, transport), keyed so it
	// outlives any one smux session: a rebuilt mux session reuses its keys and
	// nonce counters, and a peer restart is seen as a changed half.
	secure map[secureKey]*secureSession
	stop   chan struct{}

	stats engineStats
}

// engineStats holds the transport counters reported by Status. They are
// cumulative since process start; the fields are safe for concurrent use.
type engineStats struct {
	punchAttempts atomic.Int64 // hole-punch attempts
	punchSuccess  atomic.Int64 // attempts that reached a live direct session
	streamsDirect atomic.Int64 // streams opened over a direct path
	streamsDerp   atomic.Int64 // streams opened over the relay
}

// snapshot returns the counters in StatusReply field order.
func (s *engineStats) snapshot() (punchAttempts, punchSuccess, streamsDirect, streamsDerp int64) {
	return s.punchAttempts.Load(), s.punchSuccess.Load(), s.streamsDirect.Load(), s.streamsDerp.Load()
}

// countStream records one stream opened over the given transport ("direct" or
// "derp").
func (s *engineStats) countStream(transport string) {
	if transport == "direct" {
		s.streamsDirect.Add(1)
		return
	}
	s.streamsDerp.Add(1)
}

// peerTransports names each peer's current path — the value set documented on
// p2p.Status.PeerTransports. A peer is connected through the relay (that is
// what makes it connected); the value says whether it rides a hole-punched
// session instead, and when it does not, the most specific reason available:
// this peer's own punch state first, then the host-wide reason (which is the
// same for every peer). Only peers with a live data path appear, the same set
// peerEncryptions reports. It probes with the side-effect-free
// peerConn.liveSession() and directConn.live() rather than session(): session()
// tears down a dead session and schedules a re-punch, which a status query must
// never do. The engine lock is released before probing, so pc.mu and dc.mu are
// never taken while holding it.
func (e *engine) peerTransports() map[string]string {
	e.mu.Lock()
	directs := make(map[derpclient.PublicKey]*directConn, len(e.directs))
	for k, dc := range e.directs {
		directs[k] = dc
	}
	peers := make([]derpclient.PublicKey, 0, len(e.peers))
	for p := range e.peers {
		peers = append(peers, p)
	}
	e.mu.Unlock()

	reason := e.directReason()
	fallback := transportRelay
	if reason != "" {
		fallback = reason
	}

	// A peer is reported only while it has a live data path (peerLive) — the
	// same set peerEncryptions reports, so a single snapshot cannot report two
	// different peer sets. A killed app sends no PeerGone to an open relay, so
	// its adapter outlives it in these maps and its relay session is noticed
	// dead only by the smux keepalive; without this a peer that is long gone
	// still reads as connected.
	out := make(map[string]string, len(peers)+len(directs))
	for _, p := range peers {
		if !e.peerLive(p) {
			continue // no live data path — the peer is not connected
		}
		out[keyName(p)] = fallback
	}
	for k, dc := range directs {
		if !e.peerLive(k) {
			continue // no live data path — whatever the punch state says
		}
		name := keyName(k)
		switch {
		case dc.live():
			out[name] = transportDirect
		case reason != "":
			// A host-wide cause outranks this peer's own round: when STUN does
			// not answer, "this peer's punch failed" is the symptom, and the
			// reason is what a user would fix.
			out[name] = reason
		case dc.peerDirectOff():
			// The peer told us it will not punch, so no round here can succeed.
			// This outranks "failed" on purpose: the failed word says "punch
			// failed, usually a symmetric NAT", which sends the reader after a
			// NAT problem that is not there. Nothing is broken — the pair is
			// connected, and one end asked for the relay.
			out[name] = transportPeerDirectOff
		case dc.hasFailed():
			// A round failed for this peer. Reported even while a retry is in
			// flight: re-announcements restart rounds often enough that the
			// live state alone would show "punching" forever, which is exactly
			// the state a user cannot act on.
			out[name] = transportFailed
		case dc.stateOf() == directAttempting:
			out[name] = transportPunching
		default:
			// Nothing in flight for this peer and nothing wrong with the host:
			// a punch has simply not been needed yet.
			out[name] = transportRelay
		}
	}
	return out
}

// relayState reports whether the relay holds a live connection, and the last
// dial failure. Status exposes it because no other field can show a relay
// outage: a live direct session keeps every gauge and counter healthy while the
// relay is unreachable.
func (e *engine) relayState() (connected bool, lastErr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dialErr != nil {
		lastErr = e.dialErr.Error()
	}
	return e.client != nil, lastErr
}

// peerDiagnostics snapshots each connected peer. transports is the peer-set
// snapshot peerTransports just computed (its only caller is status()), so it is
// also the peer set here: the same filter, the paths read once per status tick.
// The host-wide reason applies to every peer it outranks — but only on a path
// that is not already direct, matching peerTransports, where a live session
// outranks the reason: a peer that reads Path="direct" must not also carry
// Reason="stun-unreachable". The per-peer fields come from the adapter and the
// punch state machine, read without probing a session.
func (e *engine) peerDiagnostics(transports map[string]string) map[string]p2p.PeerDiagnostic {
	e.mu.Lock()
	peers := make([]*peerConn, 0, len(e.peers))
	for _, pc := range e.peers {
		peers = append(peers, pc)
	}
	directs := make([]*directConn, 0, len(e.directs))
	for _, dc := range e.directs {
		directs = append(directs, dc)
	}
	e.mu.Unlock()

	reason := e.directReason()
	// A live direct session outranks the host-wide reason (peerTransports), so
	// the reason is reported only on the paths that did not go direct.
	reasonFor := func(path string) string {
		if path == transportDirect {
			return ""
		}
		return reason
	}

	now := time.Now()
	out := make(map[string]p2p.PeerDiagnostic, len(peers)+len(directs))
	for _, pc := range peers {
		name := keyName(pc.peer)
		path := transports[name]
		if path == "" {
			continue // no live data path — not a connected peer (peerTransports)
		}
		out[name] = p2p.PeerDiagnostic{
			Path:   path,
			Reason: reasonFor(path),
			// The snapshot's zero value must read the same everywhere: a peer with
			// no directConn is in the same state as one whose directConn is in
			// directNone.
			State:       "none",
			LastRecvAge: ageOf(now, pc.lastFrameAt.Load()),
			// The peer's relay-session churn, so a pair that is flapping reads as
			// such in the report instead of only in the log.
			RelayRebuilds: pc.relayRebuilds.Load(),
			PeerRekeys:    pc.relayRebuildPeers.Load(),
		}
	}
	for _, dc := range directs {
		name := keyName(dc.peer)
		path := transports[name]
		if path == "" {
			continue // no live data path — not a connected peer (peerTransports)
		}
		d := out[name] // keep a relay connector's lastFrame age if there is one
		d.Path = path
		d.Reason = reasonFor(path)
		d.State = dc.stateName()
		d.Failed = dc.hasFailed()
		d.LastError = dc.lastErrOf()
		d.PeerAddr = dc.peerAddrString()
		d.Candidates = dc.candidateCount()
		d.Caps = dc.capNames()
		// The freshest last-recv of the two paths: a direct-first peer has no
		// relay adapter, a peer with both may have sent on either.
		if at := dc.lastFrameAt.Load(); at != 0 {
			if a := ageOf(now, at); d.LastRecvAge == 0 || a < d.LastRecvAge {
				d.LastRecvAge = a
			}
		}
		if at := dc.sessAtOf(); !at.IsZero() {
			d.SessionAge = now.Sub(at)
		}
		d.Attempts, d.Ups, d.Drops = dc.punchCounters()
		d.Trace = dc.traceLines()
		out[name] = d
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ageOf is the time since a UnixNano stamp, or 0 when unset.
func ageOf(now time.Time, nano int64) time.Duration {
	if nano == 0 {
		return 0
	}
	return now.Sub(time.Unix(0, nano))
}

// peerEncryptions names each connected peer's session state — "secure" or
// "plaintext" (the value set documented on p2p.Status.PeerEncryption), over the
// same peer set peerTransports reports. A peer is reported only while it has a
// live data path (a built relay session or a live direct session): a peer whose
// session was refused has no path and is not a plaintext session, so it is
// skipped — which is what keeps PlaintextPeers at 0 under forced encryption.
// When reported, a peer is "secure" only when every live session it has holds
// keys, so a plaintext direct path is not masked by an encrypted relay session.
// The *secureSession pointers are stable and keys() takes its own lock, so
// neither the engine lock nor pc.mu/dc.mu is held across the classification.
func (e *engine) peerEncryptions() map[string]string {
	e.mu.Lock()
	peers := make(map[derpclient.PublicKey]*peerConn, len(e.peers))
	for k, pc := range e.peers {
		peers[k] = pc
	}
	directs := make(map[derpclient.PublicKey]*directConn, len(e.directs))
	for k, dc := range e.directs {
		directs[k] = dc
	}
	e.mu.Unlock()

	out := make(map[string]string, len(peers)+len(directs))
	for k, pc := range peers {
		dc := directs[k]
		if !pc.liveSession() && !(dc != nil && dc.live()) {
			continue // no live data path — not a connected session
		}
		out[keyName(k)] = encryptionState(pc, dc)
	}
	for k, dc := range directs {
		if _, ok := out[keyName(k)]; ok {
			continue // already classified through its relay adapter
		}
		if !dc.live() {
			continue // no live data path
		}
		out[keyName(k)] = encryptionState(nil, dc)
	}
	return out
}

// encryptionState classifies one peer by its live sessions: "secure" only when
// every considered session holds keys — the relay session when the peer has one,
// the direct session while one is live — else "plaintext". Reporting "plaintext"
// for any unsettled live session is the safe direction for a downgrade alarm: it
// may over-report transiently (a direct session mid-handshake), but never masks
// a plaintext data path behind an encrypted relay session. Either argument may
// be nil: a peer can be present with only a relay adapter or only a direct
// connection.
func encryptionState(pc *peerConn, dc *directConn) string {
	considered, allSecure := false, true
	if pc != nil {
		// pc.secure is reassigned when a replaced session re-handshakes, so the
		// field is read under pc.mu like sessionLocked's reads.
		pc.mu.Lock()
		secure := pc.secure
		pc.mu.Unlock()
		if secure != nil {
			considered = true
			if _, _, ok := secure.keys(); !ok {
				allSecure = false
			}
		}
	}
	if dc != nil && dc.live() && dc.secure != nil {
		considered = true
		if _, _, ok := dc.secure.keys(); !ok {
			allSecure = false
		}
	}
	if considered && allSecure {
		return encStateSecure
	}
	return encStatePlaintext
}

// directConfig reports the direct path this host is running with, for Status:
// the master switch as resolved, the STUN server actually held (not the one
// configured — an embedder may hand an empty one after a failed probe), whether
// that server answered, whether IPv6 egress exists, and the host-wide reason
// word. A host that never punches is explained by these alone, without reading
// the engine's fields.
func (e *engine) directConfig() p2p.DirectConfig {
	return p2p.DirectConfig{
		Direct:     e.direct,
		Stun:       e.stunAddr,
		StunFailed: e.stunFailed.Load(),
		IPv6:       e.v6Available || e.v6Addr != nil,
		Reason:     e.directReason(),
	}
}

// directReason names what stands between this host and a direct path when
// nothing peer-specific does: "" while punching is possible, else "disabled"
// (the master switch), "no-candidates" (no STUN server and no IPv6 egress) or
// "stun-unreachable" (STUN configured but its last query failed, with no IPv6
// to fall back on). Each is a distinct thing for a user to fix.
func (e *engine) directReason() string {
	if !e.direct {
		return transportDisabled
	}
	hasV6 := e.v6Addr != nil || e.v6Available
	switch {
	case e.stunAddr == "" && !hasV6:
		return transportNoCandidates
	case !hasV6 && e.stunFailed.Load():
		return transportStunUnreachable
	}
	return ""
}

// transportCounts returns how many peers currently ride a direct session and
// how many are on the relay only.
func (e *engine) transportCounts() (direct, derp int) {
	for _, transport := range e.peerTransports() {
		if transport == transportDirect {
			direct++
			continue
		}
		derp++
	}
	return
}

// peerConn is the per-peer packet adapter: smux sees it as a net.Conn, whose
// writes become DERP SendPackets and whose reads drain packets routed by the
// connection pump.
type peerConn struct {
	e       *engine
	peer    derpclient.PublicKey
	inbound chan []byte

	// secure is this pair's relay security session, borrowed from e.secure (one
	// per (peer, transport), outliving this adapter). The AEAD record layer
	// wraps the smux underlay once both halves are exchanged, and stays
	// plaintext (peer predates encryption) otherwise.
	secure *secureSession

	// lastFrameAt is the UnixNano stamp of the last frame seen from this peer
	// (relay). An atomic so a status read never takes pc.mu.
	lastFrameAt atomic.Int64

	// Relay-session rebuilds for this peer, by cause. A pair that rebuilds often
	// is flapping, and that was only visible by grepping the log: the field case
	// was five "peer rekeyed" teardowns in twelve minutes, each taking the relay
	// session down with it. Atomics so a status read never takes pc.mu.
	relayRebuilds     atomic.Int64 // relay sessions built (first build excluded)
	relayRebuildPeers atomic.Int64 // of those, the peer changed its secure half

	mu        sync.Mutex
	sess      *smux.Session
	sessAt    time.Time     // when sess was established, for the stream-open log
	accepting *smux.Session // the session whose inbound accept loop is running, if any
	closed    bool
	closeCh   chan struct{}
	remainder []byte // partially consumed packet from inbound
	current   []byte

	// Relay-session churn for this peer: sessions built inside the current
	// window, when that window opened, and whether its limit has been crossed.
	// The crossing is acted on by the next caller, out of pc.mu (the reconnect
	// takes e.mu, and pc.mu is taken under e.mu elsewhere).
	churnFrom    time.Time
	churn        int
	churnTripped bool
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
	// goneHandshakeTimeout bounds waiting for a peer's handshake half when the
	// peer is marked gone: it answers only if it is already back, and the wait
	// must not charge a full handshake timeout to an open that will fall through
	// to the plaintext (and then fail-fast) path.
	goneHandshakeTimeout = 1 * time.Second
	// dialTimeout caps the DERP connection establishment.
	dialTimeout = 10 * time.Second
)

// resendInterval is how often an unsettled handshake re-sends its half while
// ensureSession waits out handshakeTimeout, so a dropped reply heals instead of
// leaving one side plaintext while the other encrypts. A var so tests can
// shorten it.
var resendInterval = 500 * time.Millisecond

// Deployment-dependent timings, adjustable via the `timeouts` config section
// (applyTimeouts in config.go). Vars, not consts, so tests can shorten them.
var (
	// keepAlivePeriod pings the DERP server well below typical proxy idle
	// timeouts (e.g. Cloudflare's ~100s).
	keepAlivePeriod = 30 * time.Second
	// smux keepalive for the relay session. KeepAliveTimeout must stay well
	// above the interval (>= 2x): with them equal, smux's idle check races the
	// first NOP round-trip and closes an idle session after ~interval (see
	// docs/2026-09-09-p2p-mutual-punch-design.md, kcp-go deep dive R1/R2).
	//
	// The pair is what bounds how long a peer that restarted — or moved
	// networks — stays "connected" while carrying nothing: only the frames the
	// *peer* sends feed a session's liveness, and the relay's PeerGone is
	// best-effort (derper sends it to mesh watchers, not to open-relay clients),
	// so a session whose far end vanished is noticed only here. Measured on a
	// phone whose tun entrypoint was restarted: ~33s of blackhole at 10s/30s,
	// which is one timeout plus the re-establishment.
	//
	// The timeout must stay above the ping interval of a peer that has not
	// adopted this pair — 10s, what this pair used to be — or a peer pinging
	// every 10s would have its healthy session torn down on a tick. 15s is that
	// floor for a mixed fleet; 3s pings leave room for a tighter timeout once
	// both ends negotiate one (see capsTightKeepalive's shape).
	smuxKeepAliveInterval = 3 * time.Second
	smuxKeepAliveTimeout  = 15 * time.Second

	// The direct session's own keepalive, deliberately tighter than the relay's.
	// Smux answers a NOP with nothing, so a session's liveness is fed by the
	// frames the *peer* sends — which is why the pair is negotiated
	// (capsTightKeepalive) rather than applied outright: a peer that does not
	// advertise it gets smuxKeepAliveInterval/Timeout above instead.
	//
	// The timeout is a silence budget, not a failover target, and a measured
	// field case set it: a phone on Wi-Fi lost its direct session at exactly
	// 18.000s (~3 ticks of the 6s timeout it then was), and the cause was ~12s
	// of one-way silence from RF batching — a 6s timeout cannot survive that,
	// while the relay's 15s one did (relaySilent, 60s, never fired). Smux clears
	// its activity flag on one tick and closes on the next, so 15s puts the
	// silent-path window at roughly 30-45s: long enough for the batching, still
	// far shorter than the relay's. Until then the session is served as live:
	// status calls the peer "direct" and a new stream is handed to a dead path
	// instead of the relay. The relay's PeerGone is not a substitute — it is
	// best-effort and says nothing about a path that does not run through the
	// relay.
	//
	// The direct path is peer-to-peer and its frames ride KCP, so a lost NOP is
	// retransmitted rather than dropped: silence for seconds means the path
	// carries nothing at all, not that it is lossy. A false positive costs a
	// fallback to the relay and a re-punch, so deployments with slow or lossy
	// direct paths widen it further through timeouts.directSmux.
	directSmuxKeepAliveInterval = 2 * time.Second
	directSmuxKeepAliveTimeout  = 15 * time.Second
)

func newEngine(url, target string, priv derpclient.PrivateKey, log *slog.Logger) *engine {
	e := &engine{
		url:     url,
		targets: newTargetPool(),
		direct:  true,
		priv:    priv,
		pub:     priv.Public(),
		peers:   make(map[derpclient.PublicKey]*peerConn),
		directs: make(map[derpclient.PublicKey]*directConn),
		links:   make(map[derpclient.PublicKey][]*link),
		gone:    make(map[derpclient.PublicKey]bool),
		secure:  make(map[secureKey]*secureSession),
		log:     log,
		stop:    make(chan struct{}),
	}
	if target != "" {
		if err := e.addTargets([]string{target}); err != nil {
			log.Error("target", "value", target, "error", err)
		}
	}
	// The host is a rendezvous node: it must be connected to the relay for
	// peers to reach it, and it must recover after the connection drops.
	go e.reconnect()
	return e
}

// addTargets parses each target spec (a bare "host:port" is tcp, "udp://…" is
// udp) and adds it to the pool. Blank entries are skipped; the first malformed
// spec is returned so startup fails loudly.
func (e *engine) addTargets(specs []string) error {
	for _, s := range specs {
		if strings.TrimSpace(s) == "" {
			continue
		}
		sp, err := parseTarget(s)
		if err != nil {
			return err
		}
		e.targets.add(sp)
	}
	return nil
}

// reconnect redials the relay whenever there is no live connection. It runs
// for the lifetime of the engine; OpenStream also triggers a dial on demand.
func (e *engine) reconnect() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-ticker.C:
			e.mu.Lock()
			wasDown := e.client == nil
			if wasDown {
				e.ensureClientLocked()
			}
			var punch []*directConn
			if wasDown && e.client != nil {
				for _, dc := range e.directs {
					punch = append(punch, dc)
				}
			}
			e.mu.Unlock()

			// The relay just came back, which on a phone means the network
			// changed (Wi-Fi ↔ cellular): the candidates exchanged over it are
			// stale, and a round that ran while it was down gave up. Punch
			// again — nothing else would, while the pair is idle.
			if len(punch) > 0 {
				e.log.Debug("relay reconnected, punching again", "peers", len(punch))
				for _, dc := range punch {
					go dc.start()
				}
			}
		}
	}
}

// Connect dials the relay eagerly (used at startup so inbound tunnels work
// immediately instead of waiting for the reconnect ticker).
func (e *engine) Connect() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ensureClientLocked()
	if e.client == nil {
		if e.dialErr != nil {
			// The caller gets the cause, not just "failed": a TLS or DNS
			// failure is actionable, a bare "connect failed" is not.
			return fmt.Errorf("derp engine: connect: %w", e.dialErr)
		}
		return errors.New("derp engine: connect failed")
	}
	return nil
}

// PublicKey returns the engine's public key, base64 (raw URL) encoded — the
// string other hosts put in their GOST node addr.
func (e *engine) PublicKey() string {
	return base64.RawURLEncoding.EncodeToString(e.pub[:])
}

// OpenStream opens a tunnel stream to the peer, establishing the DERP
// connection and mux session on first use. An established direct (hole-punched)
// session is preferred; on any failure it falls back to the relay session. The
// returned connection is tagged with the transport it uses ("direct" or
// "derp") so the caller can log which path the tunnel took.
func (e *engine) OpenStream(peerB64 string) (net.Conn, error) {
	peer, err := parsePeerKey(peerB64)
	if err != nil {
		return nil, err
	}
	if dc := e.getDirect(peer); dc != nil {
		if sess := dc.session(); sess != nil {
			if c, err := openStream(sess, directOpenTimeout); err == nil {
				e.stats.countStream("direct")
				return &openedStream{Conn: &stampConn{Conn: c, at: &dc.lastFrameAt},
					transport: "direct", peerAddr: dc.peerAddrString()}, nil
			}
		}
	}

	// No direct session yet: try to punch one (bounded by punchWaitTimeout)
	// before falling back to the relay, so the first connection can ride the
	// direct path too instead of always starting on the relay.
	if sess := e.punchAndWait(peer); sess != nil {
		if c, err := openStream(sess, streamOpenTimeout); err == nil {
			pa := ""
			var conn net.Conn = c
			if dc := e.getDirect(peer); dc != nil {
				pa = dc.peerAddrString()
				conn = &stampConn{Conn: c, at: &dc.lastFrameAt}
			}
			e.stats.countStream("direct")
			return &openedStream{Conn: conn, transport: "direct", peerAddr: pa}, nil
		}
	}

	pc := e.peerConn(peer)
	sess, err := pc.ensureSession(true, true)
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
	// What is carrying this stream, and how stale that carrier looks: a stream
	// handed to a relay session whose peer has gone silent is the documented
	// "a dead session is served as live" hole, and these are the numbers that
	// tell it apart from a healthy open.
	pc.mu.Lock()
	sessAge := time.Since(pc.sessAt).Round(time.Second)
	pc.mu.Unlock()
	frameAge := "n/a"
	e.mu.Lock()
	cl := e.client
	e.mu.Unlock()
	if cl != nil {
		if last := cl.LastRecv(); !last.IsZero() {
			frameAge = time.Since(last).Round(time.Millisecond).String()
		}
	}
	e.log.Debug("open stream: relay", "peer", peerB64, "sessionAge", sessAge.String(),
		"derpFrameAge", frameAge, "gone", wasGone)
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
				pc.killSession(errors.New("derp engine: peer gone probe timeout"), true)
			}
		}()
	}
	e.stats.countStream("derp")
	return &openedStream{Conn: c, transport: "derp"}, nil
}

// stampConn stamps a per-peer last-recv atomic on every successful read, so a
// peer that sends only on one long-lived stream — one it opened, or one it
// accepted — does not read as silent. The store is lock-free: it hits the
// directConn's own atomic, never the engine lock.
type stampConn struct {
	net.Conn
	at *atomic.Int64
}

func (c *stampConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.at.Store(time.Now().UnixNano())
	}
	return n, err
}

// openedStream is a tunnel stream tagged with the transport it uses, so the
// opening side can log whether the tunnel rode the direct path or the relay.
type openedStream struct {
	net.Conn
	transport string
	peerAddr  string // peer's dialed endpoint (direct only; empty for relay)
}

// Transport returns the path this stream used: "direct" or "derp".
func (c *openedStream) Transport() string { return c.transport }

// PeerAddr returns the peer's dialed endpoint for direct streams (empty for relay).
func (c *openedStream) PeerAddr() string { return c.peerAddr }

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
		// The open can still succeed after the wait. Nobody is left to use or
		// close that stream, so close it here or it rides the session forever
		// (and the peer holds a stream this side never reads).
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// secureKey identifies one (peer, transport) security session.
type secureKey struct {
	peer      derpclient.PublicKey
	transport byte
}

// secureSessionLocked returns (creating if needed) the cached per-(peer,
// transport) session. Caller must hold e.mu.
func (e *engine) secureSessionLocked(peer derpclient.PublicKey, transport byte) *secureSession {
	k := secureKey{peer: peer, transport: transport}
	ss := e.secure[k]
	if ss == nil {
		ss = newSecureSession(e.log, transport, e.priv, peer)
		e.secure[k] = ss
	}
	return ss
}

// secureSessionFor returns (creating if needed) the cached per-(peer,
// transport) session, which outlives any one smux session. Must NOT be called
// while holding e.mu.
func (e *engine) secureSessionFor(peer derpclient.PublicKey, transport byte) *secureSession {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.secureSessionLocked(peer, transport)
}

// dropRelaySecure forgets the peer's relay security session so the next rebuilt
// adapter re-handshakes on a fresh ephemeral. The invariant the shared counters
// rely on is that every nonce drawn is either delivered-and-consumed by the peer
// or both sides reset; it breaks when the relay link is lost (derpclient reports
// the write failure only after the nonce is spent, so sendCtr can be one ahead
// of the peer's recvCtr) or when a local kill abandons records still queued in
// the adapter (smux's read loop stops without draining them). Either way the
// peer never consumes those nonces and can never realign, so the pair must
// re-handshake: our next half carries a new ephemeral, the peer sees `changed`,
// resets its counters and rebuilds — both converge. It must NOT be used on the
// peer-restart path (resetPeerSession): there the peer already changed its half
// and respond re-derived ours, so both counters already match and dropping would
// send yet another fresh half, loop the two ends, and never settle.
func (e *engine) dropRelaySecure(peer derpclient.PublicKey) {
	e.mu.Lock()
	delete(e.secure, secureKey{peer: peer, transport: secureTransportRelay})
	e.mu.Unlock()
}

// peerConn returns (creating if needed) the adapter for peer, dialing the
// DERP server and starting the pump on first use. A cached adapter that was
// closed (e.g. the peer process died and its relay session broke) is replaced
// with a fresh one so the next stream rebuilds instead of failing forever. The
// adapter borrows the per-(peer, transport) security session from e.secure: a
// replacement adapter keeps the settled keys, unless the kill that closed the
// old one dropped them (killSession) — then the next build re-handshakes.
func (e *engine) peerConn(peer derpclient.PublicKey) *peerConn {
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
		secure:  e.secureSessionLocked(peer, secureTransportRelay),
	}
	e.peers[peer] = pc
	return pc
}

// ensureClientLocked dials the DERP server and starts the pump + keepalive
// goroutines. Caller must hold e.mu.
func (e *engine) ensureClientLocked() {
	if e.client != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	c, err := derpclient.Dial(ctx, e.url, e.priv, e.tlsCfg)
	if err != nil {
		e.log.Error("derp dial", "url", e.url, "error", err)
		e.dialErr = err
		return
	}
	e.dialErr = nil
	e.client = c
	// Debug fault injection, read once here because the fault config is
	// startup-only: the flag must be in place before the read loop starts.
	c.SetDropPong(e.faults.Load().pong())
	e.log.Debug("derp connected", "url", e.url, "server", keyName(c.ServerPublicKey()))
	go e.pump(c)
	go e.keepalive(c)
}

// pump routes inbound packets to the owning peer adapter; a transport error
// tears down the connection and all sessions (the next OpenStream redials).
func (e *engine) pump(c *derpclient.Client) {
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

		// Fault injection (see faults): an inbound data frame is dropped before
		// delivery, as indistinguishable from a path loss as the outbound one —
		// which is what starves a session whose peer looks healthy.
		if e.faults.Load().muteData(time.Now()) {
			continue
		}

		// peerConn creates the adapter for a peer we have not seen and drops a
		// closed one instead of handing it back. Reaching into the map directly
		// left a killed adapter (its session ended, e.g. on a queue overflow) in
		// place, so every later packet failed against it and the peer had no
		// inbound path at all until some outbound open happened to replace it.
		pc := e.peerConn(src)
		pc.lastFrameAt.Store(time.Now().UnixNano())
		// Ensure a session exists on this side too: inbound packets must be
		// consumed by smux (which then accepts streams) even when this host
		// never opens a tunnel to the peer itself.
		if _, err := pc.ensureSession(true, false); err != nil {
			// The session could not be built, so records already queued for this
			// peer are abandoned and their nonces never consumed: the kill drops
			// the pair's relay security session so the rebuild re-handshakes
			// (see dropRelaySecure).
			pc.killSession(err, true)
			continue
		}
		select {
		case pc.inbound <- pkt:
		case <-pc.closeCh:
			// session already dead; drop
		default:
			// Queue overflow: the session is unrecoverable (smux needs
			// lossless delivery) — kill it and let the peer redial. Killing
			// abandons the records still queued (smux's read loop stops without
			// draining them), so those nonces are spent but never consumed: the
			// kill drops the relay security session so both ends reset and
			// realign instead of wedging on a permanent counter offset.
			pc.killSession(errors.New("derp engine: inbound queue overflow"), true)
		}
	}
}

// handleControl dispatches a control frame ([kind 1B][payload]) received from
// src. The source key is relay-authenticated; candidate payloads are
// additionally sealed to the peer so a malicious relay cannot inject them.
func (e *engine) handleControl(src derpclient.PublicKey, body []byte) {
	// Fault injection (see faults): the inbound half of the same mute. Nothing
	// is negotiated while a control fault is on, which is the point.
	if e.faults.Load().muteCtrl(time.Now()) {
		return
	}
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
	case ctrlCaps:
		clear, ok := e.priv.OpenFrom(src, body[1:])
		if !ok || len(clear) < 1 {
			e.log.Debug("direct punch: bad caps box", "peer", keyName(src))
			return
		}
		e.directConn(src).addCaps(clear[0])
	case ctrlSecure:
		clear, ok := e.priv.OpenFrom(src, body[1:])
		if !ok || len(clear) < 1 {
			e.log.Debug("secure: bad box", "peer", keyName(src))
			return
		}
		// Only the two known transports: a bogus tag must not create a cached
		// session (respond would reject the half anyway).
		if clear[0] != secureTransportRelay && clear[0] != secureTransportDirect {
			return
		}
		if len(clear) != secureHalfLen {
			e.log.Debug("secure: bad half length", "peer", keyName(src), "len", len(clear))
			return
		}
		// Rule (b): a received half makes us answer with our own, so a
		// one-sided tunnel cannot deadlock (the opener cannot send data before
		// the key exists, so it cannot trigger the peer with data). We answer
		// while we are unsettled, when the peer's ephemeral changed (a peer
		// restart), or when the peer is asking (its want bit), so a lost reply
		// heals. Once both ends settle, neither sets want and a repeated half is
		// a no-op, so the exchange terminates — no mutual resend.
		ss := e.secureSessionFor(src, clear[0])
		wasSettled := ss.settled()
		accepted, changed := ss.respond(clear)
		if !accepted {
			// Well-formed but unusable (its ephemeral does not derive): surfaced
			// so a silent plaintext downgrade cannot hide here.
			e.log.Warn("secure: unusable peer half", "peer", keyName(src), "transport", clear[0])
			return
		}
		want := clear[1+32] != 0
		if want || !wasSettled || changed {
			if err := e.sendSecureHalf(src, ss); err != nil {
				e.log.Debug("secure: respond failed", "peer", keyName(src), "error", err)
			}
		}
		if changed {
			if clear[0] == secureTransportRelay {
				// The peer restarted: its half changed. Tear the relay mux session
				// down so it rebuilds over the new key (kill also unblocks the
				// parked read loop; a session left reading would eat the new
				// session's packets). The secure session itself is kept.
				e.resetPeerSession(src)
			} else {
				// Same on the direct transport: tear the direct mux session down
				// so the next punch rebuilds it over the new key. The session
				// itself is kept (resetDirectSession only detaches the smux layer).
				e.resetDirectSession(src)
			}
		}
	}
}

// sendSecureHalf sends our relay-session handshake half to the peer. Idempotent
// (re-sealing the same public half); safe to call more than once.
func (e *engine) sendSecureHalf(peer derpclient.PublicKey, ss *secureSession) error {
	sealed, err := ss.start()
	if err != nil {
		return err
	}
	return e.sendControl(peer, ctrlSecure, sealed)
}

// resetPeerSession tears the peer's relay mux session down so the next packet
// or open rebuilds it over the current key. The peer adapter is killed (not
// just its session): kill unblocks the parked read loop, which a bare
// sess.Close would deadlock against.
func (e *engine) resetPeerSession(peer derpclient.PublicKey) {
	e.mu.Lock()
	pc := e.peers[peer]
	e.mu.Unlock()
	if pc != nil {
		// The one teardown a user cannot cause from either end: the peer changed
		// its key. It tears the session down every time, so its rate is the one
		// that separates "the network is flapping" from "we are churning".
		pc.relayRebuildPeers.Add(1)
		// The one kill that must NOT drop the secure session (dropSecure=false):
		// the peer changed its half and respond re-derived ours, so both
		// counters already match — re-handshaking would make the two ends swap
		// halves forever (see dropRelaySecure).
		pc.killSession(errors.New("derp engine: peer rekeyed"), false)
	}
}

// resetDirectSession tears the peer's direct mux session down so a re-punch
// rebuilds it over the peer's new key (a peer restart arrives as a changed
// secure half). It mirrors resetPeerSession, but the direct path lives in
// e.directs and is rebuilt by a punch rather than a packet-driven ensureSession,
// so markDead is what reclaims it: it detaches the session, closes its socket,
// and (when that session owned directUp) schedules the re-punch. The secure
// session itself is kept — respond already re-derived it under the new key, and
// the next punch's conn() wraps the fresh underlay with those keys. It is not
// added to peerGone: the direct path survives a relay loss by design.
func (e *engine) resetDirectSession(peer derpclient.PublicKey) {
	e.mu.Lock()
	dc := e.directs[peer]
	e.mu.Unlock()
	if dc == nil {
		return
	}
	dc.mu.Lock()
	sess := dc.sess
	dc.mu.Unlock()
	if sess != nil {
		dc.markDead(sess)
	}
}

// relayDeadPeriod is how long an unanswered probe may stand before the engine
// treats the relay path as dead and reconnects. Probes go out every
// keepAlivePeriod (30s), so the ceiling sits between one and two ticks: long
// enough that a round trip in flight is never mistaken for a dead path, short
// enough that a stale registration is cleared within a minute. A var so tests
// can shorten it.
var relayDeadPeriod = 45 * time.Second

// relaySilent reports whether the relay connection has stopped answering: a
// ping went out at pingedAt and no pong has come back within relayDeadPeriod.
// Inbound frames alone cannot answer this — a quiet relay carries none at all,
// healthy or not (measured: a hub with an idle peer set sees frames=0 on a
// perfectly good connection) — which is why the engine probes instead.
func relaySilent(pingedAt, pongAt, now time.Time) bool {
	if pingedAt.IsZero() {
		return false // nothing probed yet: no verdict
	}
	last := pongAt
	if last.IsZero() || last.Before(pingedAt) {
		// The ping that is outstanding is the newest evidence there is: an
		// older pong (or none) says nothing about this round trip.
		last = pingedAt
	}
	return now.Sub(last) > relayDeadPeriod
}

// relayChurnWindow and relayChurnMax bound how often one peer's relay session
// may be rebuilt before the engine treats that *pair* — not the transport — as
// wedged. A session dies on its own keepalive timeout when its packets stop
// getting through, and the rebuild rides the same path it did before, so a pair
// the relay no longer routes for looks like this and nothing else: a rebuild
// every keepalive timeout, forever, while the shared connection stays busy with
// every other peer and nothing logs an error. That is the one shape the
// connection-level silence check above cannot see, and the only local cure is a
// fresh registration, so the transport is torn down and redialed. The window is
// generous on purpose: a network change or a peer restart costs a rebuild or
// two and must not trip this. Vars so tests can shorten them.
var (
	relayChurnWindow = 5 * time.Minute
	relayChurnMax    = 5
)

// errPeerSessionClosed is what a killed adapter answers with. It is one
// identity so callers can map it: the p2p contract exposes the same thing as
// p2p.ErrPeerUnreachable.
var errPeerSessionClosed = errors.New("derp engine: peer session closed")

// keepalive keeps the DERP connection alive through proxy/CDN idle timeouts.
func (e *engine) keepalive(c *derpclient.Client) {
	ticker := time.NewTicker(keepAlivePeriod)
	defer ticker.Stop()

	// pingedAt is this loop's own: the probe and its verdict are the keepalive
	// goroutine's business, and a new connection starts a new loop.
	var pingedAt time.Time
	for range ticker.C {
		if err := c.KeepAlive(); err != nil {
			e.teardown(c, err)
			return
		}
		// A relay path can die without the WebSocket noticing: writes buffer and
		// nothing errors, so every peer's streams keep being handed to a dead
		// path and nothing recovers until the host is restarted (a stale relay
		// registration keeps serving as live). Inbound frames cannot say whether
		// that happened — a quiet relay carries none either way — so a ping goes
		// out and the pong, or its absence, is the verdict: an unanswered probe
		// tears the connection down, and the redial registers the relay afresh,
		// which is what clears the stale state.
		if err := c.Ping(); err != nil {
			e.teardown(c, err)
			return
		}
		// The ping just sent becomes the *outstanding* probe only once the
		// previous one was answered (or when none was outstanding yet). The stamp
		// must not advance on every tick: the age would then stay at one interval
		// — below the ceiling — and the verdict below could never fire, leaving a
		// half-open relay in place forever. Candidate exchange rides the relay, so
		// that is also a punch that never succeeds again.
		now := time.Now()
		pong := c.LastPong()
		if pingedAt.IsZero() || (!pong.IsZero() && !pong.Before(pingedAt)) {
			pingedAt = now
		}
		// The reported age is the last pong's, which is the number that says
		// whether the path is answering; the ping just sent is only in flight.
		pongAge := "never"
		if !pong.IsZero() {
			pongAge = now.Sub(pong).Round(time.Millisecond).String()
		}
		e.log.Debug("derp: keepalive", "pongAge", pongAge, "pongs", c.Pongs(),
			"inboundFrameAge", time.Since(c.LastRecv()).Round(time.Second).String(),
			"frames", c.RecvFrames())
		if relaySilent(pingedAt, pong, now) {
			e.log.Error("derp: relay path dead, reconnecting", "pongAge", pongAge,
				"pongs", c.Pongs(), "frames", c.RecvFrames())
			e.teardown(c, fmt.Errorf("relay path unresponsive for %v (%d pongs, %d frames in)",
				relayDeadPeriod, c.Pongs(), c.RecvFrames()))
			return
		}
	}
}

// peerGone drops everything to a peer whose DERP connection just closed (the
// DERP server told us). Subsequent streams rebuild against a fresh session, and
// opens use a short timeout until the peer is reachable again.
//
// The peer's *direct* session is deliberately left alone. PeerGone is a
// best-effort notice about the peer's relay connection, and it says nothing
// about the hole-punched path, which does not run through the relay at all —
// tearing it down here destroyed a working path every time a peer's relay link
// blipped. The direct session answers for itself through its own keepalive
// (see directSmuxKeepAliveTimeout); dropIfGone reclaims the entry once that
// session ends.
func (e *engine) peerGone(peer derpclient.PublicKey) {
	e.mu.Lock()
	e.gone[peer] = true
	pc := e.peers[peer]
	delete(e.peers, peer)
	// The peer's relay connection dropped: forget its security session too. The
	// peer may have restarted (a new ephemeral will arrive), and holding a stale
	// key would leave the next rebuild mismatched. A peer that merely blipped
	// re-handshakes once on its return.
	delete(e.secure, secureKey{peer: peer, transport: secureTransportRelay})
	e.mu.Unlock()
	if pc != nil {
		// A session-less adapter is a handshake in flight: killing it would fail
		// that open before its bounded wait can decide, and the peer may already
		// be back. Only a built session is torn down.
		pc.mu.Lock()
		built := pc.sess != nil
		pc.mu.Unlock()
		if built {
			pc.killSession(errors.New("derp engine: peer gone"), true)
		}
	}
	e.log.Debug("derp peer gone", "peer", keyName(peer))
}

// dropIfGone reclaims a peer's punch state when the relay has reported it gone
// and the session that was keeping the entry alive has ended. It reports
// whether it dropped the entry: a peer that is gone has nothing to re-punch
// with, so the caller can skip scheduling one.
func (e *engine) dropIfGone(peer derpclient.PublicKey, dc *directConn) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.gone[peer] || e.directs[peer] != dc {
		return false
	}
	delete(e.directs, peer)
	return true
}

func (e *engine) isGone(peer derpclient.PublicKey) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gone[peer]
}

func (e *engine) clearGone(peer derpclient.PublicKey) {
	e.mu.Lock()
	delete(e.gone, peer)
	e.mu.Unlock()
}

// teardown drops the transport and every session built on it.
func (e *engine) teardown(c *derpclient.Client, cause error) {
	e.mu.Lock()
	if e.client != c {
		e.mu.Unlock()
		return
	}
	e.client = nil
	peers := make([]*peerConn, 0, len(e.peers))
	for _, pc := range e.peers {
		peers = append(peers, pc)
		// The relay link is gone: forget each peer's relay security session so a
		// reconnect re-handshakes instead of reusing counters a lost record may
		// have advanced (see dropRelaySecure). Without this a peer whose link
		// dropped — the Wi-Fi<->cellular switch — would come back with our
		// sendCtr one ahead of its recvCtr, with no way to realign.
		delete(e.secure, secureKey{peer: pc.peer, transport: secureTransportRelay})
	}
	e.peers = make(map[derpclient.PublicKey]*peerConn)
	e.mu.Unlock()
	e.log.Error("derp connection lost", "error", cause)
	c.Close()
	for _, pc := range peers {
		pc.killSession(cause, true)
	}
}

// Close shuts the engine down.
func (e *engine) Close() {
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
	links := make([]*link, 0, len(e.links))
	for _, ls := range e.links {
		links = append(links, ls...)
	}
	e.links = make(map[derpclient.PublicKey][]*link)
	e.mu.Unlock()
	for _, pc := range peers {
		pc.killSession(errors.New("engine closed"), true)
	}
	for _, dc := range directs {
		dc.teardown()
	}
	for _, l := range links {
		l.close()
	}
	if c != nil {
		c.Close()
	}
}

// ensureSession brings up the peer's relay mux session and, when punch is set,
// starts a hole punch for it. It takes pc.mu itself: the session state is
// touched from the pump goroutine as well as OpenStream, and the callers used
// to disagree on whether that lock was held (pump did not), racing pc.sess and
// able to build two smux sessions over one packet stream.
//
// The punch runs after pc.mu is released: maybeStartDirect takes e.mu, while
// peerConn takes pc.mu under e.mu, so starting it under pc.mu would invert the
// two and deadlock two concurrent opens of the same peer.
//
// The punch and the session are separable because the roles differ: a host that
// dials out wants the punch, while one that only answers a peer's dial (a
// reverse tunnel) should not spend a round on a peer that has not engaged yet —
// that round fails by construction and its failure is indistinguishable, in the
// status, from a punch that cannot work.
// liveSession reports whether the adapter has a built, open relay smux session
// — a live data path. It is the side-effect-free probe Status uses: unlike
// sessionLocked it never builds or tears down.
func (pc *peerConn) liveSession() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.liveSessionLocked()
}

// liveSessionLocked is liveSession with pc.mu already held.
func (pc *peerConn) liveSessionLocked() bool {
	return pc.sess != nil && !pc.sess.IsClosed()
}

func (pc *peerConn) ensureSession(punch bool, wait bool) (*smux.Session, error) {
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return nil, errPeerSessionClosed
	}
	live := pc.liveSessionLocked()
	// A dead session standing here is about to be replaced by sessionLocked.
	// When the dead session left records nothing will read (its read loop is
	// gone, so what the pump kept pushing is abandoned), the replacement must
	// re-handshake: those records' nonces are spent at the peer and can never
	// realign (see dropRelaySecure), and their bytes are discarded below so the
	// fresh key starts on a clean record boundary. The drop runs here, before
	// the handshake below and outside pc.mu — dropRelaySecure takes e.mu, which
	// is taken before pc.mu elsewhere (see peerConn), so it cannot run inside
	// sessionLocked's pc.mu section. A replacement that abandons nothing keeps
	// the settled session: the nonce sequence is intact, so the rebuild is
	// transparent and costs no handshake round trip.
	replaced := pc.sess != nil && pc.sess.IsClosed()
	secure := pc.secure
	dropSecure := replaced && pc.abandonedLocked()
	pc.mu.Unlock()

	if dropSecure {
		pc.e.dropRelaySecure(pc.peer)
		secure = pc.e.secureSessionFor(pc.peer, secureTransportRelay)
		pc.mu.Lock()
		pc.secure = secure
		// Discard the abandoned stream bytes with the old session: they belong
		// to the old key's record sequence, and the fresh session would
		// misparse them as its first records. Only dead ciphertext is lost —
		// the peer's respond resets its counters alongside ours.
		pc.current, pc.remainder = nil, nil
		for {
			select {
			case <-pc.inbound:
				continue
			default:
			}
			break
		}
		pc.mu.Unlock()
	}

	// No live session: settle the handshake before building, so both ends agree
	// on encrypted-vs-plaintext for this session. A settled security session
	// needs none of this: its keys outlive the mux session, so a rebuild just
	// reuses them — except a replaced session, which re-handshakes above — and
	// a peer restart arrives as a changed half, not here. The
	// send and the wait run OUTSIDE pc.mu: sendControl takes e.mu, which pc.mu
	// is taken under elsewhere, so holding pc.mu here would invert the two.
	if !live && !secure.settled() && !wait {
		// Inbound (pump) path: never block on a relay round trip. Announce our
		// half anyway (idempotent: start re-seals the same half) — the peer may
		// be settled on a key this side just dropped and will then send no half
		// of its own, and without the announce a pump-driven rebuild would wait
		// for the peer's next rebuild to re-handshake. The peer sees `changed`
		// (or a want bit), resets its counters and answers, and handleControl
		// settles us. If it does not, drop this packet fast and let the next
		// one (or an outbound open) retry: waiting here would stall the single
		// pump goroutine — and every peer's inbound routing — for up to
		// handshakeTimeout, per packet.
		if err := pc.e.sendSecureHalf(pc.peer, secure); err != nil {
			pc.e.log.Debug("secure: send half failed", "peer", keyName(pc.peer), "error", err)
		}
		return nil, errEncryptionRequired
	}
	if !live && !secure.settled() {
		// Retry the half on an interval: a reply lost in flight leaves us
		// unsettled while the peer is settled, so re-sending (with want set) is
		// what makes the peer answer again — otherwise we would stay plaintext
		// while it encrypts, and both mux sessions would churn. The loop ends the
		// moment we settle, or once the deadline passes.
		total := handshakeTimeout
		if pc.e.isGone(pc.peer) {
			// The peer's relay dropped: it answers only if it is already back.
			// Bound the whole attempt well under handshakeTimeout so an open to a
			// still-down peer falls through to plaintext (and the fail-fast
			// probe) instead of burning a full timeout first.
			total = goneHandshakeTimeout
		}
		deadline := time.Now().Add(total)
		for {
			if err := pc.e.sendSecureHalf(pc.peer, secure); err != nil {
				pc.e.log.Debug("secure: send half failed", "peer", keyName(pc.peer), "error", err)
			}
			if secure.waitReady(resendInterval) {
				break
			}
			if secure.settled() || !time.Now().Before(deadline) {
				break
			}
		}
	}

	if !secure.settled() {
		// Forced encryption: a session that did not settle is refused, never
		// built as plaintext. Return before sessionLocked (and before the churn
		// accounting) so the open fails loudly instead of sending cleartext.
		pc.e.log.Warn("relay session refused: encryption required but the peer did not negotiate it",
			"peer", keyName(pc.peer))
		return nil, errEncryptionRequired
	}

	pc.mu.Lock()
	sess, err := pc.sessionLocked()
	pc.mu.Unlock()
	if pc.takeChurnTripped() {
		// This pair is rebuilding sessions far faster than a working one ever
		// does: its packets are not getting through a relay that still looks
		// healthy for every other peer, and each rebuild rides the same path.
		// A fresh registration is the cure, so the transport goes down and the
		// redial brings it back.
		pc.e.log.Error("derp: peer relay session churn, reconnecting the relay",
			"peer", keyName(pc.peer), "builds", relayChurnMax+1, "window", relayChurnWindow.String())
		pc.e.reconnectRelay(fmt.Errorf("peer %s rebuilt its relay session more than %d times in %v",
			keyName(pc.peer), relayChurnMax, relayChurnWindow))
	}
	if err == nil && punch {
		pc.e.maybeStartDirect(pc.peer)
	}
	return sess, err
}

// reconnectRelay tears the shared relay connection down, so the redial loop
// registers with it afresh. Nothing smaller cures a stale registration: the
// relay's routing table is per connection, and it is the registration that has
// gone stale.
func (e *engine) reconnectRelay(cause error) {
	e.mu.Lock()
	c := e.client
	e.mu.Unlock()
	if c != nil {
		e.teardown(c, cause)
	}
}

// sessionLocked brings up the peer's relay mux session if it is not already
// live. The role is fixed by public-key ordering so both ends converge on one
// session per pair. Caller must hold pc.mu.
func (pc *peerConn) sessionLocked() (*smux.Session, error) {
	if pc.sess != nil && pc.sess.IsClosed() {
		// A replacement that abandoned records re-handshakes: ensureSession
		// dropped the pair's relay security session and settled a fresh one
		// before calling in here (see dropRelaySecure); one that abandoned
		// nothing keeps the settled session. The drop cannot happen in this
		// pc.mu section — dropRelaySecure takes e.mu, which is taken before
		// pc.mu elsewhere (see peerConn).
		pc.sess = nil
	}
	if pc.sess != nil {
		return pc.sess, nil
	}
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = smuxKeepAliveInterval
	cfg.KeepAliveTimeout = smuxKeepAliveTimeout
	roleIsClient := bytes.Compare(pc.e.pub[:], pc.peer[:]) < 0
	underlay, err := pc.secure.conn(pc)
	if err != nil {
		return nil, err
	}
	// A session built while one was already there is a rebuild (the caller
	// cleared a closed one above), and a rebuild rate is what says "this pair is
	// flapping" — the field case was a session rebuilt every few seconds, visible
	// only by grepping the log. Counted before the build so a failed one still
	// shows: the churn guard already acts on the same window.
	rebuild := !pc.sessAt.IsZero()
	if roleIsClient {
		pc.sess, _ = smux.Client(underlay, cfg)
	} else {
		pc.sess, _ = smux.Server(underlay, cfg)
	}
	if pc.sess == nil {
		return nil, errors.New("derp engine: cannot establish mux session")
	}
	if rebuild {
		pc.relayRebuilds.Add(1)
	}
	pc.sessAt = time.Now()
	pc.noteBuildLocked(pc.sessAt)
	_, _, enc := pc.secure.keys()
	pc.e.log.Debug("peer relay session up", "peer", keyName(pc.peer), "client", roleIsClient, "secure", enc)
	pc.startAccept()
	return pc.sess, nil
}

// noteBuildLocked records one relay session built for this peer, opening a new
// window when the old one has run out, and trips when the window's limit is
// crossed. Caller must hold pc.mu.
func (pc *peerConn) noteBuildLocked(now time.Time) {
	if pc.churnFrom.IsZero() || now.Sub(pc.churnFrom) > relayChurnWindow {
		pc.churnFrom, pc.churn = now, 0
	}
	pc.churn++
	if pc.churn > relayChurnMax {
		pc.churnTripped = true
	}
}

// takeChurnTripped reports — once — that this peer's churn limit was crossed,
// and clears the count so the next window can trip again. It takes pc.mu, so it
// must be called once the session lock is released.
func (pc *peerConn) takeChurnTripped() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if !pc.churnTripped {
		return false
	}
	pc.churnTripped = false
	pc.churn, pc.churnFrom = 0, time.Time{}
	return true
}

// startAccept launches the inbound stream loop for the adapter's current
// session, if that session has none yet. Caller must hold pc.mu.
//
// The session is captured here, not read inside the goroutine: a rebuild would
// otherwise hand the loop whatever pc.sess had become — nil (a crash in
// AcceptStream) or a different, newer session. The flag names the session the
// loop serves rather than being a plain bool, so a rebuild never has to wait
// for the previous loop to notice its session died before it can start serving
// the new one.
func (pc *peerConn) startAccept() {
	sess := pc.sess
	if sess == nil || pc.accepting == sess {
		return
	}
	pc.accepting = sess
	go func() {
		defer func() {
			pc.mu.Lock()
			if pc.accepting == sess {
				pc.accepting = nil
			}
			pc.mu.Unlock()
		}()
		pc.e.acceptLoop(sess, "derp", pc.peer, "")
	}()
}

// killSession marks the adapter dead and tears down its session. Safe for
// concurrent use and for already-dead adapters.
//
// dropSecure asks for the pair's relay security session to be dropped when the
// kill abandons records: packets still queued (or partially consumed) whose
// nonces the peer already spent and this side will never draw. A session
// rebuilt over them can never realign (see dropRelaySecure), so the next build
// must re-handshake. A kill that abandons nothing keeps the session: the dying
// read loop drains what it still consumes (those nonces advance in step with
// the peer's), so the leftover buffers are the exact abandoned set, and when
// they are empty the nonce sequence is intact — the rebuild is the transparent
// one secure.go documents. The one caller that passes false is resetPeerSession
// (the peer rekeyed): there the peer already changed its half and respond
// re-derived ours, so both counters already match and a drop would make the two
// ends swap halves forever.
//
// Only the caller that flips the adapter dead decides the secure session, and
// it runs once: smux's session Close re-enters here through the underlay
// (Close), and a re-entry must not re-decide — it would drop what a
// killSession(cause, false) deliberately kept.
func (pc *peerConn) killSession(cause error, dropSecure bool) {
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return
	}
	pc.closed = true
	close(pc.closeCh)
	sess := pc.sess
	abandoned := pc.abandonedLocked()
	pc.mu.Unlock()

	if dropSecure && abandoned && pc.e != nil {
		pc.e.dropRelaySecure(pc.peer)
	}
	if sess != nil {
		sess.Close()
	}
	pc.e.log.Debug("peer session killed", "peer", keyName(pc.peer), "cause", cause)
}

// abandonedLocked reports whether the adapter still holds frame bytes nothing
// will read: queued packets and partially consumed ones. Caller must hold
// pc.mu, so pc.Read's bookkeeping and this snapshot cannot race.
func (pc *peerConn) abandonedLocked() bool {
	return len(pc.inbound) > 0 || len(pc.current) > 0 || len(pc.remainder) > 0
}

// Read implements net.Conn: drain queued packets, honoring partial reads. The
// remainder/current bookkeeping runs under pc.mu (it is shared with
// abandonedLocked's kill-time snapshot), never across a channel wait.
func (pc *peerConn) Read(p []byte) (int, error) {
	for {
		pc.mu.Lock()
		if len(pc.remainder) > 0 {
			n := copy(p, pc.remainder)
			pc.remainder = pc.remainder[n:]
			pc.mu.Unlock()
			return n, nil
		}
		if len(pc.current) > 0 {
			n := copy(p, pc.current)
			pc.current = pc.current[n:]
			pc.mu.Unlock()
			return n, nil
		}
		pc.mu.Unlock()
		select {
		case pkt := <-pc.inbound:
			pc.mu.Lock()
			pc.current = pkt
			pc.mu.Unlock()
		case <-pc.closeCh:
			// drain remaining queued packets before reporting EOF
			select {
			case pkt := <-pc.inbound:
				pc.mu.Lock()
				pc.current = pkt
				pc.mu.Unlock()
			default:
				return 0, io.EOF
			}
		}
	}
}

// Write implements net.Conn: each write is one DERP SendPacket.
func (pc *peerConn) Write(p []byte) (int, error) {
	// Fault injection (see faults): the frame never reaches the relay, and the
	// write reports success — smux cannot tell this from a path that ate it.
	if pc.e.faults.Load().muteData(time.Now()) {
		return len(p), nil
	}
	pc.mu.Lock()
	closed := pc.closed
	pc.mu.Unlock()
	if closed {
		return 0, errPeerSessionClosed
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
	pc.killSession(errors.New("adapter closed"), true)
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
// gost style ("<peer> <-> <target>", ">-<" + duration on close). peerAddr is
// the peer's dialed endpoint (direct only; empty for relay).
func bridgeInbound(stream net.Conn, transport, peer, peerAddr, target string, log *slog.Logger) {
	defer stream.Close()
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Debug("inbound bridge dial failed", "transport", transport, "peer", peer, "target", target, "error", err)
		return
	}
	defer up.Close()

	// peer is the remote p2p host key, endpoint the local service the stream
	// is bridged to (the --target).
	attrs := []any{"transport", transport, "peer", peer, "endpoint", target}
	if peerAddr != "" {
		attrs = append(attrs, "peerAddr", peerAddr)
	}
	start := time.Now()
	log.Info(fmt.Sprintf("%s <-> %s", peer, target), attrs...)
	defer func() {
		log.Info(fmt.Sprintf("%s >-< %s", peer, target),
			append(append([]any{}, attrs...), "duration", time.Since(start).String())...)
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
