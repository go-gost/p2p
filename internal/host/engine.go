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
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/clock"
	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// sessionGenSeq numbers every relay session built across the whole process, so
// a session's generation is globally unique within a process: a rebuild, a
// desync, a kill and a pair-KCP epoch reset on the same peer all carry the same
// number, and two peers' generations never collide. It is deliberately
// package-level, not per-engine, so two engines in one process (tests, a host
// with multiple relays) still produce distinct generations.
var sessionGenSeq atomic.Uint64

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
	// lastControlHeal is when a control-blackhole trip last reconnected the
	// relay (see healControlBlackhole): the reconnect tears every peer's
	// relay session down, so trips are rate limited engine-wide. Guarded by
	// mu.
	lastControlHeal time.Time
	// relayKCPs holds one relay KCP holder per peer, on the same principle as
	// secure: the pair's KCP session outlives any one adapter, so an adapter
	// swap does not restart the pair's sequence epoch under a peer whose
	// session is still running (see relayKCPPair). Guarded by its own leaf
	// lock, not e.mu: sessionLocked takes it under pc.mu, and e.mu is taken
	// before pc.mu everywhere else.
	kcpMu     sync.Mutex
	relayKCPs map[derpclient.PublicKey]*relayKCPPair
	stop      chan struct{}

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
		// M1: the word names the pair's current path. The pair's own recency
		// decides it, so a peer whose pair carries a fresh direct underlay
		// reads "direct" even before its punch state machine (a directConn)
		// exists.
		if pair := e.relayKCPPairGet(p); pair != nil && pair.pathName() == transportDirect {
			out[keyName(p)] = transportDirect
			continue
		}
		out[keyName(p)] = fallback
	}
	for k, dc := range directs {
		if !e.peerLive(k) {
			continue // no live data path — whatever the punch state says
		}
		name := keyName(k)
		// M1 again: the pair's path outranks the per-peer punch state, so a
		// live pair underlay is never overwritten by "failed"/"punching" off a
		// directConn that has not caught up.
		if pair := e.relayKCPPairGet(k); pair != nil && pair.pathName() == transportDirect {
			out[name] = transportDirect
			continue
		}
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
		out[name] = func() p2p.PeerDiagnostic {
			d := p2p.PeerDiagnostic{
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
				// The pair's relay KCP session health, read through the pair (not the
				// adapter) so a clean adapter swap still reports the surviving session.
				RelayKCP: e.relayKCPStats(pc.peer),
			}
			// The pair's O2/O4/O5 migration history (in-process only).
			e.fillPairDiag(&d, pc.peer)
			return d
		}()
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
		// The pair's O2/O4/O5 migration history and the punch backoff (O4).
		e.fillPairDiag(&d, dc.peer)
		d.NextPunchIn = dc.nextPunchIn()
		out[name] = d
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fillPairDiag copies the pair's O2/O4/O5 diagnostic view onto d (in-process
// only: the gRPC proto is frozen). A peer with no pair leaves the fields zero.
func (e *engine) fillPairDiag(d *p2p.PeerDiagnostic, peer derpclient.PublicKey) {
	pair := e.relayKCPPairGet(peer)
	if pair == nil {
		return
	}
	pd := pair.diag()
	d.PathTrace = pd.pathTrace
	d.FallbackReason = pd.fallbackReason
	d.PairMigrations = int64(pd.migrations)
	d.PairFallbacks = int64(pd.fallbacks)
	d.DirectIdleEvictions = int64(pd.directIdleEvictions)
	d.RepunchAfterIdle = int64(pd.repunchAfterIdle)
	d.SeedFailures = int64(pd.seedFailures)
	d.RelayLossSuppressedByDirect = int64(pd.relayLossSuppressed)
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
		out[keyName(k)] = encryptionState(pc)
	}
	for k, dc := range directs {
		if _, ok := out[keyName(k)]; ok {
			continue // already classified through its relay adapter
		}
		if !dc.live() {
			continue // no live data path
		}
		out[keyName(k)] = encryptionState(nil)
	}
	return out
}

// encryptionState classifies one peer by its live relay session: "secure" when
// it holds keys, else "plaintext". The direct underlay no longer has a separate
// secure session (Task 7): it rides the pair's relay secure session, so a live
// direct path is exactly as encrypted as the relay it shares and is not
// consulted here.
func encryptionState(pc *peerConn) string {
	considered, allSecure := false, true
	if pc != nil {
		// pc.secure is fixed at adapter creation (see peerConn) and read under
		// pc.mu for consistency with sessionLocked's and killSession's reads.
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

// peerConn is the per-peer derp adapter the relay packet layer sits on: its
// inbound channel is drained one datagram at a time by relayPacketConn.ReadFrom
// (feeding KCP), and its Write turns one datagram into a single DERP
// SendPacket.
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

	// sessionGen is the generation of the most recently built relay session,
	// assigned from sessionGenSeq on every build (first included) in
	// sessionLocked. It ties a rebuild, a desync, a kill and the pair-KCP epoch
	// reset on this peer to one number in the log. An atomic so the kill and
	// desync paths can read it without pc.mu.
	sessionGen atomic.Uint64

	mu   sync.Mutex
	sess *smux.Session
	// kcp is this adapter's view of the pair's KCP session under sess (see
	// relayKCPPair): the reliable datagram layer between the relay packet path
	// and the crypto record framing, so a dropped relay packet is one
	// retransmitted segment instead of a permanent record desync. The pair owns
	// the session — it outlives adapter swaps — and this view is set by
	// sessionLocked's build and cleared by killSession. Guarded by pc.mu.
	kcp       *kcp.UDPSession
	sessAt    time.Time     // when sess was established, for the stream-open log
	accepting *smux.Session // the session whose inbound accept loop is running, if any
	closed    bool
	closeCh   chan struct{}

	// lastEndReason is the reason the previous relay session ended with, set by
	// killSession and consumed by the next rebuild's storm check (in
	// sessionLocked). The zero value means the session died on its own, with no
	// kill. Guarded by pc.mu.
	lastEndReason sessionEndReason

	// deadSince and silentFor date one outage: the moment this side OBSERVED the
	// relay session die, and how long the pair's underlays had been quiet when
	// it did. They are set in the two places a death is observable and nowhere
	// else — killSession (the adapter is closed by a kill, so the rebuild goes
	// through peerConn) and ensureSession's replacement branch (the session
	// died on its own, so the rebuild happens in place) — which are mutually
	// exclusive, since killSession sets closed and ensureSession returns early
	// on it.
	//
	// Consumed by the next rebuild log, which reads and clears them in one
	// pc.mu block: the clear must not happen outside that block (it would race
	// killSession's stamp), and must not be skipped (the next rebuild would
	// report a span measured from an older death). The zero value means no
	// death was observed, and the log then carries the reason alone.
	//
	// The silence is taken from the pair at the moment of death, never at
	// emit time: by then the peer may be sending again, and six of the nine kill
	// reasons reset the pair's KCP epoch, which deletes the pair before the
	// rebuild runs. Guarded by pc.mu.
	deadSince time.Time
	silentFor time.Duration

	// lastEnded is the session the last death report was accepted for. The
	// accept loop reports a session's death, and the report force-closes the
	// session — which wakes the loop's own parked AcceptStream, whose exit
	// reports the same session again. Identity against pc.sess cannot dedup
	// that second report (the rebuild has not replaced sess yet), so the
	// first accepted report records itself here and a repeat stands down.
	// Guarded by pc.mu.
	lastEnded *smux.Session

	// Relay-session churn for this peer: sessions built inside the current
	// window, when that window opened, and whether its limit has been crossed.
	// The crossing is acted on by the next caller, out of pc.mu (the reconnect
	// takes e.mu, and pc.mu is taken under e.mu elsewhere).
	churnFrom    time.Time
	churn        int
	churnTripped bool

	// storm tracks this peer's recent rebuilds so a rebuild storm — far more
	// rebuilds than a working session ever produces — is flagged exactly once
	// per window. Self-contained (its own lock and an injectable clock); it is
	// only touched on the rebuild path, which is rare.
	storm rebuildStorm
}

const (
	// rebuildStormWindow is the span over which one peer's relay-session
	// rebuilds are counted for the storm check. It is far tighter than the
	// churn window (relayChurnWindow): churn ends in a relay reconnect, while a
	// storm is only flagged, so it must not fire on a single network change
	// (which costs a rebuild or two) but must catch the livelock this diagnoses
	// (rebuilds every few seconds).
	rebuildStormWindow = 30 * time.Second
	// rebuildStormThreshold is how many rebuilds inside rebuildStormWindow may
	// pass before the storm WARN fires. "More than 3 within 30 seconds" means
	// the 4th rebuild trips it.
	rebuildStormThreshold = 3
	// rebuildStormMaxEvents caps the storm ring so a pathological in-process
	// storm cannot grow it without bound. It is far above the threshold, so the
	// count and reasons are exact for any storm the WARN is meant to flag.
	rebuildStormMaxEvents = 16
)

// rebuildStorm tracks one peer's recent relay-session rebuilds so a rebuild
// storm — far more rebuilds than a working session ever produces — is flagged
// exactly once per window instead of only by reading the log timeline. The
// clock is injectable (now) so the window logic is testable with a fake clock
// and no sleeps; the zero value uses time.Now. Guarded by its own mutex;
// rebuilds are rare, so it is never contended.
type rebuildStorm struct {
	now func() time.Time
	mu  sync.Mutex
	// events is the oldest-first list of the most recent rebuilds still inside
	// the window, capped at rebuildStormMaxEvents. Each rebuild carries the
	// reason its previous session ended with ("" when the session died on its
	// own).
	events []rebuildEvent
	// warned is set when the window's threshold is crossed and cleared once the
	// count falls back to the threshold, so a fresh burst after a quiet window
	// warns again.
	warned bool
}

// rebuildEvent is one rebuild: when it happened and why (the reason the
// previous session ended with).
type rebuildEvent struct {
	at     time.Time
	reason sessionEndReason
}

// note records one rebuild and reports whether the WARN should be emitted now:
// true the first time the window holds more than rebuildStormThreshold rebuilds,
// together with the count and the oldest-first sequence of their reasons. It
// never allocates on the data path — it is only called on the rebuild path, and
// the reasons slice is built only on the call that warns.
func (s *rebuildStorm) note(reason sessionEndReason) (count int, reasons []sessionEndReason, warn bool) {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	at := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := at.Add(-rebuildStormWindow)
	kept := s.events[:0]
	for _, e := range s.events {
		if !e.at.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	s.events = append(kept, rebuildEvent{at: at, reason: reason})
	if n := len(s.events); n > rebuildStormMaxEvents {
		s.events = s.events[n-rebuildStormMaxEvents:]
	}
	if len(s.events) <= rebuildStormThreshold {
		s.warned = false
		return 0, nil, false
	}
	if s.warned {
		return 0, nil, false
	}
	s.warned = true
	reasons = make([]sessionEndReason, len(s.events))
	for i, e := range s.events {
		reasons[i] = e.reason
	}
	return len(s.events), reasons, true
}

// carryTo hands this storm's window state to dst — the events still inside the
// window, the warned flag, and the injected clock — so a replacement adapter
// continues the pair's storm instead of restarting it on every swap. It does not
// copy the mutex (dst keeps its own); the caller (peerConn, under e.mu) installs
// dst before any other goroutine can reach it, so dst needs no lock here.
func (s *rebuildStorm) carryTo(dst *rebuildStorm) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dst.events = append(dst.events[:0], s.events...)
	dst.warned = s.warned
	dst.now = s.now
}

// recordRebuild feeds one rebuild to the storm check and emits the WARN the
// first time the window's threshold is crossed. reason is the reason the
// previous session ended with. It runs on the rebuild path only (sessionLocked,
// under pc.mu): the storm lock is a leaf taken under pc.mu, and the WARN is a
// plain log, so it neither blocks nor allocates on any data path.
func (pc *peerConn) recordRebuild(reason sessionEndReason) {
	count, reasons, warn := pc.storm.note(reason)
	if !warn || pc.e == nil || pc.e.log == nil {
		return
	}
	// gen is the generation of the session whose build just tripped the storm —
	// the same number the "peer relay session up" line logs right after this —
	// while reasons are the ends of the sessions that were rebuilt away.
	pc.e.log.Warn("derp: peer relay rebuild storm",
		"peer", keyName(pc.peer),
		"gen", pc.sessionGen.Load(),
		"count", count,
		"window", rebuildStormWindow.String(),
		"reasons", reasons)
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
// leaving one side plaintext while the other encrypts. Settable so tests can
// shorten it — and atomic because they do so while engines are live: an engine
// from an earlier test can still be inside ensureSession's retry loop, reading a
// value no running test owns, so a plain var here is a data race that takes the
// whole package's -race run down with it.
var resendInterval = newAtomicDuration(500 * time.Millisecond)

// newAtomicDuration returns an atomic holding d as nanoseconds. A pointer,
// because a zero Int64 reads as 0 — a hot spin in every caller that waits on it
// — and because copying an atomic by value is itself a vet error.
func newAtomicDuration(d time.Duration) *atomic.Int64 {
	v := &atomic.Int64{}
	v.Store(int64(d))
	return v
}

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

	// directSmuxKeepAliveInterval/Timeout are retained for config compatibility
	// (timeouts.directSmux still parses and applies) but are no longer read: the
	// direct plane no longer runs its own smux session — it rides the pair's
	// relay session, whose liveness is smuxKeepAliveInterval/Timeout above and,
	// for the hole-punched path, the underlay idle watchdog (directUnderlayIdle).
	// Kept so an existing config that sets them still loads.
	directSmuxKeepAliveInterval = 2 * time.Second
	directSmuxKeepAliveTimeout  = 15 * time.Second
)

func newEngine(url, target string, priv derpclient.PrivateKey, log *slog.Logger) *engine {
	e := &engine{
		url:       url,
		targets:   newTargetPool(),
		direct:    true,
		priv:      priv,
		pub:       priv.Public(),
		peers:     make(map[derpclient.PublicKey]*peerConn),
		directs:   make(map[derpclient.PublicKey]*directConn),
		links:     make(map[derpclient.PublicKey][]*link),
		gone:      make(map[derpclient.PublicKey]bool),
		secure:    make(map[secureKey]*secureSession),
		relayKCPs: make(map[derpclient.PublicKey]*relayKCPPair),
		log:       log,
		stop:      make(chan struct{}),
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
			// again — nothing else would, while the pair is idle. kick, not
			// start: a backoff armed on the dead registration was earned on a
			// channel that no longer exists, and start is a no-op while a
			// backoff is armed — without the kick the re-punch would sit out
			// the remainder behind a stale timer.
			if len(punch) > 0 {
				e.log.Debug("relay reconnected, punching again", "peers", len(punch))
				for _, dc := range punch {
					go dc.kick()
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
// connection and mux session on first use. There is one session per peer now —
// the pair — and its KCP layer picks the preferred underlay (direct when fresh,
// relay otherwise), so a stream opened before a punch still migrates to the
// direct path once it lands. The returned connection is tagged with the pair's
// current path ("direct" or "derp") so the caller can log which path the tunnel
// is taking; the label is a snapshot, not a lifelong plane (M1).
func (e *engine) OpenStream(peerB64 string) (net.Conn, error) {
	peer, err := parsePeerKey(peerB64)
	if err != nil {
		return nil, err
	}
	pc := e.peerConn(peer)
	// ensureSession(punch=true) starts a hole punch for the peer, so a first
	// open still gets the direct path as soon as it comes up; the open itself
	// does not wait for it (M3).
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
				pc.killSession(errors.New("derp engine: peer gone probe timeout"), true, reasonPeerGoneProbe)
			}
		}()
	}
	path := e.pairPath(peer)
	e.stats.countStream(path)
	// Stamp the per-peer last-recv on the directConn (when one exists) so a
	// stream that carries only one direction still keeps the peer's last-recv
	// fresh for the diagnostics.
	var conn net.Conn = c
	peerAddr := ""
	if dc := e.getDirect(peer); dc != nil {
		conn = &stampConn{Conn: c, at: &dc.lastFrameAt}
		if path == "direct" {
			peerAddr = dc.peerAddrString()
		}
	}
	// Capture the pair and its path now for O6: the stream reports a later
	// migration on its I/O. lastPath uses the pair's own names ("relay"/"direct"),
	// so it compares against pathName directly; transport above stays the public
	// "derp"/"direct" label (M1).
	pair := e.relayKCPPairGet(peer)
	lastPath := ""
	if pair != nil {
		lastPath = pair.pathName()
	}
	return &openedStream{
		Conn:      conn,
		transport: path,
		peerAddr:  peerAddr,
		log:       e.log,
		peer:      peerB64,
		pair:      pair,
		lastPath:  lastPath,
	}, nil
}

// pairPath names the peer's current path for stream tagging and status:
// "direct" while the pair's direct underlay is preferred (recent recency), else
// "derp". It is a snapshot of the pair's current path, not a stream's lifelong
// plane: the pair migrates underneath the stream (M1). A peer with no pair yet
// reads "derp".
func (e *engine) pairPath(peer derpclient.PublicKey) string {
	if pair := e.relayKCPPairGet(peer); pair != nil && pair.pathName() == "direct" {
		return "direct"
	}
	return "derp"
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
//
// transport is a point-in-time snapshot of the pair's path at open time
// (Task 10/M1), not a stream's lifelong plane: the pair migrates underneath a
// long-lived stream. Read and Write watch for that migration and emit one Info
// "stream path-changed" (O6) so a stream's history can be reconstructed from
// logs; the pair's own pathChanges counter is the cheap fallback.
type openedStream struct {
	net.Conn
	transport string
	peerAddr  string // peer's dialed endpoint (direct only; empty for relay)

	// Path-change observation (O6). Log and peer name the stream in the event;
	// pair is polled for the pair's current path, and lastPath is the last path
	// this stream saw on its own I/O. A nil pair (no pair built) makes this
	// inert. pathMu guards lastPath: Read/Write run from both copy goroutines.
	log      *slog.Logger
	peer     string
	pair     *relayKCPPair
	pathMu   sync.Mutex
	lastPath string
}

// Transport returns the path this stream used: "direct" or "derp".
func (c *openedStream) Transport() string { return c.transport }

// PeerAddr returns the peer's dialed endpoint for direct streams (empty for relay).
func (c *openedStream) PeerAddr() string { return c.peerAddr }

// Read reads from the stream, then notes the pair's current path so a migration
// that happened while this stream was idle is reported on the next transfer.
func (c *openedStream) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.notePath()
	return n, err
}

// Write writes to the stream, then notes the pair's current path (see Read).
func (c *openedStream) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.notePath()
	return n, err
}

// notePath records a stream path change when this stream's I/O first sees the
// pair on a path other than the one it last saw. The pair migrates silently
// beneath an open stream, so this is where a long-lived stream becomes
// reconstructable from logs (O6): one Info "stream path-changed" per transition,
// with a finite, greppable reason. from/to use the pair's own names
// ("relay"/"direct"); transport keeps the public "derp" label.
func (c *openedStream) notePath() {
	if c.pair == nil {
		return
	}
	cur := c.pair.pathName()
	c.pathMu.Lock()
	from := c.lastPath
	c.lastPath = cur
	c.pathMu.Unlock()
	if cur == from {
		return
	}
	if c.log != nil {
		c.log.Info("stream path-changed", "peer", c.peer, "from", from, "to", cur,
			"reason", streamPathChangeReason(cur))
	}
}

// streamPathChangeReason maps the destination path of a stream path change to a
// finite reason enum for the O6 log. A stream only sees the pair's current path,
// not the cause the pair-level event (Task 11) carries, so this is a coarse
// direction-derived name: direct is a fresh direct datagram re-electing the
// path; relay is the direct path going silent past the idle bound.
func streamPathChangeReason(to string) string {
	if to == "direct" {
		return "first-direct-datagram"
	}
	return "direct-idle"
}

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
// of the peer's recvCtr) or when the record framing desyncs past the backstop
// (see armDesyncRecovery). Under the KCP underlay a local clean kill no longer
// breaks it: a queued packet is a segment KCP retransmits, never a consumed
// record whose nonce the peer spent, so the pair realigns on the surviving KCP
// session instead. Either way the peer never consumes those nonces and can
// never realign, so the pair must re-handshake: our next half carries a new
// ephemeral, the peer sees `changed`, resets its counters and rebuilds — both
// converge. It must NOT be used on the peer-restart path (resetPeerSession):
// there the peer already changed its half and respond re-derived ours, so both
// counters already match and dropping would send yet another fresh half, loop
// the two ends, and never settle.
func (e *engine) dropRelaySecure(peer derpclient.PublicKey, expect *secureSession) {
	e.mu.Lock()
	defer e.mu.Unlock()
	k := secureKey{peer: peer, transport: secureTransportRelay}
	// Compare-and-delete. The decision to drop is taken under pc.mu but runs
	// after pc.mu is released, and by then the key may already hold a different
	// session — a replacement adapter's, or one a concurrent ensureSession
	// installed. Deleting that one would evict a LIVE pair's keys and force a
	// needless handshake, and would leave the session the peer is actually
	// holding stranded in the cache under a key nobody reads. Dropping only the
	// session the decision was made about makes the delete idempotent: teardown
	// and peerGone already drop every relay session under e.mu, and the
	// killSession that follows finds nothing of its own left to delete.
	if expect != nil && e.secure[k] != expect {
		return
	}
	delete(e.secure, k)
}

// relayKCPPairFor returns (creating if needed) the pair's relay KCP holder,
// which outlives any one adapter exactly like the pair's secure session. Must
// NOT be called while holding e.mu — it takes kcpMu, the store's leaf lock.
func (e *engine) relayKCPPairFor(peer derpclient.PublicKey) *relayKCPPair {
	e.kcpMu.Lock()
	defer e.kcpMu.Unlock()
	if e.relayKCPs == nil {
		e.relayKCPs = make(map[derpclient.PublicKey]*relayKCPPair)
	}
	pair := e.relayKCPs[peer]
	if pair == nil {
		pair = newRelayKCPPair(e, peer)
		e.relayKCPs[peer] = pair
	}
	return pair
}

// relayKCPPairGet returns the pair's relay KCP holder, or nil when none exists.
// Unlike relayKCPPairFor it never creates: Status reads the pair's stats through
// this so a status query cannot build a session as a side effect.
func (e *engine) relayKCPPairGet(peer derpclient.PublicKey) *relayKCPPair {
	e.kcpMu.Lock()
	defer e.kcpMu.Unlock()
	return e.relayKCPs[peer]
}

// relayKCPFreshness returns the peer's merged underlay recency and whether the
// engine holds a pair that has one. It never creates a pair: like
// relayKCPPairGet, a peer with no pair reports false rather than a zero time
// that would age into "since 1970" downstream.
//
// A false here is not "the peer was quiet" — it is "the engine has nothing to
// say", which for a peer whose kill reset its pair (killSession ->
// dropRelayKCP -> delete(e.relayKCPs, peer)) is the more common half of the
// state.
func (e *engine) relayKCPFreshness(peer derpclient.PublicKey) (time.Time, bool) {
	pair := e.relayKCPPairGet(peer)
	if pair == nil {
		return time.Time{}, false
	}
	return pair.freshestRecv()
}

// registerDirectUnderlay installs a freshly punched socket as the peer's pair
// direct underlay (the P2 cutover). It builds the underlay with the raw-UDP seed
// token threaded from the handshake (Task 6) so the underlay can echo the peer's
// late seed probes while dropping its own returning echo; the no-token
// constructor never echoes, which would regress the late-responder fallback. The
// pair's idle callback is installed once (idempotent): the pair invokes it when
// the underlay goes silent past directUnderlayIdle.
//
// setDirectUnderlay retires any previous underlay by closing its socket, so a
// re-punch never leaks the old one and never double-reads. Do not call this with
// an already-installed socket: setDirectUnderlay would close it as the "old"
// underlay (the Task 3 contract); markUp guards the same-socket case.
//
// The pair session (the direct feed's consumer) is built asynchronously, off the
// punch goroutine. The direct pump only feeds the pair's KCP session, so a
// direct path with no built pair session has nowhere to deliver — the accepting
// side of a punch can land before its relay session exists. Doing it here rather
// than inline keeps registration non-blocking, so a re-punch that replaces this
// underlay cannot be raced by a stale install; if the session cannot be built
// (forced encryption not settled), the underlay is retired rather than reported
// direct while carrying nothing (I1/I4).
func (e *engine) registerDirectUnderlay(peer derpclient.PublicKey, sock *net.UDPConn, addr netip.AddrPort, token [seedTokenLen]byte) {
	if sock == nil {
		return
	}
	pair := e.relayKCPPairFor(peer)
	pair.mu.Lock()
	if pair.onDirectIdle == nil {
		pair.onDirectIdle = func(u *directUnderlay) { e.directUnderlayDead(peer, u) }
	}
	if pair.onDirectInbound == nil {
		pair.onDirectInbound = func() { e.onDirectInbound(peer) }
	}
	pair.mu.Unlock()
	u := newDirectUnderlayToken(sock, addr, token)
	pair.setDirectUnderlay(u)
	go e.ensureDirectConsumer(peer, pair, u)
}

// ensureDirectConsumer builds the pair session that consumes the direct feed,
// then retires the underlay if it cannot be built. It runs in its own goroutine
// so registration stays non-blocking (I1). The retirement is a
// compare-and-clear against u, so a re-punch that replaced u in the meantime is
// left alone (C1).
func (e *engine) ensureDirectConsumer(peer derpclient.PublicKey, pair *relayKCPPair, u *directUnderlay) {
	if !e.relayConnected() {
		// No relay, no pair session to build, and the punch could not have
		// exchanged candidates without it: leave the underlay installed (unit
		// tests register underlays on relay-less engines).
		return
	}
	pc := e.peerConn(peer)
	if pc == nil {
		return
	}
	_, err := pc.ensureSession(false, true)
	if err == nil {
		return
	}
	if errors.Is(err, errEncryptionRequired) {
		e.log.Warn("direct: pair secure not settled, retiring the direct underlay",
			"peer", keyName(peer))
	} else {
		e.log.Debug("direct: pair session not ready", "peer", keyName(peer), "error", err)
	}
	if dc := e.getDirect(peer); dc != nil {
		if errors.Is(err, errEncryptionRequired) {
			dc.noteErr("encryption not settled")
			dc.noteRound("encrypted: not settled")
		} else {
			dc.noteErr("pair session not ready")
			dc.noteRound("pair session not ready")
		}
	}
	if pair.clearDirectUnderlayIf(u, pathChangeClear) {
		if dc := e.getDirect(peer); dc != nil {
			dc.underlayDead(u)
		}
	}
}

// directUnderlayDead is the pair's idle-watchdog callback (Task 4's
// onDirectIdle): the direct underlay u went silent past directUnderlayIdle. If
// the pair still holds u, retire it and mark the peer's directConn down so it
// re-punches. The identity test and the clear are one critical section
// (clearDirectUnderlayIf): a plain check-then-clear would race a re-punch that
// replaces u and retire the replacement instead (C1). It is deliberately
// non-blocking (H4): clearDirectUnderlayIf signals the pump and closes the socket
// without joining it, and the re-punch runs on its own goroutine/timer.
func (e *engine) directUnderlayDead(peer derpclient.PublicKey, u *directUnderlay) {
	pair := e.relayKCPPairGet(peer)
	if pair == nil {
		return
	}
	if !pair.clearDirectUnderlayIf(u, pathChangeDirectIdle) {
		return // a newer underlay replaced it: not ours to retire
	}
	// The idle eviction is what schedules the re-punch (dc.underlayDead,
	// below): count it so Status can tell "idle and recovering" from
	// "flapping" without reading logs.
	pair.repunchAfterIdle.Add(1)
	dc := e.getDirect(peer)
	if dc == nil {
		return
	}
	dc.underlayDead(u)
}

// relayPathSilent is the relay idle watchdog's engine side: the pair's relay
// underlay went quiet past relayIdleWindow, and the strike says which hit
// this is. The evidence line always fires — silentFor is the pair's own
// relay-measured silence, not the kill line's merged freshestRecv — and then:
// strike 1 kills only the mux (reasonRelaySilent is a clean death: the pair
// and its keys survive for the cheap rebuild), strike 2 and beyond kill with
// reasonLinkLost, which resets the pair's KCP epoch (H1-suppressed while a
// live direct path carries it; the churn window counts it like any link
// loss). A pair that never built a session has no mux to kill and no outage
// to date, so it is evidence only.
//
// It runs on the watchdog's dispatch goroutine, off the tick, and takes no
// pair lock itself: livePeerConn takes e.mu, killSession reads the pair's
// recency outside pc.mu, so the order stays pair-then-adapter throughout.
func (e *engine) relayPathSilent(peer derpclient.PublicKey, strike int, silentFor time.Duration) {
	e.log.Debug("relay path silent", "peer", keyName(peer),
		"silentFor", silentFor.String(), "strike", strike)
	// livePeerConn, not peerConn (see peerRelaySessionEnded): a report for a
	// peer with no adapter must not create one.
	pc := e.livePeerConn(peer)
	if pc == nil {
		return
	}
	pc.mu.Lock()
	neverBuilt := pc.sessAt.IsZero()
	pc.mu.Unlock()
	if neverBuilt {
		return
	}
	if strike >= 2 {
		pc.killSession(errRelaySilent, false, reasonLinkLost)
		return
	}
	pc.killSession(errRelaySilent, false, reasonRelaySilent)
}

// onDirectInbound rebuilds the peer's mux session when an inbound direct
// datagram arrives and the adapter has no live session. A relay loss with a
// live direct path keeps the pair's KCP epoch and settled keys but closes the
// per-build mux session on both ends (killSession). The dialing side rebuilds on
// its next OpenStream; the accepting side has no relay pump to trigger a
// rebuild (engine.pump is the only non-outbound rebuild trigger), so without
// this a new stream opened over direct would hang. It is the direct-side
// counterpart of that relay-pump ensureSession.
//
// It runs on its own goroutine dispatched by the pair's direct pump (see
// reportDirectInbound), so it may take pc.mu and, on a first adapter, dial the
// relay — both off the data path, and bounded to one in flight per pair. With
// the settled keys a rebuild needs no relay round trip; the dial only fails
// fast when the relay is down, which is the case this path exists for.
func (e *engine) onDirectInbound(peer derpclient.PublicKey) {
	pc := e.peerConn(peer)
	if pc == nil {
		return
	}
	pc.mu.Lock()
	live := pc.liveSessionLocked()
	pc.mu.Unlock()
	if live {
		return
	}
	if _, err := pc.ensureSession(false, true); err != nil {
		e.log.Debug("direct: inbound direct with no live mux",
			"peer", keyName(peer), "error", err)
	}
}

// peerRelaySessionEnded is the relay-side counterpart of onDirectInbound: the
// relay accept loop dispatches here (on its own goroutine) when AcceptStream
// fails, which is how a session that died without closing itself is noticed.
// A smux session whose underlay goes quiet never closes on its own — the
// recvLoop exits on the read error while the session stays open — so without
// this the death is silent until some unrelated caller happens to rebuild.
//
// The report is deduped against the kill path (a kill swaps the adapter, so a
// report for its old session stands down) and against itself (the force-Close
// below wakes the loop's own parked AcceptStream, whose exit reports the same
// session again; lastEnded records the first). The death is always reported —
// the ended line is the event the silent window never had — but the rebuild
// is gated on the pair still carrying: a pair quiet past relayLiveWindow
// means the link is down, and a new session on it would die on the next
// keepalive tick. That case answers errRelaySessionStale and leaves the link
// to the pair's own watchdog.
func (e *engine) peerRelaySessionEnded(sess *smux.Session, peer derpclient.PublicKey, err error) error {
	// Freshness is read before any adapter lock: it takes the pair's lock,
	// and pc.mu is taken under e.mu elsewhere, so the order here is
	// pair-then-adapter, never the reverse.
	fresh, ok := e.relayKCPFreshness(peer)
	pairFresh := ok && time.Since(fresh) <= relayLiveWindow
	// livePeerConn, not peerConn: the creating lookup would resurrect what
	// the kill just dropped — secureSessionLocked re-creates the e.secure
	// entry the kill deleted, and the dead-adapter branch logs a "relay
	// session rebuilt" line for a session nobody built. A report that finds
	// no live adapter has nothing to rebuild on.
	pc := e.livePeerConn(peer)
	if pc == nil {
		return errRelaySessionSuperseded
	}
	pc.mu.Lock()
	deduped := pc.closed || pc.sess != sess || pc.lastEnded == sess
	if !deduped {
		pc.lastEnded = sess
	}
	pc.mu.Unlock()

	// The line fires on every processed report, including stand-downs: it
	// is the event the silent window never had, and deduped/pairFresh say
	// what the handler did with it.
	e.log.Debug("peer relay session ended", "peer", keyName(peer), "error", err,
		"deduped", deduped, "pairFresh", pairFresh)
	if deduped {
		return errRelaySessionSuperseded
	}
	if !sess.IsClosed() {
		// The §2.3 window: the session died without closing itself. Close
		// is idempotent, so the check only skips a spurious error return.
		_ = sess.Close()
	}
	if !pairFresh {
		return errRelaySessionStale
	}
	_, rerr := pc.ensureSession(false, false)
	if errors.Is(rerr, errPeerSessionClosed) {
		// A kill won the race after the report was accepted: the kill owns
		// the death now, and there is nothing left to rebuild.
		e.log.Debug("peer relay session ended: rebuild lost to kill", "peer", keyName(peer))
		return nil
	}
	return rerr
}

// relayKCPLogAttrs returns the slog attrs describing the pair's relay KCP
// session, or nil when the pair holds no session. It is appended (additively)
// to the lifecycle lines that carry gen=, so a reader sees the session's health
// at exactly the moment of a rebuild or epoch reset.
func (e *engine) relayKCPLogAttrs(peer derpclient.PublicKey) []any {
	pair := e.relayKCPPairGet(peer)
	if pair == nil {
		return nil
	}
	return relayKCPSnapshotAttrs(pair.snapshot())
}

// relayDownAttrs renders one outage's evidence for the "relay session rebuilt"
// line: the reason the relay session ended with, how long it stayed down before
// this rebuild, and how long it had already been silent when it died. Both
// rebuild paths (peerConn's kill-driven swap and ensureSession's in-place
// replacement) emit through here, so the rule about which fields appear is
// stated once.
//
// An empty reason is the informative case and is always emitted: it says the
// smux keepalive timeout judged the session dead with no kill behind it, which
// is exactly the outage the relay-side accept loop logs nothing for.
//
// The durations are emitted only for a death this side observed (deadSince
// set). An unobserved death reports the reason alone: a span measured from an
// unset time reads as an outage that began in year 1 and never ends — the same
// trap sessionAge already had to guard.
//
// downFor spans from the death to now, which is before the rebuild's new
// session is built, so it says how long the peer was down rather than how long
// the recovery took. silentFor is 0 when the engine held no pair to measure
// from (a kill that reset the pair's KCP epoch deleted it), which is not the
// same claim as "the peer was talking until that instant".
func relayDownAttrs(reason sessionEndReason, deadSince time.Time, silentFor time.Duration, now time.Time) []any {
	attrs := []any{"relayReason", reason}
	if deadSince.IsZero() {
		return attrs
	}
	return append(attrs,
		"downFor", now.Sub(deadSince).Round(time.Millisecond),
		"silentFor", silentFor.Round(time.Millisecond))
}

// relayKCPStats snapshots the pair's relay KCP session for Status, filled with
// the configured constants so a reader can compare configured against observed
// SRTT/RTO. Live is false when the pair holds no session; Status reports only
// peers with a live data path, whose pair normally exists, but a peer
// mid-rebuild can have none yet, and Live marks that instead of reading a zero
// SRTT as a healthy idle session.
func (e *engine) relayKCPStats(peer derpclient.PublicKey) p2p.RelayKCPStats {
	out := p2p.RelayKCPStats{
		Mtu:    relayKCPMtu,
		SndWnd: relayKCPSndWnd,
		RcvWnd: relayKCPRcvWnd,
	}
	pair := e.relayKCPPairGet(peer)
	if pair == nil {
		return out
	}
	s := pair.snapshot()
	out.SRTT = int64(s.srtt)
	out.RTO = int64(s.rto)
	out.RTTVar = int64(s.rttVar)
	out.Conv = s.conv
	out.BytesSent = s.bytesSent
	out.BytesRcvd = s.bytesRcvd
	out.Live = s.present
	// Per-underlay attribution (O3): the session stats above are the pair's,
	// these say which underlay carried the bytes and which is quiet. Path uses
	// the public transport word ("direct"/"derp") so it matches
	// PeerTransports, not the pair's internal "relay".
	if s.path == "direct" {
		out.Path = transportDirect
	} else {
		out.Path = transportRelay
	}
	out.RelayBytesSent = s.relayBytesSent
	out.RelayBytesRcvd = s.relayBytesRcvd
	out.DirectBytesSent = s.directBytesSent
	out.DirectBytesRcvd = s.directBytesRcvd
	out.DirectAlive = s.directAlive
	now := time.Now()
	if !s.relayLastRecv.IsZero() {
		out.RelayLastRecvAge = now.Sub(s.relayLastRecv)
	}
	if !s.directLastRecv.IsZero() {
		out.DirectLastRecvAge = now.Sub(s.directLastRecv)
	}
	return out
}

// dropRelayKCP ends and forgets the pair's relay KCP session, so the next build
// starts a fresh epoch. It runs only where the pair's sequence state can no
// longer align with the peer's: the peer restarted (its session starts over),
// the pair re-handshakes after a secure desync or a dropped key (the peer
// resets alongside our changed half, see resetPeerSession), the relay link
// carrying it is gone, or the engine is closing. A clean kill — keys kept —
// must NOT call it: the rebuilt mux session continues the pair's session
// instead of restarting at sn=0 under a peer whose session is still running.
//
// Compare-and-delete like dropRelaySecure: the decision is taken under pc.mu
// (or outside any lock) and runs after, and by then the key may already hold a
// replacement pair's session — evicting that one would kill a LIVE session's
// epoch. expect names the session the decision was made about; nil forces the
// drop (teardown paths, and kills of adapters that never built). gen is the
// relay-session generation whose epoch is being reset (0 when there is no
// specific built session, e.g. the pair's own Close), carried on the log line so
// a reset correlates with the kill or desync that caused it.
func (e *engine) dropRelayKCP(peer derpclient.PublicKey, expect *kcp.UDPSession, cause error, gen uint64) {
	e.kcpMu.Lock()
	pair := e.relayKCPs[peer]
	if pair == nil {
		e.kcpMu.Unlock()
		return
	}
	pair.mu.Lock()
	live := pair.sess
	pair.mu.Unlock()
	if expect != nil && live != expect {
		e.kcpMu.Unlock()
		return
	}
	delete(e.relayKCPs, peer)
	e.kcpMu.Unlock()
	// Snapshot before shutdown drops the session: these are its last observed
	// values, not zeros (a zero would read as a healthy idle session). When the
	// pair never built a session there are no attrs, and the line stays as it
	// was.
	stats := pair.snapshot()
	pair.shutdown()
	resetAttrs := []any{"peer", keyName(peer), "cause", cause, "gen", gen}
	resetAttrs = append(resetAttrs, relayKCPSnapshotAttrs(stats)...)
	e.log.Debug("relay kcp pair reset", resetAttrs...)
}

// closeRelayKCPs ends every pair's relay KCP session: the relay connection
// carrying them all is gone. Pairs whose adapter is already gone are included —
// a session left running would leak its read loop — but a pair kept alive by a
// live direct path is NOT: the relay half is merely unregistered, and the pair
// (with its KCP epoch and secure session) keeps running (H1). The engine's own
// shutdown uses closeAllRelayKCPs, which force-ends every pair.
func (e *engine) closeRelayKCPs(cause error) {
	e.closeRelayKCPsFor(cause, false)
}

// closeAllRelayKCPs ends every pair's relay KCP session regardless of a live
// direct path: the engine is closing, so nothing is left to keep a pair alive.
func (e *engine) closeAllRelayKCPs(cause error) {
	e.closeRelayKCPsFor(cause, true)
}

// closeRelayKCPsFor is the shared body of closeRelayKCPs/closeAllRelayKCPs.
// The live-direct decision is taken between kcpMu sections, not under one:
// pairHasLiveDirect takes kcpMu itself (to read the pair store) and then the
// pair's mu, so calling it while holding kcpMu would nest the two. The pair is
// compare-and-deleted so a concurrent lookup that replaced it is left alone.
func (e *engine) closeRelayKCPsFor(cause error, force bool) {
	type pairEntry struct {
		peer derpclient.PublicKey
		pair *relayKCPPair
	}
	e.kcpMu.Lock()
	entries := make([]pairEntry, 0, len(e.relayKCPs))
	for peer, pair := range e.relayKCPs {
		entries = append(entries, pairEntry{peer: peer, pair: pair})
	}
	e.kcpMu.Unlock()

	pairs := make([]*relayKCPPair, 0, len(entries))
	for _, en := range entries {
		if !force && e.pairHasLiveDirect(en.peer) {
			continue // a live direct path keeps the pair; only the relay half is gone
		}
		e.kcpMu.Lock()
		if e.relayKCPs[en.peer] != en.pair {
			e.kcpMu.Unlock()
			continue // replaced or already dropped underneath us
		}
		delete(e.relayKCPs, en.peer)
		e.kcpMu.Unlock()
		pairs = append(pairs, en.pair)
	}
	for _, pair := range pairs {
		pair.shutdown()
	}
	if len(pairs) > 0 {
		e.log.Debug("relay kcp pairs reset", "pairs", len(pairs), "cause", cause)
	}
}

// armDesyncRecovery wires a relay security session's record-boundary self-heal:
// secureDesyncThreshold consecutive failures mean the pair's framing can never
// realign (see dropRelaySecure), so the session is dropped and the adapter
// rebuilt on a fresh ephemeral. Arming twice is a no-op, so every site that
// hands a session to an adapter may call it.
//
// The callback resolves the live adapter when it fires instead of capturing one:
// a clean kill hands the same settled session to the replacement adapter, and a
// captured adapter would be dead by then.
func (e *engine) armDesyncRecovery(peer derpclient.PublicKey, secure *secureSession) {
	secure.mu.Lock()
	defer secure.mu.Unlock()
	if secure.onDesync != nil || secure.transport != secureTransportRelay {
		return
	}
	secure.onDesync = func(streak int) {
		// Resolve the live adapter once, before any teardown: its generation is
		// the desyncing session's, and it is the adapter the kill below closes.
		pc := e.livePeerConn(peer)
		gen := uint64(0)
		if pc != nil {
			gen = pc.sessionGen.Load()
		}
		e.log.Warn("p2p: relay secure desync, resetting",
			"peer", keyName(peer), "streak", streak, "gen", gen)
		e.dropRelaySecure(peer, secure)
		// The pair's KCP epoch resets with the keys — unconditionally, for the
		// same reason as resetPeerSession: a reset that lands on a dead adapter
		// must still reach the pair, or the mismatch survives the re-handshake
		// this callback exists to force.
		e.dropRelayKCP(peer, nil, errors.New("p2p: secure desync"), gen)
		// dropRelaySecure has released e.mu, so taking pc.mu here keeps the
		// e.mu-before-pc.mu order.
		if pc != nil {
			pc.killSession(errors.New("p2p: secure desync"), true, reasonSecureDesync)
		}
	}
}

// livePeerConn returns the peer's current adapter, or nil when it has none.
func (e *engine) livePeerConn(peer derpclient.PublicKey) *peerConn {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.peers[peer]
}

// peerConn returns (creating if needed) the adapter for peer, dialing the
// DERP server and starting the pump on first use. A cached adapter that was
// closed (e.g. the peer process died and its relay session broke) is replaced
// with a fresh one so the next stream rebuilds instead of failing forever. The
// adapter borrows the per-(peer, transport) security session from e.secure: a
// replacement adapter keeps the settled keys, unless the kill that closed the
// old one dropped them (killSession) — then the next build re-handshakes.
func (e *engine) peerConn(peer derpclient.PublicKey) *peerConn {
	// Deliberately not deferred: the rebuild log below has to run with e.mu
	// released. It reads the pair's relay KCP health, which takes e.kcpMu and
	// then the KCP session's own lock, so logging it here would hold the
	// engine's global lock across a KCP call — the exact inversion
	// relayKCPPairFor's contract forbids, and it would park every other peer's
	// lookup behind one session's RTT sample. Same shape as ensureSession,
	// which builds its rebuild attrs after dropping pc.mu.
	e.mu.Lock()
	var dead *peerConn
	if pc, ok := e.peers[peer]; ok {
		pc.mu.Lock()
		closed := pc.closed
		pc.mu.Unlock()
		if !closed {
			e.mu.Unlock()
			return pc
		}
		dead = pc
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
	e.armDesyncRecovery(peer, pc.secure)
	if dead == nil {
		e.mu.Unlock()
		return pc
	}
	// killSession closes the adapter, so recovering from a killed session
	// lands HERE — the replacement is a brand-new peerConn whose sess is nil,
	// and the in-place branch in ensureSession never runs. Logging the
	// rebuild only there reported nothing at all: a full e2e run showed
	// "relay session rebuilt" = 0 against "peer session killed" = 4, leaving
	// secureReuse unreported and nothing for the e2e to grep.
	dead.mu.Lock()
	prev, at := dead.secure, dead.sessAt
	gen := dead.sessionGen.Load()
	reason := dead.lastEndReason
	// The outage killSession dated is consumed here and nowhere else: read and
	// cleared in this one block, because a clear outside it races the stamp
	// under -race, and left set it would be reported against a later death.
	// It is not copied to the replacement — this line is that death's record.
	deadSince, silentFor := dead.deadSince, dead.silentFor
	dead.deadSince, dead.silentFor = time.Time{}, time.Duration(0)
	dead.mu.Unlock()
	// The rebuild counters are the pair's, not the adapter's: the
	// replacement continues them — and the pair's build timestamp with
	// them, which is what makes the replacement's first build count as a
	// rebuild (see sessionLocked's rebuild flag). One clean kill then shows
	// as exactly one rebuild, and Status keeps reporting the pair's count
	// across adapter swaps.
	pc.sessAt = at
	pc.relayRebuilds.Store(dead.relayRebuilds.Load())
	pc.relayRebuildPeers.Store(dead.relayRebuildPeers.Load())
	// The reason the killed session ended with is what the replacement's
	// first build will feed to the rebuild-storm check (see sessionLocked).
	pc.lastEndReason = reason
	// The storm is pair-scoped like the counters: a kill-driven rebuild that
	// landed here would otherwise restart the ring on every swap and never
	// accumulate (each fresh adapter would hold a single event). Carrying the
	// window state — events, warned, and the injected clock — keeps the
	// "exactly one WARN per window" guarantee across the swap.
	dead.storm.carryTo(&pc.storm)
	// The churn window is the same class of pair state: without it a peer
	// killed on every adapter restarts at zero per swap and the churn guard
	// can never trip on the kill-driven path.
	pc.churn, pc.churnFrom, pc.churnTripped = dead.churn, dead.churnFrom, dead.churnTripped
	// The new session starts at a zero streak, so the count that explains
	// the rebuild has to come off the session being replaced.
	var streak int
	var age time.Duration
	if prev != nil {
		streak = prev.desyncStreakValue()
	}
	if !at.IsZero() {
		age = time.Since(at)
	}
	rebuildAttrs := []any{
		"peer", keyName(peer),
		"secureReuse", prev == pc.secure,
		"desyncStreak", streak,
		"sessionAge", age.Round(time.Millisecond),
		"gen", gen,
	}
	// This line, not the kill's, is the record of one outage: a kill always
	// implies a rebuild here (killSession closed the adapter, so this is the
	// only way back), and the relay-side accept loop logs nothing at all when a
	// session dies — so a rebuild with no kill is the normal shape of a silent
	// keepalive timeout, not a missing event. See
	// docs/2026-10-08-p2p-peer-down-reading-the-logs.md.
	rebuildAttrs = append(rebuildAttrs, relayDownAttrs(reason, deadSince, silentFor, time.Now())...)
	e.mu.Unlock()

	// The pair's KCP session survives a clean kill (it is what the rebuild
	// continues on), so its health rides the same line; a kill whose reason
	// reset the pair already dropped it, and then there are no KCP attrs.
	// Read outside e.mu because that is where reading it belongs — and a
	// concurrent epoch reset in that window may retire the pair first, which
	// costs these attrs, not the rebuild this line records.
	rebuildAttrs = append(rebuildAttrs, e.relayKCPLogAttrs(peer)...)
	e.log.Debug("relay session rebuilt", rebuildAttrs...)
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
		if fs := e.faults.Load(); fs.muteDataArmed() && fs.muteData(clock.Now()) {
			continue
		}

		// peerConn creates the adapter for a peer we have not seen and drops a
		// closed one instead of handing it back. Reaching into the map directly
		// left a killed adapter (its session ended, e.g. on a queue overflow) in
		// place, so every later packet failed against it and the peer had no
		// inbound path at all until some outbound open happened to replace it.
		pc := e.peerConn(src)
		pc.lastFrameAt.Store(clock.UnixNano())
		// Ensure a session exists on this side too: inbound packets must be
		// consumed by smux (which then accepts streams) even when this host
		// never opens a tunnel to the peer itself.
		if _, err := pc.ensureSession(true, false); err != nil {
			// The session could not be built. Records already queued for this
			// peer are KCP segments the peer will retransmit, not consumed
			// records, so nothing is abandoned: the kill is a clean one that
			// keeps the settled keys and the pair's KCP session.
			pc.killSession(err, false, reasonBuildFailed)
			continue
		}
		select {
		case pc.inbound <- pkt:
		case <-pc.closeCh:
			// session already dead; drop
		default:
			// Queue overflow: KCP repairs ordinary loss below, but a queue
			// that stays full means this adapter is no longer draining, so
			// kill it as a conservative recovery and let the peer redial.
			// The dropped packets are KCP segments the peer retransmits, not
			// consumed records, so the pair's nonce sequence stays aligned: the
			// kill is a clean one that keeps the settled keys and the pair's
			// KCP session.
			pc.killSession(errors.New("derp engine: inbound queue overflow"), false, reasonQueueOverflow)
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
		// Only the relay transport: a bogus tag must not create a cached
		// session (respond would reject the half anyway).
		if clear[0] != secureTransportRelay {
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
			// The peer restarted: its half changed. Tear the relay mux session
			// down so it rebuilds over the new key (kill also unblocks the
			// parked read loop; a session left reading would eat the new
			// session's packets). The secure session itself is kept.
			e.resetPeerSession(src)
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
	// The pair's KCP epoch ends with the peer's, and this is the signal that
	// says the peer's ended: drop it unconditionally, BEFORE the adapter kill
	// below. killSession early-returns on an adapter that is already dead (a
	// clean kill left the pair running in the gap between adapters), and a
	// reset that no-ops leaves the pair's advanced sequence state in place to
	// discard the peer's fresh session's segments — the epoch mismatch the
	// coordination exists to prevent.
	gen := uint64(0)
	if pc != nil {
		gen = pc.sessionGen.Load()
	}
	e.dropRelayKCP(peer, nil, errors.New("derp engine: peer rekeyed"), gen)
	if pc != nil {
		// The one teardown a user cannot cause from either end: the peer changed
		// its key. It tears the session down every time, so its rate is the one
		// that separates "the network is flapping" from "we are churning".
		pc.relayRebuildPeers.Add(1)
		// The one kill that must NOT drop the secure session (dropSecure=false):
		// the peer changed its half and respond re-derived ours, so both
		// counters already match — re-handshaking would make the two ends swap
		// halves forever (see dropRelaySecure).
		pc.killSession(errors.New("derp engine: peer rekeyed"), false, reasonPeerRekeyed)
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

// errRelaySilent is the cause both watchdog strikes kill with: the relay path
// went silent. It is cause-grade (for the kill line and dropRelayKCP's cause
// passthrough), while the reasons differ per strike (relay-silent, then
// link-lost).
var errRelaySilent = errors.New("derp engine: relay path silent")

// relayLiveWindow is how recently the pair must have carried an underlay
// datagram for a dead session's death to read as "the session's, not the
// link's". A healthy relay session's smux NOPs cross in both directions every
// smuxKeepAliveInterval (3s), so a pair quiet past this window is not an idle
// link but a dead one, and rebuilding smux on it is the 15s-death loop. A
// var so tests can name the boundary without backdating stamps.
var relayLiveWindow = 6 * time.Second

// errRelaySessionStale is what a death report answers when the pair went
// quiet past relayLiveWindow: the death is reported, the rebuild is stood
// down, and the pair's own watchdog owns what happens next.
var errRelaySessionStale = errors.New("derp engine: relay pair stale, rebuild stood down")

// errRelaySessionSuperseded is what a death report answers when it is not
// for the adapter's live session — a kill swapped the adapter first, or the
// same session already reported. The death belongs to someone else's path.
var errRelaySessionSuperseded = errors.New("derp engine: death report superseded")

// keepalive keeps the DERP connection alive through proxy/CDN idle timeouts.
func (e *engine) keepalive(c *derpclient.Client) {
	ticker := time.NewTicker(keepAlivePeriod)
	defer ticker.Stop()

	// pingedAt is this loop's own: the probe and its verdict are the keepalive
	// goroutine's business, and a new connection starts a new loop.
	var pingedAt time.Time
	for range ticker.C {
		// The death verdict comes before the writes: on a half-open path the
		// writes below can block (buffered, then stuck) while nothing errors,
		// and the old order ran both writes before asking whether the path
		// was answering — each blocked write pushed detection further out
		// (seen: 2m13s of silence before the 45s ceiling fired). Read the
		// verdict off the already-kept timestamps, then write.
		now := time.Now()
		pong := c.LastPong()
		if relaySilent(pingedAt, pong, now) {
			pongAge := "never"
			if !pong.IsZero() {
				pongAge = now.Sub(pong).Round(time.Millisecond).String()
			}
			e.log.Error("derp: relay path dead, reconnecting", "pongAge", pongAge,
				"pongs", c.Pongs(), "frames", c.RecvFrames())
			e.teardown(c, fmt.Errorf("relay path unresponsive for %v (%d pongs, %d frames in)",
				relayDeadPeriod, c.Pongs(), c.RecvFrames()))
			return
		}
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
		// — below the ceiling — and the verdict above could never fire, leaving a
		// half-open relay in place forever. Candidate exchange rides the relay, so
		// that is also a punch that never succeeds again.
		now = time.Now()
		pong = c.LastPong()
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
// blipped. The direct path answers for itself through its own idle watchdog
// (see directUnderlayDead); a peer-gone notice does not retire it, and the pair
// is deliberately kept across the notice (H1) so a returning peer resumes
// without a rekey.
//
// For the same reason a live direct path keeps the pair (and its relay secure
// session) alive across the notice (H1, see resetsPairKCPFor): the relay half is
// merely unregistered. With no direct path the keys and the pair's KCP epoch go
// with the peer's relay connection exactly as before.
func (e *engine) peerGone(peer derpclient.PublicKey) {
	e.mu.Lock()
	e.gone[peer] = true
	pc := e.peers[peer]
	delete(e.peers, peer)
	dc := e.directs[peer]
	e.mu.Unlock()

	// Probed outside e.mu, like peerLive: dc.live takes dc.mu. A direct path
	// that dies in the window is still dropped by the killSession below, which
	// re-decides on the current paths.
	liveDirect := dc != nil && dc.live()
	if !liveDirect {
		e.mu.Lock()
		// The peer's relay connection dropped: forget its security session too.
		// The peer may have restarted (a new ephemeral will arrive), and holding
		// a stale key would leave the next rebuild mismatched. A peer that merely
		// blipped re-handshakes once on its return.
		delete(e.secure, secureKey{peer: peer, transport: secureTransportRelay})
		e.mu.Unlock()
	}
	gen := uint64(0)
	if pc != nil {
		gen = pc.sessionGen.Load()
	}
	if !liveDirect {
		// The pair's KCP session goes with the peer: its sequence state is with
		// a peer that is gone (or restarted), and a session left running would
		// leak its read loop.
		e.dropRelayKCP(peer, nil, errors.New("derp engine: peer gone"), gen)
	}
	if pc != nil {
		// A session-less adapter is a handshake in flight: killing it would fail
		// that open before its bounded wait can decide, and the peer may already
		// be back. Only a built session is torn down.
		pc.mu.Lock()
		built := pc.sess != nil
		pc.mu.Unlock()
		if built {
			pc.killSession(errors.New("derp engine: peer gone"), true, reasonPeerGone)
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
	directs := make(map[derpclient.PublicKey]*directConn, len(e.directs))
	for _, pc := range e.peers {
		peers = append(peers, pc)
		if dc := e.directs[pc.peer]; dc != nil {
			directs[pc.peer] = dc
		}
	}
	e.peers = make(map[derpclient.PublicKey]*peerConn)
	e.mu.Unlock()

	// A live direct path keeps the pair — and with it these keys — alive across
	// the relay loss (H1): the relay half is merely unregistered, and a
	// reconnect re-registers it without a re-handshake. Dropping the keys here
	// would force a needless re-handshake and could strand the live direct path.
	// Liveness is probed outside e.mu (dc.live takes dc.mu; see peerLive). A
	// direct path that dies in the window is still dropped by the killSession
	// below, which re-decides on the current paths.
	liveDirect := make(map[derpclient.PublicKey]bool, len(directs))
	for peer, dc := range directs {
		if dc.live() {
			liveDirect[peer] = true
		}
	}
	e.mu.Lock()
	for _, pc := range peers {
		if liveDirect[pc.peer] {
			continue
		}
		// The relay link is gone: forget each peer's relay security session so a
		// reconnect re-handshakes instead of reusing counters a lost record may
		// have advanced (see dropRelaySecure). Without this a peer whose link
		// dropped — the Wi-Fi<->cellular switch — would come back with our
		// sendCtr one ahead of its recvCtr, with no way to realign.
		delete(e.secure, secureKey{peer: pc.peer, transport: secureTransportRelay})
	}
	e.mu.Unlock()
	e.log.Error("derp connection lost", "error", cause)
	c.Close()
	for _, pc := range peers {
		pc.killSession(cause, true, reasonLinkLost)
	}
	// The peers' kills cover the pairs their adapters built; every other pair's
	// KCP session (an adapter already swapped out, its replacement never built)
	// rides the same dead relay and goes too.
	e.closeRelayKCPs(cause)
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
		pc.killSession(errors.New("engine closed"), true, reasonEngineClosed)
	}
	// As in teardown: pairs whose adapter is already gone are not in the loop
	// above, and a KCP session left running would leak its read loop. The engine
	// is closing, so force every pair down — a live direct path is about to be
	// torn down too (see the directs loop below).
	e.closeAllRelayKCPs(errors.New("engine closed"))
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
	// Under the KCP underlay this replacement is always transparent: the dead
	// session's records ride the pair's KCP byte stream, which survives the
	// rebuild, so the settled keys and nonce counters stay aligned and nothing
	// is re-handshaken. The byte-queue abandonment that used to force a
	// re-handshake here (a queued secure record whose nonce the peer had spent
	// but this side never drew) no longer exists — the queue now holds KCP
	// segments, which KCP retransmits, so a queued segment is still-to-be-read
	// pipe content, not unrecoverable crypto state. The log below is the only
	// record that the pair kept its keys; the streak is read off the session
	// being replaced — the replacement starts at zero and would report nothing.
	replaced := pc.sess != nil && pc.sess.IsClosed()
	secure := pc.secure
	var age time.Duration
	streak := 0
	gen := uint64(0)
	if replaced {
		age = time.Since(pc.sessAt)
		streak = secure.desyncStreakValue()
		// The generation of the session being replaced: the rebuild log
		// describes the old session, and this is the number that correlates it
		// with that session's kill (or, here, its own end).
		gen = pc.sessionGen.Load()
	}
	pc.mu.Unlock()

	var reason sessionEndReason
	var deadSince time.Time
	var silentFor time.Duration
	if replaced {
		// This path has no kill behind it, so the death has to be dated here:
		// nothing else observed it, and without this the rebuild line is the
		// only trace of an outage with no start time. The pair's recency is read
		// out of pc.mu (it takes the pair's lock) and the whole set is then read
		// out and cleared in one block.
		//
		// The IsZero guard keeps one death from being dated twice, but it is not
		// a barrier against a concurrent kill: killSession stamps in the same
		// block that publishes pc.closed, so a kill landing inside this window
		// either wins (this branch reports the kill's death) or lands after the
		// clear and is reported by that kill's own rebuild. Both are the later
		// death, so neither double-counts an outage.
		fresh, freshOK := pc.e.relayKCPFreshness(pc.peer)
		now := time.Now()
		pc.mu.Lock()
		if pc.deadSince.IsZero() {
			pc.deadSince = now
			pc.silentFor = 0
			if freshOK {
				pc.silentFor = now.Sub(fresh)
			}
		}
		reason, deadSince, silentFor = pc.lastEndReason, pc.deadSince, pc.silentFor
		pc.deadSince, pc.silentFor = time.Time{}, time.Duration(0)
		pc.mu.Unlock()
	}

	if replaced {
		replacedAttrs := []any{
			"peer", keyName(pc.peer),
			"secureReuse", true,
			"desyncStreak", streak,
			"sessionAge", age.Round(time.Millisecond),
			"gen", gen,
		}
		// An empty reason is the informative case, not a missing one: it says
		// the smux keepalive timeout judged this session dead with no kill at
		// all, which is the outage the relay-side accept loop logs nothing for.
		// One outage is one rebuild line whichever path it came by, and a
		// rebuild with no kill is normal — see
		// docs/2026-10-08-p2p-peer-down-reading-the-logs.md.
		replacedAttrs = append(replacedAttrs, relayDownAttrs(reason, deadSince, silentFor, time.Now())...)
		// The dead session died on its own (a clean end), so the pair's KCP
		// session survives and its health rides the rebuild line.
		replacedAttrs = append(replacedAttrs, pc.e.relayKCPLogAttrs(pc.peer)...)
		pc.e.log.Debug("relay session rebuilt", replacedAttrs...)
	}

	// No live session: settle the handshake before building, so both ends agree
	// on encrypted-vs-plaintext for this session. A settled security session
	// needs none of this: its keys outlive the mux session, so a rebuild just
	// reuses them, and a peer restart arrives as a changed half, not here. The
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
			if secure.waitReady(time.Duration(resendInterval.Load())) {
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

// relaySessionEvidence reports what the relay session to peer says about
// whether the peer is still there: live when a built session is serving now,
// fresh when one was built within controlBlackholeGrace (a killed adapter
// keeps its build time until the map drops it, and a replacement carries it
// across the swap, so "recently built" survives the death itself). It is the
// blackhole tripwire's discriminator between "the peer is answering on the
// relay data path but control hears nothing" (wedged registration) and "the
// peer is just gone" (a killed phone): only the former may trip a relay
// reconnect.
func (e *engine) relaySessionEvidence(peer derpclient.PublicKey) (live, fresh bool) {
	e.mu.Lock()
	pc := e.peers[peer]
	e.mu.Unlock()
	if pc == nil {
		return false, false
	}
	if pc.liveSession() {
		return true, true
	}
	pc.mu.Lock()
	at := pc.sessAt
	pc.mu.Unlock()
	if at.IsZero() {
		return false, false
	}
	return false, time.Since(at) < controlBlackholeGrace
}

// healControlBlackhole reconnects the relay on the punch control plane's
// behalf: enough consecutive control misses accumulated while the peer showed
// a relay session, so the registration — not the peer — is presumed wedged.
// It is the same cure the relay churn guard and the pong watchdog apply (a
// fresh registration is what clears stale server-side routing), tripped
// earlier by control-plane evidence. Rate limited engine-wide, and consuming
// the peer's live sighting, so one peer death costs at most one reconnect: a
// peer that never comes back shows no new live session afterwards.
func (e *engine) healControlBlackhole(peer derpclient.PublicKey, misses int) {
	e.mu.Lock()
	if time.Since(e.lastControlHeal) < controlBlackholeCooldown {
		e.mu.Unlock()
		return
	}
	e.lastControlHeal = time.Now()
	e.mu.Unlock()
	if dc := e.getDirect(peer); dc != nil {
		dc.resetControlMisses()
	}
	e.log.Error("derp: control blackhole suspected, reconnecting the relay",
		"peer", keyName(peer), "misses", misses)
	e.reconnectRelay(fmt.Errorf("peer %s missed %d punch control exchanges",
		keyName(peer), misses))
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
		// The dead session died on its own — any kill closes the adapter too
		// (killSession), so a killed session rebuilds through peerConn, not
		// here. Its keys were therefore kept, and the rebuild is transparent
		// over the surviving pair KCP session. The reason-driven key drop lives
		// in killSession (see resetsPairKCP) and could not run here anyway:
		// dropRelaySecure takes e.mu, which is taken before pc.mu elsewhere
		// (see peerConn).
		pc.sess = nil
	}
	if pc.sess != nil {
		return pc.sess, nil
	}
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = smuxKeepAliveInterval
	cfg.KeepAliveTimeout = smuxKeepAliveTimeout
	roleIsClient := bytes.Compare(pc.e.pub[:], pc.peer[:]) < 0
	// KCP under the record layer, mirroring the direct plane's
	// KCP -> secure -> smux stack: the relay is a lossy datagram path, and one
	// dropped packet desyncs the crypto record framing permanently ("bad
	// secure record length"). Over KCP it is one lost segment, retransmitted.
	//
	// The KCP session is the PAIR's (see relayKCPPair), not this adapter's: a
	// clean kill swaps the adapter and rebuilds smux and the record layer on
	// top of the same session, so the pair's sequence epoch does not restart
	// under a peer whose session is still running. This adapter registers as
	// the session's endpoint — the queue KCP reads from and the send it writes
	// through.
	pair := pc.e.relayKCPPairFor(pc.peer)
	pair.register(pc)
	kcpConn, err := pair.session()
	if err != nil {
		return nil, err
	}
	// The underlay is this mux session's own view of the pair's stream: it dies
	// with the session built on it (smux closes its underlay), retiring that
	// session's reader while the pair's KCP session below survives.
	stream := pair.newStream()
	underlay, err := pc.secure.conn(stream)
	if err != nil {
		// Nothing rides this view: retire it here rather than leave a reader
		// the next build would race. The pair's KCP session stays — it outlives
		// any one build (see relayKCPPair).
		stream.Close()
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
		stream.Close()
		return nil, errors.New("derp engine: cannot establish mux session")
	}
	if rebuild {
		pc.relayRebuilds.Add(1)
	}
	// pc.kcp is this adapter's view of the pair's KCP session (the pair owns
	// it): what the build rode, for the kill path and the KCP-underlay probes.
	pc.kcp = kcpConn
	pc.sessAt = time.Now()
	// A (re)build re-arms the relay idle watchdog for the new session: the
	// latch clears while the strikes carry, so a silence that continues past
	// a rebuild escalates to strike 2 instead of latching silent forever.
	// First builds clear nothing (the latch starts unset) — harmless.
	pair.rearmRelayIdle()
	// Every build — first included — gets a fresh, process-unique generation so
	// the up line, and a later kill/desync/KCP-reset on this session, all share
	// one number.
	pc.sessionGen.Store(sessionGenSeq.Add(1))
	if rebuild {
		// The rebuild-storm check runs only here, on the rebuild path: it
		// consumes the reason the previous session ended with (set by
		// killSession, copied across the adapter swap in peerConn) and warns
		// once per window when a peer rebuilds far too often.
		pc.recordRebuild(pc.lastEndReason)
		pc.lastEndReason = ""
	}
	pc.noteBuildLocked(pc.sessAt)
	_, _, enc := pc.secure.keys()
	pc.e.log.Debug("peer relay session up", "peer", keyName(pc.peer), "client", roleIsClient, "secure", enc, "gen", pc.sessionGen.Load())
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

// sessionEndReason is the structured cause of a relay session's end. The
// production symptom this exists for was a session rebuilt every 15s with
// nothing saying what killed it, so log aggregation groups on these values: a
// new death path picks the closest one rather than inventing a string at the
// call site. Keep it a closed set — a new value is a diagnosability change.
type sessionEndReason string

const (
	// reasonPeerGoneProbe: the bounded peer-gone probe expired with the peer
	// still unreachable, so the session is failed rather than left hanging.
	reasonPeerGoneProbe sessionEndReason = "peer-gone-probe"
	// reasonLocalKill: torn down locally with nothing to say about the peer.
	reasonLocalKill sessionEndReason = "local-kill"
	// reasonQueueOverflow: the adapter's inbound queue overflowed, meaning it
	// stopped draining. The kill is a conservative recovery; KCP repairs the
	// dropped segments below.
	reasonQueueOverflow sessionEndReason = "queue-overflow"
	// reasonLinkLost: the relay link carrying it went down.
	reasonLinkLost sessionEndReason = "link-lost"
	// reasonRelaySilent: the relay idle watchdog's first strike — the PAIR
	// went quiet past relayIdleWindow (neither underlay carrying, not relay
	// alone: a session living on direct sends nothing over relay). A clean
	// death by omission from resetsPairKCP: the pair's KCP session and keys
	// survive, so the rebuild is the cheap transparent one.
	reasonRelaySilent sessionEndReason = "relay-silent"
	// reasonPeerGone: the relay reported the peer is gone.
	reasonPeerGone sessionEndReason = "peer-gone"
	// reasonPeerRekeyed: the peer's identity changed under us (a restarted peer).
	reasonPeerRekeyed sessionEndReason = "peer-rekeyed"
	// reasonBuildFailed: the replacement session could not be built.
	reasonBuildFailed sessionEndReason = "build-failed"
	// reasonSecureDesync: the record framing could not realign, so the pair
	// re-handshakes (see noteDesync).
	reasonSecureDesync sessionEndReason = "secure-desync"
	// reasonEngineClosed: this process is shutting down.
	reasonEngineClosed sessionEndReason = "engine-closed"
	// reasonAdapterClosed: the adapter's underlay is gone.
	reasonAdapterClosed sessionEndReason = "adapter-closed"
)

// resetsPairKCP reports whether a kill with this reason must also end the
// pair-level KCP session (see relayKCPPair). The pair's sequence state survives
// adapter swaps; it cannot survive a reset of the far end's state or the end of
// the pair: a peer restart (rekey) comes with a fresh session starting at sn=0,
// a desync or dropped keys come with a re-handshake the peer answers by
// resetting too, a lost link or a gone peer ends the session on both sides, and
// the engine's end leaves nothing to run it. Every other reason is a clean
// adapter death — the pair's session runs on.
func resetsPairKCP(reason sessionEndReason) bool {
	switch reason {
	case reasonPeerGoneProbe, reasonLinkLost, reasonPeerGone, reasonPeerRekeyed, reasonSecureDesync, reasonEngineClosed:
		return true
	}
	return false
}

// relayChurnReason reports whether a kill reason describes the relay path going
// away while the pair itself may still be served by another underlay. A live
// direct path keeps the pair alive across these (H1); the other epoch-resetting
// reasons (a peer restart, a secure desync, engine shutdown) are path-
// independent and always reset.
func relayChurnReason(reason sessionEndReason) bool {
	switch reason {
	case reasonLinkLost, reasonPeerGone, reasonPeerGoneProbe:
		return true
	}
	return false
}

// pairHasLiveDirect reports whether the peer currently has a live direct path,
// so a relay-only failure must not tear the pair down (H1: the pair lives while
// any underlay lives).
//
// The signal is the pair's own direct-underlay recency (preferredDirect, the
// shared predicate of Task 3): the pair holds an installed underlay that
// delivered inbound traffic within directUnderlayIdle. It deliberately does not
// read the per-peer directConn's smux session, which will no longer carry the
// data plane once the unified underlay lands (Task 7). A pair that does not
// exist yet has no direct path, so it reports false.
//
// relayKCPPairGet takes kcpMu, the pair store's leaf lock, and preferredDirect
// takes the pair's own mu after kcpMu is released; neither nests e.mu, so this
// keeps the engine's lock order intact (unlike the directConn probe it
// replaces, which had to copy the pointer under e.mu and release first).
func (e *engine) pairHasLiveDirect(peer derpclient.PublicKey) bool {
	pair := e.relayKCPPairGet(peer)
	return pair != nil && pair.preferredDirect()
}

// resetsPairKCPFor reports whether a kill with this reason must end the pair's
// KCP epoch (and drop its relay secure session) given the peer's current paths.
// It is resetsPairKCP, except that a relay-churn reason no longer resets a pair
// a live direct path is keeping alive (H1). Evaluated once per kill so the
// secure drop and the KCP reset cannot disagree.
func (e *engine) resetsPairKCPFor(peer derpclient.PublicKey, reason sessionEndReason) bool {
	if !resetsPairKCP(reason) {
		return false
	}
	if !relayChurnReason(reason) {
		return true
	}
	// One lookup, so the suppression decision and the O1/O2 relay-loss signal
	// cannot disagree. The pair, when it exists, records whether a live direct
	// path kept this relay loss from resetting it — the explicit H1 signal.
	pair := e.relayKCPPairGet(peer)
	suppressed := pair != nil && pair.preferredDirect()
	if pair != nil {
		pair.noteRelayLoss(suppressed, string(reason))
	}
	return !suppressed
}

// killSession marks the adapter dead and tears down its session. Safe for
// concurrent use and for already-dead adapters.
//
// dropSecure asks for the pair's relay security session to be dropped when the
// kill ends the pair's KCP epoch for a reason that also resets the keys (see
// resetsPairKCP): a peer restart, a secure desync, a lost link, a gone peer or
// the engine's end all end the epoch, and once it ends the peer's nonce state
// can no longer align, so the pair must re-handshake (see dropRelaySecure). A
// clean kill — any other reason — keeps the session: the pair's KCP underlay
// survives the adapter swap and retransmits whatever segment is queued, so the
// nonce sequence is intact and the rebuild is the transparent one secure.go
// documents. The one caller that passes false is resetPeerSession (the peer
// rekeyed): there the peer already changed its half and respond re-derived
// ours, so both counters already match and a drop would make the two ends swap
// halves forever.
//
// Only the caller that flips the adapter dead decides the secure session, and
// it runs once: smux's session Close re-enters here through the underlay
// (Close), and a re-entry must not re-decide — it would drop what a
// killSession(cause, false) deliberately kept.
//
// reason names the cause for the log (see sessionEndReason). dropSecure in the
// log is the EFFECTIVE value, not the request: it is what explains whether the
// next rebuild reused its keys, so reporting the request would hide exactly the
// case that matters — a kill that dropped nothing because its reason is clean.
//
// The session's KCP underlay is NOT closed here unconditionally: it is the
// pair's session (see relayKCPPair), and a clean kill must leave it running so
// the rebuild continues the pair's sequence epoch instead of restarting at sn=0
// under a peer whose session is still running. It is closed exactly when the
// pair's epoch must reset with the kill (see resetsPairKCP): the keys were
// dropped (the peer resets alongside our changed half), the reason means the
// peer restarted or the pair is ending, or the engine is going away. smux's
// Close above reaches only the per-build stream view, never the pair's session.
func (pc *peerConn) killSession(cause error, dropSecure bool, reason sessionEndReason) {
	// Date the outage HERE, at the death, and out of pc.mu: reading the pair
	// takes its own lock, and pc.mu is taken under e.mu elsewhere. The
	// observation has to happen at this point and not when the rebuild log is
	// emitted, for two reasons — by emit time the peer may be sending again, so
	// the span collapses to ~0, and this same call resets the pair's KCP epoch
	// for six of the nine kill reasons (see resetsPairKCP), so dropRelayKCP
	// below deletes the pair and the rebuild is left with no recency at all.
	// Taking it after that deletion is the one order that loses the value.
	//
	// It also has to happen BEFORE pc.mu, not after it: the stamp below goes in
	// the same block that publishes pc.closed, and a rebuild reaching a dead
	// adapter in between would consume an unset death — emitting a line with no
	// downFor, and orphaning the stamp on an adapter already out of e.peers.
	// (See TestKillRecordsItsDeathBeforeTheAdapterReadsAsDead.)
	var fresh time.Time
	var freshOK bool
	if pc.e != nil {
		fresh, freshOK = pc.e.relayKCPFreshness(pc.peer)
	}

	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return
	}
	pc.closed = true
	pc.lastEndReason = reason
	// When the peer went dead, and how long it had been silent before that:
	// both observed above, both consumed by the next rebuild log, which is the
	// only reader (see relayDownAttrs and the peerConn field docs). Stamped
	// unconditionally, unlike ensureSession's IsZero guard: the pc.closed check
	// runs in this same block, so an adapter can only ever be dated once.
	// silentFor stays 0 when the engine held no pair to measure — see the field
	// doc for what that does and does not mean.
	pc.deadSince = time.Now()
	pc.silentFor = 0
	if freshOK {
		pc.silentFor = pc.deadSince.Sub(fresh)
	}
	close(pc.closeCh)
	sess := pc.sess
	kcpConn := pc.kcp
	pc.kcp = nil
	secure := pc.secure
	gen := pc.sessionGen.Load()
	// An adapter that never built a session has a zero sessAt; without the guard
	// the log reported the time since year 1 (2562047h47m16s).
	age := time.Duration(0)
	if !pc.sessAt.IsZero() {
		age = time.Since(pc.sessAt)
	}
	pc.mu.Unlock()

	// Under the KCP underlay a queued packet is a segment KCP will retransmit,
	// not a secure record whose nonce is lost, so the queue no longer decides
	// whether the pair re-handshakes. The re-handshake is driven by the kill
	// reason alone: a reason that resets the pair's KCP epoch (see
	// resetsPairKCP) ends the nonce alignment and must drop the secure half too
	// — except the peer-rekeyed teardown, which keeps the re-derived keys (the
	// caller passes dropSecure=false for exactly that reason).
	// A relay-churn reason no longer ends the pair when a live direct path is
	// keeping it alive (H1, see resetsPairKCPFor). Evaluated once so the secure
	// drop and the KCP reset agree on the same snapshot of the peer's paths.
	resetPair := pc.e != nil && pc.e.resetsPairKCPFor(pc.peer, reason)
	dropped := dropSecure && resetPair
	if dropped {
		pc.e.dropRelaySecure(pc.peer, secure)
	}
	if sess != nil {
		sess.Close()
	}
	// The pair's KCP session ends exactly when the kill reason says the pair's
	// epoch ends (see resetsPairKCP): a clean kill leaves it running so the
	// rebuild continues the pair's sequence, while a rekey/desync/link-loss/
	// gone/engine-close resets it alongside the keys — unless a live direct path
	// keeps the pair running across relay churn.
	if resetPair {
		pc.e.dropRelayKCP(pc.peer, kcpConn, cause, gen)
	}
	pc.e.log.Debug("peer session killed",
		"peer", keyName(pc.peer),
		"relayReason", reason,
		"dropSecure", dropped,
		"sessionAge", age.Round(time.Millisecond),
		"cause", cause,
		"gen", gen)
}

// Write sends one datagram as a single DERP SendPacket.
func (pc *peerConn) Write(p []byte) (int, error) {
	// Fault injection (see faults): the frame never reaches the relay, and the
	// write reports success — smux cannot tell this from a path that ate it.
	faults := pc.e.faults.Load()
	if faults.muteDataArmed() && faults.muteData(clock.Now()) {
		return len(p), nil
	}
	// Probabilistic loss on the relay data path only: KCP must retransmit the
	// dropped segment instead of the record framing above it desyncing.
	if faults.dropDataPacket() {
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

// Close closes the adapter, killing the session (streams and all). It does not
// touch the shared DERP transport.
func (pc *peerConn) Close() error {
	pc.killSession(errors.New("adapter closed"), false, reasonAdapterClosed)
	return nil
}

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
