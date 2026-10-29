package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

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
// the relay. The direct path is retired by its own idle watchdog, not by the
// peer-gone notice, and the pair is deliberately kept across the notice so a
// returning peer resumes without a rekey (H1, see underlayDead).

const (
	frameControl = 0x00 // [0x00][kind 1B][payload]
	frameData    = 0x01 // [0x01][smux byte stream]

	ctrlPunchCandidates = 0x02 // sealed candidate list
	ctrlCaps            = 0x04 // sealed capability bitfield (forward-looking seam)
	// 0x03 was the udp dial notice: a datagram link now always presents its own
	// edge, so no notice is sent and none is acted on. The kind stays unused.
	ctrlSecure = 0x05 // sealed [transport][ephemeral X25519 public key]
)

// Capability bits exchanged via ctrlCaps. Bit 0 marks IPv6 awareness. The frame
// is a negotiation seam: IPv6 selection does NOT depend on it — the candidate
// list is the in-band signal (a peer that offers a v6 candidate supports v6) —
// so an unset bit changes no behavior there. It is re-sent with every candidate
// broadcast so a lost frame or a late-joining peer cannot permanently degrade
// negotiation; the receiver ORs the bits.
const capsIPv6 uint8 = 1 << 0

// Bit 1 was capsTightKeepalive: it used to select the direct session's own,
// tighter smux keepalive. The KCP path migration removed that second session —
// the direct plane now rides the pair's session — so the bit is retired and
// ignored. Do not reuse it: an older peer may still advertise it.
//
// capsNoDirect marks a peer that has turned the direct path OFF
// (Config.Direct=false): it will neither start a round nor answer one. It
// exists so the other end stops asking. Without it, a host with direct on and
// a peer with it off is an unactionable asymmetry — the punching side sees
// "no peer candidates", reports "punch failed (often a symmetric NAT)", and
// retries forever, which sends the reader after a NAT problem that is not
// there. The pair is connected; one end asked for the relay.
//
// It is the one bit that is *cleared* rather than only ORed: a peer that
// announces candidates is punching, which is positive evidence it no longer
// holds the switch off, and a bit that only ever accumulated would pin the
// answer to the first frame a peer ever sent. Clearing on the candidate
// broadcast fails safe — a lost frame leaves the punching side doing one round
// it did not need — because the direction of the error is "asked when it
// should not have", not the reverse.
//
// Sent with the caps frame rather than on its own: a host with direct off sends
// no candidates, so this is the only frame it puts on the wire about punching.
const capsNoDirect uint8 = 1 << 2

// punchTraceCap is the number of recent punch steps a peer's Status.Trace
// holds: enough for a few failed rounds' worth of history, small enough to stay
// a fixed-size array (no per-round allocation).
const punchTraceCap = 16

// v6AnnounceFunc maps the bound IPv6 punch socket's port to the endpoint to
// advertise. Production advertises the socket's own local address; tests
// override it to force an unreachable candidate.
type v6AnnounceFunc func(port uint16) netip.AddrPort

// Direct timing. Vars so tests can shorten them.
var (
	punchTimeout = 10 * time.Second
	// punchWaitTimeout is retained as a configured knob (TimeoutsConfig.PunchWait)
	// but no longer gates anything: since M3 OpenStream does not block on a punch
	// (it opens on the pair and lets the stream migrate when the underlay lands),
	// so there is no wait to bound.
	punchWaitTimeout = 5 * time.Second
	// backoffPeriod is the floor of the punch's retry schedule. Atomic for the
	// same reason as resendInterval: the punch goroutine reads it when it
	// schedules a retry, and a test that overrides it (or restores it) while
	// an engine is still live would race that read.
	backoffPeriod = newAtomicDuration(30 * time.Second)
	// directRepunchBackoffCap caps the H3 hysteresis: the re-punch wait for a
	// direct that keeps dying shortly after registration grows from
	// backoffPeriod and stops here, so a flapping path settles into a slow
	// re-probe instead of a storm.
	directRepunchBackoffCap = 5 * time.Minute
	// deadPeerWaitCap bounds how long a punch waits for a peer that shows no
	// live path at all. See silentPeerWait.
	deadPeerWaitCap = 5 * time.Minute
	// relayWaitRetry is how long a punch waits for the relay to come back
	// before trying again; it is short because the relay is usually back
	// within the reconnect ticker's period.
	relayWaitRetry = 2 * time.Second
	stunTimeout    = 3 * time.Second
	// controlBlackholeThreshold is how many consecutive punch-control misses
	// (rounds that heard no peer candidates, plus gone-gate skips) with fresh
	// relay-session evidence trip a relay reconnect. Each miss is cheap
	// (a STUN lookup and a broadcast, or nothing at all for a skip), while a
	// wedged relay registration heals nothing until it is re-registered — the
	// field case was 2.5 minutes of doubling backoff behind a control channel
	// that delivered nothing. Vars so tests can shorten them.
	controlBlackholeThreshold = 3
	// controlBlackholeGrace bounds how stale the peer's relay session may be
	// for a miss to count: the session must be live now, or have been built
	// within this window. A peer that died long ago (a killed phone) stops
	// counting once its last build ages out, so it can never hold the relay
	// hostage. Together with the live-sighting requirement in
	// noteControlMiss, one peer death costs at most one reconnect.
	controlBlackholeGrace = 5 * time.Minute
	// controlBlackholeCooldown is the minimum gap between two
	// blackhole-triggered relay reconnects engine-wide: the reconnect tears
	// every peer's relay session down, so a repeatedly failing peer must not
	// flap it.
	controlBlackholeCooldown = 5 * time.Minute
	// candidateGrace is how long a round holds after taking a peer's candidate
	// list, for a fresher one to supersede it. See the call site in punch.
	candidateGrace = 200 * time.Millisecond
	// seedTimeout bounds the symmetric echo handshake (both peers must see
	// their own token round-trip before streams ride the session).
	seedTimeout = 5 * time.Second
)

// seedRetransmit is how often seedHandshakeUDP resends its probe while it waits
// for its own token to come back. The read deadline between sends is the same
// interval, so a retransmit and the wait for a reply interleave.
const seedRetransmit = 200 * time.Millisecond

// seedTokenLen is the per-side seed token length. Long enough that two peers
// never collide by chance, short enough to keep the probe tiny. The underlay
// uses it to tell a peer's probe from this side's own returning echo.
const seedTokenLen = 8

// errSeedTimeout reports that the raw-UDP seed handshake saw no echo of its own
// token before the timeout.
var errSeedTimeout = errors.New("host: seed handshake timeout")

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
	transportDirect            = "direct"             // live hole-punched session
	transportPunching          = "punching"           // a punch for this peer is in flight
	transportFailed            = "failed"             // this peer's punch failed (usually a symmetric NAT)
	transportPeerDirectOff     = "peer-direct-off"    // the peer has the direct path off (its Config.Direct)
	transportRelay             = "derp"               // on the relay, nothing in the way of a punch
	transportDisabled          = "disabled"           // the direct path is off (Config.Direct)
	transportNoCandidates      = "no-candidates"      // no STUN server and no IPv6 egress: nothing to punch with
	transportStunUnreachable   = "stun-unreachable"   // STUN configured but not answering, and no IPv6 fallback
	transportServerUnreachable = "server-unreachable" // the relay (server) is unreachable, so this peer has no data path to it
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

	mu     sync.Mutex
	state  directState
	failed bool // a punch round has failed at least once (sticky)
	// failGen counts punch rounds that have failed. failed alone cannot tell a
	// failure that happened while a caller was waiting for a punch from one that
	// happened long before it: failed is sticky for the life of the peer, so a
	// caller arriving after any historical failure would read it as "direct is
	// broken" and never wait again. failGen lets such a caller snapshot the
	// count and see only the failures that are actually its own.
	failGen uint64
	// sock is the punched UDP socket registered as the pair's direct underlay
	// while the direct path is up. The pair's KCP session reads and writes it
	// (see relayKCPPair); directConn tracks it for status and re-punch
	// bookkeeping only. There is no separate direct smux session any more.
	sock     *net.UDPConn
	peerAddr netip.AddrPort // the endpoint the peer answered the seed from
	mine     []candidate    // our candidates for the current punch, answered to the peer
	lastPeer []candidate    // peer candidates already acted on (dedupes re-announcements)
	peerCaps uint8          // capability bits the peer advertised via ctrlCaps
	peerQUIC *quicCaps      // peer's QUIC identity from the latest caps frame, nil when unusable
	lastErr  string         // the last punch failure's reason, cleared when one succeeds
	sessAt   time.Time      // when the current direct underlay came up (zero when none)

	// The peer's NAT shape, as the seed handshake saw it: the endpoint it
	// actually answered from, and whether that endpoint is one it announced.
	// A peer that answers from an endpoint it never announced has a mapping
	// that varies by destination (a per-destination NAT), or one that changed
	// since its own STUN probe. The punch still works — the learned address
	// is what gets dialled — so this is a shape fact, not a failure.
	//
	// peerEndpointDiffers is the verdict, and peerEndpointObservedAt when the
	// latest successful seed made the observation. The endpoint the peer
	// answered from is not kept here: the direct path already registers it
	// (markUp), and that is the value the report shows.
	//
	// The observation is sticky: a failed round makes none and leaves the
	// last one standing, because the question being answered is "why is this
	// peer still on the relay".
	// Guarded by mu like the rest of the round's state.
	peerEndpointDiffers    bool
	peerEndpointObservedAt time.Time

	// repunchBackoff is the hysteresis (H3) for a direct that dies shortly after
	// it came up: the re-punch wait grows geometrically from backoffPeriod up to
	// directRepunchBackoffCap while underlays keep dying young, and resets when
	// one survives its youth. Zero means none earned yet. Guarded by mu.
	repunchBackoff time.Duration

	// silentFor is the wait silentPeerWait last handed out, carried so the
	// growth survives across rounds while the peer stays silent. Zero means no
	// growth has been earned yet, and it resets the moment the peer has a path
	// again. Guarded by mu like the rest of the round's state.
	silentFor time.Duration

	// backoffUntil is when the armed re-punch backoff expires, so
	// PeerDiagnostic.NextPunchIn can answer "how long until we try again"
	// without reading the timer. Zero when no backoff is armed. Guarded by mu.
	backoffUntil time.Time

	// controlMisses counts consecutive punch-control failures while the peer
	// still showed a relay session recently: rounds that heard no peer
	// candidates, plus armed-timer skips behind the gone-gate. A control
	// channel that answers nothing while the relay looks connected is the
	// signature of a wedged registration (server-side routing stale after a
	// network switch), which no amount of re-punching heals — only a fresh
	// registration does. controlLiveSeen records that at least one counted
	// miss saw a live relay session, i.e. the peer was demonstrably answering
	// on the relay data path while control failed; without it a peer that
	// simply died could trip the reconnect. Both reset the moment control
	// works again (onCandidates), when direct comes up (markUp), when the
	// relay goes down (the reconnect loop owns the re-punch then), or when
	// the evidence goes stale. Guarded by mu.
	controlMisses   int
	controlLiveSeen bool

	// This peer's punch history, reported through Status.PeerDiagnostics. Atomics
	// so a status query reads them without taking dc.mu and queueing behind a
	// punch round; drops is also incremented while dc.mu is held, where a second
	// lock would enter the engine's lock order for no reason.
	attempts atomic.Int64 // punch rounds started
	ups      atomic.Int64 // rounds that reached a live direct session
	drops    atomic.Int64 // live direct sessions that ended

	// trace is this peer's recent punch history, a fixed-size ring of short
	// lines reported through Status.PeerDiagnostic.Trace. It holds the last
	// punchTraceCap steps (the snapshot's single value cannot show a flaky
	// punch's history). traceRing is allocated once and reused, so a round adds
	// no growing state; tracePos is the next write slot and traceN the count
	// written (saturating at the cap). Guarded by dc.mu.
	traceRing [punchTraceCap]string
	// traceTime is traceRing's parallel ring: traceTime[i] is when the line in
	// the same slot was written, so a reader can say when each step happened.
	// Allocated once with the ring, like it.
	traceTime [punchTraceCap]time.Time
	tracePos  int
	traceN    int

	// lastFrameAt is the UnixNano stamp of the last frame seen from this peer on
	// the direct path. A direct-first peer has no relay adapter (OpenStream goes
	// direct without ever building one), so the per-peer last-recv cannot live on
	// peerConn alone; the relay path keeps its own stamp there.
	lastFrameAt atomic.Int64
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

// directEnabled reports whether a punch could have a candidate source: a
// configured STUN server (IPv4), or the IPv6 family's switch.
//
// The v6 *egress* is deliberately not required here. It is probed per round, so
// an enabled family is a candidate source before the probe has found anything:
// gating on a usable address would keep a v6-only host from ever starting the
// round that discovers the egress — the DAD/DHCPv6-late case. A host with no
// egress still punches, fails, and backs off, which is exactly the retry that
// finds the egress when it appears.
//
// Side-effect free, so it is safe on the OpenStream/status paths.
func (e *engine) directEnabled() bool {
	if !e.direct {
		return false
	}
	return e.stunAddr != "" || e.v6Enabled
}

// relayConnected reports whether the relay connection is up: the punch's
// candidate exchange runs over it.
func (e *engine) relayConnected() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.client != nil
}

// maybeStartDirect kicks off hole punching when a candidate source exists.
// Idempotent: it only transitions directNone -> directAttempting, so concurrent
// triggers from OpenStream and pump converge on a single punch goroutine.
func (e *engine) maybeStartDirect(peer derpclient.PublicKey) {
	if !e.directEnabled() {
		return
	}
	dc := e.directConn(peer)
	if dc.peerDirectOff() {
		// The peer said it will not punch, so a round here is one it cannot
		// answer — and "no peer candidates" then reads as a network problem when
		// it is a setting. It will answer again the moment it turns punching
		// back on, which revokes the bit (notePunching) and lets this through.
		dc.noteRound("peer has the direct path off")
		return
	}
	dc.start()
}

// maybeKickDirect is the rebuild-path counterpart of maybeStartDirect: a session
// that died and was rebuilt (a network change) may have left the punch state in
// backoff, where start() is a no-op and the next round would not run until the
// backoff elapses — up to ~30s, which is what makes a returning device wait a
// minute before it punches. kick() clears that backoff (and the control-miss
// bookkeeping that armed it) and starts a round now, so a returning link can
// go direct within a second instead of waiting out the stale backoff.
func (e *engine) maybeKickDirect(peer derpclient.PublicKey) {
	if !e.directEnabled() {
		return
	}
	dc := e.directConn(peer)
	if dc.peerDirectOff() {
		dc.noteRound("peer has the direct path off")
		return
	}
	dc.kick()
}

// peerLive reports whether the peer currently has a live data path: a built
// relay session or a live direct one — the same definition of "connected" the
// status surfaces use (see peerTransports). It is NOT the gate for whether a
// punch can reach the peer: candidates ride the relay's *control* channel
// (sendControl, a DERP SendPacket), which needs only the relay connection, not
// a relay smux session. A host that never dialed the peer has no relay session
// to it, so peerLive reads that peer as dead the moment its direct session
// dies — which is why the re-punch gate uses peerGoneForPunch instead.
func (e *engine) peerLive(peer derpclient.PublicKey) bool {
	e.mu.Lock()
	pc, dc := e.peers[peer], e.directs[peer]
	e.mu.Unlock()
	if pc != nil && pc.liveSession() {
		return true
	}
	if dc != nil && dc.live() {
		return true
	}
	// A pair with a fresh direct underlay is a live data path in its own right
	// (M1): the accepting side of a punch can hold the pair before its relay
	// adapter exists, and the underlay — not the punch state machine — is what
	// carries traffic. relayKCPPairGet takes kcpMu, so it is called after e.mu
	// is released.
	if pair := e.relayKCPPairGet(peer); pair != nil && pair.preferredDirect() {
		return true
	}
	return false
}

// peerGoneForPunch reports positive evidence that the peer can no longer be
// punched: a relay session this side built has died, and no direct session is
// serving. It is the re-punch gate's predicate (see retry), deliberately
// narrower than peerLive. A peer with no relay session at all — a host that
// never dialed it, so it only ever had a direct path — is not reported gone: it
// has no session to die, so its liveness is unknown and a punch is the only
// probe there is. peerLive would read that peer as disconnected (no relay
// session, no live direct one) and stop the accepting side from re-punching a
// peer whose direct session died, leaving the pair stuck until the other side
// re-announces. In QUIC mode the established pair takes the place of the KCP
// relay session as the live path; the KCP session never exists there, so it
// must not be read as "gone".
func (e *engine) peerGoneForPunch(peer derpclient.PublicKey) bool {
	e.mu.Lock()
	pc, dc := e.peers[peer], e.directs[peer]
	e.mu.Unlock()
	if e.transport == transportQUIC {
		// QUIC has no KCP relay session, so pc.liveSession() is always false
		// there. An established QUIC pair is the live data path: treating it
		// as gone would make the retry timer skip every round, so a punch that
		// lost one seed (a transient send failure) could never try again.
		if pair := e.getQUIC(peer); pair != nil && pair.established() {
			return false
		}
	}
	return pc != nil && !pc.liveSession() && (dc == nil || !dc.live())
}

// warm brings up the peer's relay session (a smux session over the DERP
// adapter, no stream on it) so the peer counts as connected and has a path in
// Status before any traffic — and, when punch is set, starts a hole punch for
// it too. See sessionLocked for why the two are separable.
func (e *engine) warm(peer derpclient.PublicKey, punch bool) error {
	// One path with OpenStream: ensureSession takes pc.mu itself, releases it
	// before the punch (which takes e.mu), and acts on a churned peer, so the
	// lock order and the churn guard live in one place.
	_, err := e.peerConn(peer).ensureSession(punch, true)
	// A host with the direct path off says so on every warm, whether or not it
	// was asked to punch: this frame is the only thing it puts on the wire about
	// punching, so without it the other end can only infer the answer from
	// silence and report it as a failure. Sent after the session is up (the
	// control channel rides it) and re-sent on each warm, which idempotently
	// heals a lost frame.
	if err == nil {
		e.announceDirect(peer)
	}
	switch {
	case errors.Is(err, errEncryptionRequired):
		return p2p.ErrEncryptionRequired
	case errors.Is(err, errPeerSessionClosed):
		return p2p.ErrPeerUnreachable
	}
	return err
}

// announceDirect sends our caps to a peer, adding capsNoDirect when the direct
// path is off so the peer stops asking. In QUIC mode the frame starts from
// e.caps(), so it carries the QUIC bit and certificate TLV: addCaps treats a
// frame without the bit as authoritative and would clear the peer's learned
// fingerprint, and a peer with direct off has no punch frame to restore it. In
// KCP mode the IPv6 capability keeps riding the punch broadcasts (sendCaps'
// callers there) and only the "off" bit travels here.
func (e *engine) announceDirect(peer derpclient.PublicKey) {
	info := capsInfo{}
	if e.transport == transportQUIC && e.quicID != nil {
		info = e.caps()
	}
	if !e.directEnabled() {
		info.Bits |= capsNoDirect
	}
	if err := e.sendCaps(peer, info); err != nil {
		e.log.Debug("direct: announce direct-off failed", "peer", keyName(peer), "error", err)
	}
}

// start kicks off a punch when none is running, and reports whether this call
// started one: false when a punch is already in flight or backing off.
//
// The direct switch is checked here, at the one point every start routes
// through, rather than at each caller: the inbound path (a peer's candidate
// announcement) and the internal re-punch triggers (a dead session, a relay
// reconnect) reach it without the guard the outbound callers carry, and any of
// them starting a round would put the pair on a direct session the switch was
// turned off to prevent.
func (dc *directConn) start() bool {
	if !dc.e.directEnabled() {
		// Without this line, "the switch is off" and "the punch cannot start"
		// are the same silence in the log — which is exactly how a host built
		// with the switch off (and one whose STUN probe silently dropped the
		// server, see wisper's p2pHostStun) reads as a peer that never answers.
		dc.e.log.Info("direct punch: not attempted, the direct path is off",
			"peer", keyName(dc.peer), "reason", dc.e.directReason())
		return false
	}
	if dc.e.getDirect(dc.peer) != dc {
		// The engine dropped this instance: dropIfGone removed it (the relay
		// reported the peer gone and its underlay died) while a retry timer or
		// an in-flight round was still scheduled, and a later punch — the peer
		// coming back — built a new directConn in its place. A round from here
		// broadcasts candidates for a peer the map no longer tracks: the peer
		// answers with a real round, which replaces the healthy underlay the
		// new instance just installed, while this instance — whose candidate
		// slot no announcement fills any more — times out and re-arms itself,
		// a broadcast every punchTimeout+backoffPeriod (40s in the field)
		// forever. The dropped instance has nothing to punch for; the current
		// one (if any) owns the peer.
		return false
	}
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.state != directNone {
		return false
	}
	dc.state = directAttempting
	// The round is starting, so any armed backoff has served its purpose: a
	// status reader must not still see a "next punch in" for a punch in flight.
	dc.backoffUntil = time.Time{}
	go dc.punch()
	return true
}

// nextPunchIn reports how long until the armed re-punch backoff expires, 0 when
// none is armed (a round is in flight, the direct path is up, or nothing is
// scheduled). It is the O4 field that answers "how long until we try again"
// without reading the timer.
func (dc *directConn) nextPunchIn() time.Duration {
	dc.mu.Lock()
	until := dc.backoffUntil
	dc.mu.Unlock()
	if until.IsZero() {
		return 0
	}
	if d := time.Until(until); d > 0 {
		return d
	}
	return 0
}

// isUp reports whether this directConn believes it has a registered direct
// underlay: the punch reached directUp and its socket is held. It is a
// side-effect-free read for status (peerTransports/peerDiagnostics) and the
// re-punch gates; it never tears anything down. Real liveness — the path
// actually delivering — is the pair's own recency (preferredDirect).
func (dc *directConn) isUp() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.sock != nil
}

// live is isUp under the name the status call sites use. Kept separate so the
// gauge probe reads the same predicate without a session teardown (the trap
// TestDirectLiveNoSideEffect pins).
func (dc *directConn) live() bool { return dc.isUp() }

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
// punching reports whether a punch round is running for this peer right now. It
// is what separates "a round is in flight, wait for it" from "no round is
// coming, do not wait" when start() reports false for either.
func (dc *directConn) punching() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.state == directAttempting
}

func (dc *directConn) hasFailed() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.failed
}

// punchFailures returns the count of punch rounds that have failed for this
// peer. A caller waiting for a punch snapshots it and compares, so it can end
// its wait when a round fails but is not silenced by one that failed before it
// arrived.
func (dc *directConn) punchFailures() uint64 {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.failGen
}

// noteErr records why a punch round failed. The latest reason wins; markUp
// clears it on a success, so a live session never carries a stale failure.
func (dc *directConn) noteErr(reason string) {
	dc.mu.Lock()
	dc.lastErr = reason
	dc.mu.Unlock()
}

// lastErrOf reads the last punch failure's reason.
func (dc *directConn) lastErrOf() string {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.lastErr
}

// sessAtOf reads when the live direct session came up.
func (dc *directConn) sessAtOf() time.Time {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.sessAt
}

// stateName names the punch state machine's current state for a diagnostic
// reader.
func (dc *directConn) stateName() string {
	switch dc.stateOf() {
	case directAttempting:
		return "attempting"
	case directUp:
		return "up"
	case directBackoff:
		return "backoff"
	default:
		return "none"
	}
}

// candidateCount is how many candidates the peer last announced.
func (dc *directConn) candidateCount() int {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return len(dc.lastPeer)
}

// capNames names the capability bits the peer advertised.
func (dc *directConn) capNames() []string {
	dc.mu.Lock()
	bits := dc.peerCaps
	dc.mu.Unlock()
	var out []string
	if bits&capsIPv6 != 0 {
		out = append(out, "ipv6")
	}
	if bits&capsNoDirect != 0 {
		out = append(out, "no-direct")
	}
	if bits&capsQUIC != 0 {
		out = append(out, "quic")
	}
	return out
}

// punchCounters snapshots this peer's punch history. The counters are atomics,
// so this takes no lock: a status query must not queue behind a punch round.
func (dc *directConn) punchCounters() (attempts, ups, drops int64) {
	return dc.attempts.Load(), dc.ups.Load(), dc.drops.Load()
}

// noteRound appends one short line to this peer's punch trace, dropping the
// oldest once the ring is full. Called from the punch goroutine at the steps
// that matter for diagnosing a punch; never per packet.
func (dc *directConn) noteRound(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	now := time.Now()
	dc.mu.Lock()
	dc.traceRing[dc.tracePos] = line
	dc.traceTime[dc.tracePos] = now
	dc.tracePos = (dc.tracePos + 1) % punchTraceCap
	if dc.traceN < punchTraceCap {
		dc.traceN++
	}
	dc.mu.Unlock()
}

// traceSnapshot returns this peer's punch trace oldest-first — the lines and
// their parallel stamps — as copies, so a caller (a status builder) never
// aliases the ring. Both halves are read under one lock: a round appending
// between two separate reads would hand the reader a line list and a stamp
// list one step apart, and the UI zips them by index.
func (dc *directConn) traceSnapshot() ([]string, []time.Time) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.traceN == 0 {
		return nil, nil
	}
	lines := make([]string, dc.traceN)
	times := make([]time.Time, dc.traceN)
	start := (dc.tracePos - dc.traceN + punchTraceCap) % punchTraceCap
	for i := range lines {
		j := (start + i) % punchTraceCap
		lines[i] = dc.traceRing[j]
		times[i] = dc.traceTime[j]
	}
	return lines, times
}

// traceLines returns this peer's punch-trace lines, oldest-first.
func (dc *directConn) traceLines() []string {
	lines, _ := dc.traceSnapshot()
	return lines
}

// traceTimes returns this peer's punch-trace stamps, oldest-first and parallel
// to traceLines (same length, same order).
func (dc *directConn) traceTimes() []time.Time {
	_, times := dc.traceSnapshot()
	return times
}

func (dc *directConn) onCandidates(cands []candidate) {
	// A peer that is broadcasting candidates is punching, whatever it said
	// earlier: that revokes a capsNoDirect, so this end stops refusing to
	// answer. Done before the dedupe, so a re-announcement of an identical list
	// still counts as punching.
	dc.notePunching()
	// Candidates arrived: the control channel works, so any counted misses
	// describe a channel that no longer exists.
	dc.resetControlMisses()
	dc.mu.Lock()
	if sameCandidates(cands, dc.lastPeer) {
		dc.mu.Unlock()
		return // a re-announcement of candidates we already acted on
	}
	dc.lastPeer = cands
	mine := dc.mine
	if dc.state != directAttempting {
		// mine names the socket of a round that has already ended: a live
		// session (directUp) the peer's re-announcement just made stale, or a
		// backoff/teardown that already cleared it. Answering with it lets the
		// peer dial a socket we are about to abandon, whose KCP session rejects
		// the peer's new source address — the seed handshake then hangs until
		// seedTimeout and the round blows the punch budget. Only a round still in
		// flight (directAttempting) has fresh candidates worth answering with;
		// the re-punch started below publishes the fresh list instead.
		mine = nil
	}
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
		// Let a round run. A live direct path is not torn down for it: the
		// pair keeps serving its underlay whatever the punch state is, and
		// markUp replaces it only once a new punch actually succeeds. If this
		// peer's direct path really is stale (it restarted and we missed its
		// PeerGone), the round is what repairs it.
		dc.state = directNone
	}
	dc.mu.Unlock()
	dc.start()
}

// teardown closes the direct socket and returns to directNone without scheduling
// a re-punch (used on engine shutdown and in tests). It also retires the pair's
// direct underlay if this directConn owned it, so writes fall back to the relay
// at once instead of aging out the recency window.
func (dc *directConn) teardown() {
	dc.mu.Lock()
	sock := dc.sock
	dc.sock = nil
	dc.sessAt = time.Time{} // no live underlay: SessionAge must read 0, not the dead one's age
	dc.mine = nil
	dc.state = directNone
	dc.mu.Unlock()
	if sock == nil {
		return
	}
	if dc.e != nil {
		dc.e.retireDirect(dc.peer, sock)
	}
	sock.Close()
}

// markUp stores the freshly punched socket and marks the state up, installing
// the socket as the pair's direct underlay through the transport-agnostic hook
// (registerDirectUnderlay for KCP, quicPair.addDirect for QUIC). token is this
// side's raw-UDP seed token (Task 6): the underlay echoes the peer's late seed
// probes with it and drops its own returning echo, so two registered underlays
// cannot ping-pong.
//
// Installation comes first: a failed install closes the socket and does not
// mark the path up (no dc.sock, no session age), so the punch's normal backoff
// handles the retry instead of reporting a path the transport does not hold.
// The state stays directAttempting on failure: punch() calls backoff() right
// after markUp returns, and that single transition owns the next state. Clearing
// it to directNone here would let onCandidates (or the QUIC ensureTransport fast
// path) start a second round in the gap, which backoff() would then clobber —
// the overlapping-round race retryFrom(..., fromNone) guards elsewhere. QUIC
// requires an established pair; the hook returns an error when the pair is gone.
//
// A punch can succeed while an older underlay is still installed (it is re-run
// on the peer's announcements): the new socket replaces it, and the old one is
// retired by the install (setDirectUnderlay or addDirect closes it).
// Re-registering the same socket is skipped — the pair already holds it, and
// the KCP setDirectUnderlay would close it as the "old" underlay (Task 3
// contract).
func (dc *directConn) markUp(sock *net.UDPConn, peerAddr netip.AddrPort, token [seedTokenLen]byte) error {
	if sock == nil {
		return nil
	}
	// Keep the direct state lock across the install: the KCP registration
	// starts an asynchronous consumer that can retire the underlay at once (an
	// unsettled cipher), and it must observe the new dc.sock rather than run
	// before this function has recorded it. The install itself only swaps a
	// socket and starts local goroutines, so holding dc.mu here is bounded.
	dc.mu.Lock()
	prevSock := dc.sock
	// The pair already holds this socket: installing it again would make
	// setDirectUnderlay close it as the "old" underlay (Task 3 contract). QUIC's
	// addDirect has its own identity no-op, but the guard must hold for both.
	if prevSock != sock {
		if err := dc.e.installDirect(dc.peer, sock, peerAddr, token); err != nil {
			// Do not leave a failed install reported as a live path. The
			// transport refused the new underlay, so the predecessor cannot be
			// live either (in QUIC the pair that held it is gone). The state is
			// left for punch()'s backoff to transition exactly once.
			if dc.sock == prevSock {
				dc.sock = nil
				dc.sessAt = time.Time{}
				dc.peerAddr = netip.AddrPort{}
			}
			dc.mu.Unlock()
			sock.Close()
			if prevSock != nil && prevSock != sock {
				prevSock.Close()
			}
			dc.noteErr(fmt.Sprintf("direct install failed: %v", err))
			dc.noteRound("direct install failed: %v", err)
			return err
		}
	}

	dc.sock = sock
	dc.peerAddr = peerAddr
	dc.state = directUp
	dc.failed = false
	dc.lastErr = ""
	dc.sessAt = time.Now()
	// Direct is up: the control channel delivered, so any counted misses
	// describe a channel that no longer exists.
	dc.controlMisses = 0
	dc.controlLiveSeen = false
	dc.mu.Unlock()

	if prevSock != nil && prevSock != sock {
		// The install already replaced and closed it; this covers a dc.sock
		// whose pair underlay had gone away without the hook seeing it.
		prevSock.Close()
	}
	dc.e.stats.punchSuccess.Add(1)
	dc.ups.Add(1)
	return nil
}

// underlayDead is the pair's idle-watchdog path (Task 4's onDirectIdle): the
// direct underlay u went silent past directUnderlayIdle and directUnderlayDead
// has already retired it from the pair. Mark this directConn down and schedule a
// re-punch. A direct that died shortly after registration backs off
// exponentially (H3) instead of flapping direct↔relay; one that had a healthy
// lifetime re-punches at once. A round already in flight, or a backoff already
// armed, is left to finish — only an underlay that owned directUp schedules the
// re-punch, matching the old markDead.
//
// Non-blocking (H4): the socket was closed by clearDirectUnderlay, and the
// re-punch runs on its own goroutine (start) or its own timer (retry).
func (dc *directConn) underlayDead(u *directUnderlay) {
	dc.mu.Lock()
	if dc.sock == nil || (u != nil && dc.sock != u.sock) {
		dc.mu.Unlock()
		return // a newer underlay already replaced this one
	}
	lifetime := time.Since(dc.sessAt)
	sock := dc.sock
	dc.sock = nil
	dc.sessAt = time.Time{} // no live underlay: SessionAge must read 0
	if dc.state != directAttempting {
		dc.mine = nil // a round in flight owns its own candidate list
	}
	repunch := dc.state == directUp
	// A muted direct path is never coming back while the fault is armed: the
	// punch would just build another muted underlay that dies the same way.
	// Count the death (so callers waiting on it still see it) but do not
	// re-punch — the pair stays on the relay instead of flapping.
	muted := u != nil && u.muted != nil && u.muted()
	var backoff time.Duration
	if repunch {
		dc.state = directNone
		dc.drops.Add(1)
		backoff = dc.repunchBackoffAfterLocked(lifetime)
	}
	dc.mu.Unlock()
	// Retire through the transport hook. The KCP idle path has already cleared
	// its underlay, so this is an identity-checked no-op there; the reset path
	// (markDirectUnderlayRetired) and QUIC's future health path rely on it to
	// detach the dead socket from the transport.
	if sock != nil {
		dc.e.retireDirect(dc.peer, sock)
	}
	if !repunch {
		return // a round or a backoff is already rebuilding: it decides next
	}
	if muted {
		return // do not re-punch a muted path; stay on the relay
	}
	if dc.e.dropIfGone(dc.peer, dc) {
		// The peer is gone from the relay, so there is nothing to re-punch
		// with. The pair itself is deliberately left in place: a peer-gone
		// notice is best-effort and the peer may return — its direct path can
		// even re-punch on its own — and the pair carries the secure/KCP state
		// a fast resume needs (H1, TestPeerGoneKeepsLiveDirectSession). Tearing
		// it down here (without also dropping the secure session) desynced the
		// nonces of a still-open stream. A peer that truly never returns leaves
		// one idle pair, reclaimed when the engine closes or when a later
		// non-direct departure goes through peerGone's reset path.
		return
	}
	if backoff > 0 {
		dc.e.log.Debug("direct underlay died young, re-punching after backoff",
			"peer", keyName(dc.peer), "lifetime", lifetime.Round(time.Millisecond).String(),
			"backoff", backoff.String())
		// Guarded: onCandidates may have started a round since the state was
		// cleared above, and retry must not clobber it (I6).
		dc.retryFrom(backoff, false, true)
		return
	}
	dc.e.log.Debug("direct underlay died, punching again", "peer", keyName(dc.peer))
	dc.start()
}

// repunchBackoffAfterLocked updates and returns the wait before the next punch
// after a direct underlay died with the given lifetime (H3). A direct that
// survived at least 2×directUnderlayIdle resets the hysteresis and re-punches at
// once (0). A younger one grows the stored backoff geometrically from
// backoffPeriod, capped at directRepunchBackoffCap. Caller must hold dc.mu.
func (dc *directConn) repunchBackoffAfterLocked(lifetime time.Duration) time.Duration {
	if lifetime >= 2*time.Duration(directUnderlayIdle.Load()) {
		dc.repunchBackoff = 0
		return 0
	}
	if dc.repunchBackoff == 0 {
		dc.repunchBackoff = time.Duration(backoffPeriod.Load())
	} else {
		dc.repunchBackoff *= 2
	}
	if dc.repunchBackoff > directRepunchBackoffCap {
		dc.repunchBackoff = directRepunchBackoffCap
	}
	return dc.repunchBackoff
}

// addCaps records the capabilities the peer advertised. The bits are sticky
// (OR): IPv6 describes a capability, and a frame that omits it must not clear
// it. capsNoDirect is the exception — it is a setting, not a capability, so it
// is level-triggered (see its definition).
//
// The QUIC TLV is the peer's current identity, not a capability, so the latest
// valid frame wins. It is stored only when that frame both sets capsQUIC and
// carries usable parameters; otherwise it is dropped, because a stale
// fingerprint would pin the peer to an identity it no longer holds.
func (dc *directConn) addCaps(info capsInfo) {
	dc.mu.Lock()
	before := dc.peerCaps
	hadQUIC := dc.peerQUIC != nil
	// capsNoDirect is level-triggered — it reflects the peer's switch *now*, so
	// the last advertisement wins and a frame without it revokes an earlier one
	// (which is what a peer sends along with its candidate broadcasts once it
	// starts punching again). The rest are sticky: they describe a capability,
	// not a setting, and a frame that omits one must not clear it.
	dc.peerCaps = (dc.peerCaps &^ capsNoDirect) | info.Bits
	if info.Bits&capsQUIC != 0 && info.QUIC != nil {
		q := *info.QUIC
		dc.peerQUIC = &q
	} else {
		dc.peerQUIC = nil
	}
	after := dc.peerCaps
	hasQUIC := dc.peerQUIC != nil
	dc.mu.Unlock()
	if dc.e != nil && (after != before || hasQUIC != hadQUIC) {
		dc.e.log.Debug("direct punch: peer caps", "peer", keyName(dc.peer),
			"ipv6", after&capsIPv6 != 0,
			"noDirect", after&capsNoDirect != 0,
			"quic", hasQUIC)
	}
}

// peerQUICInfo returns the peer's current QUIC identity. ok is false when the
// peer has not advertised capsQUIC with a usable TLV.
func (dc *directConn) peerQUICInfo() (quicCaps, bool) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.peerQUIC == nil {
		return quicCaps{}, false
	}
	return *dc.peerQUIC, true
}

// notePunching records that the peer is punching (it broadcast candidates),
// which revokes a capsNoDirect it advertised earlier: the switch is back on, and
// a host that keeps the bit would refuse to punch a peer that is asking.
func (dc *directConn) notePunching() {
	dc.mu.Lock()
	cleared := dc.peerCaps&capsNoDirect != 0
	dc.peerCaps &^= capsNoDirect
	dc.mu.Unlock()
	if cleared {
		dc.e.log.Debug("direct punch: peer resumed punching", "peer", keyName(dc.peer))
	}
}

// peerDirectOff reports whether the peer advertised capsNoDirect and has not
// since broadcast candidates: this end must not start a round for it, because a
// round it cannot answer is what produced the endless "punch failed" report.
func (dc *directConn) peerDirectOff() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.peerCaps&capsNoDirect != 0
}

// supports reports whether the peer has advertised all of the given capability
// bits. IPv6 selection does not depend on it: the candidate list is the in-band
// signal there.
func (dc *directConn) supports(bits uint8) bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.peerCaps&bits == bits
}

// peerAddrString returns the endpoint the peer answered the seed from — the
// one the direct path actually uses, not the candidate that was dialled: a
// peer behind a per-destination NAT answers from a different endpoint than
// the one it advertised, and the path follows the one that answered. This is
// the "peer addr" line of the peer block.
func (dc *directConn) peerAddrString() string {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if !dc.peerAddr.IsValid() {
		return ""
	}
	return dc.peerAddr.String()
}

// notePeerEndpoint records the endpoint a peer answered the seed from, and
// whether that endpoint is one it announced.
//
// The observation is the latest successful seed: a later one replaces the
// earlier verdict entirely, and a failed round makes no observation and
// leaves the last one standing — a shape seen an hour ago is still the reason
// a peer is on the relay.
//
// The trace line is written outside dc.mu: noteRound takes the same lock, so
// calling it under the lock would deadlock.
func (dc *directConn) notePeerEndpoint(answered netip.AddrPort, announced []netip.AddrPort) {
	differs := !containsAddr(announced, answered)

	dc.mu.Lock()
	dc.peerEndpointDiffers = differs
	dc.peerEndpointObservedAt = time.Now()
	dc.mu.Unlock()

	if differs {
		dc.noteRound("peer answered from %s (not announced)", answered)
	}
}

// natEndpoint returns the peer's NAT shape observation: whether the endpoint
// it answered from is one it announced, and how long ago the observation was
// made (zero when there was none).
//
// The age is measured under the same lock that wrote the stamp, against the
// same clock, so it can never come out negative.
func (dc *directConn) natEndpoint() (differs bool, age time.Duration) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.peerEndpointObservedAt.IsZero() {
		return dc.peerEndpointDiffers, 0
	}
	return dc.peerEndpointDiffers, time.Since(dc.peerEndpointObservedAt)
}

// silentPeerWait returns how long to wait before the next punch round, given
// the wait the caller asked for.
//
// A peer that shows no live path at all has nothing to answer a round, and one
// that has no relay session to this host — the accepting side of a pair that
// only ever had a direct path — can never produce the positive evidence
// peerGoneForPunch looks for, so it is re-punched at backoffPeriod for as long
// as it stays away: a STUN lookup, a broadcast and a timeout every 30s, the
// field case the gate above was written to stop (a killed phone re-punched every
// 30s for over an hour). So while the peer shows no path the wait grows
// geometrically, capped at deadPeerWaitCap, which keeps a phone that comes back
// reachable within minutes instead of never.
//
// Growth is confined to that case. A peer with a live path keeps the wait the
// caller asked for, because there the round is probing a path that blipped —
// the phone's Wi-Fi ↔ cellular switch — and must be re-probed promptly. The
// growth resets as soon as a path is there again, so a peer that returns does
// not inherit the wait its absence earned.
func (dc *directConn) silentPeerWait(d time.Duration) time.Duration {
	if dc.e.peerLive(dc.peer) {
		dc.mu.Lock()
		dc.silentFor = 0
		dc.mu.Unlock()
		return d
	}
	dc.mu.Lock()
	next := dc.silentFor
	if next < d {
		next = d
	}
	next *= 2
	if next > deadPeerWaitCap {
		next = deadPeerWaitCap
	}
	dc.silentFor = next
	dc.mu.Unlock()
	return next
}

// backoff marks a failed punch and schedules a retry.
func (dc *directConn) backoff() {
	dc.retry(dc.silentPeerWait(time.Duration(backoffPeriod.Load())), true)
}

// resetControlMisses forgets the counted control failures: control demonstrably
// works again (or the channel they were counted on is gone), so the old misses
// say nothing about the current one.
func (dc *directConn) resetControlMisses() {
	dc.mu.Lock()
	dc.controlMisses = 0
	dc.controlLiveSeen = false
	dc.mu.Unlock()
}

// noteControlMiss records one punch-control failure against the blackhole
// tripwire. live/fresh describe the peer's relay session when the wait
// started: live says a relay session was serving (the peer was answering on
// the relay data path while control failed), fresh says one was built within
// controlBlackholeGrace. A miss without fresh evidence — no relay session in
// living memory, or the relay itself down — resets the count instead: the
// peer is likely just gone, and gone peers must never trip a relay reconnect.
//
// When enough consecutive misses accumulate with at least one live sighting,
// the registration is presumed wedged and the relay is reconnected (rate
// limited engine-wide): the same cure the relay churn guard and the pong
// watchdog apply, but tripped by the control plane instead of the data plane.
func (dc *directConn) noteControlMiss(live, fresh bool) {
	if !dc.e.relayConnected() {
		dc.resetControlMisses()
		return
	}
	if dc.peerDirectOff() {
		// The peer said it will not punch: unanswered rounds are by design,
		// not a wedged registration, and must never trip a relay reconnect.
		dc.resetControlMisses()
		return
	}
	if !fresh {
		dc.resetControlMisses()
		return
	}
	dc.mu.Lock()
	dc.controlMisses++
	if live {
		dc.controlLiveSeen = true
	}
	fire := dc.controlMisses >= controlBlackholeThreshold && dc.controlLiveSeen
	misses := dc.controlMisses
	dc.mu.Unlock()
	if fire {
		dc.e.healControlBlackhole(dc.peer, misses)
	}
}

// kick restarts a backed-off punch at once: a backoff armed on a dead relay
// registration was earned on a channel that no longer exists, so a reconnect
// must not sit out the remainder behind it. Only a backoff is cut short — a
// round in flight, or a live direct path, is left alone. The miss count goes
// with the old channel (fresh registration, fresh evidence), while the
// silent-peer doubling is kept: a dead peer stays a slow re-probe.
func (dc *directConn) kick() {
	dc.mu.Lock()
	if dc.state == directBackoff {
		dc.state = directNone
		dc.backoffUntil = time.Time{}
	}
	dc.controlMisses = 0
	dc.controlLiveSeen = false
	dc.mu.Unlock()
	dc.start()
}

// retry reschedules the punch after d. failed says a *round* failed — the relay
// being away is not a failure, it is a reason to wait: nothing can be exchanged
// without it, and the round would otherwise back off for 30s over a network
// blip (the phone's Wi-Fi ↔ cellular switch).
func (dc *directConn) retry(d time.Duration, failed bool) {
	dc.retryFrom(d, failed, false)
}

// retryFrom is retry with an optional state guard. fromNone makes it refuse to
// run unless the state is still directNone, so a re-punch scheduled off the idle
// watchdog (underlayDead) cannot clobber a round a peer's candidate announcement
// started in the meantime (onCandidates → start); without the guard, retry's
// unconditional state=directBackoff/mine=nil wipes that round's state and
// candidates (I6). A guarded refusal is safe: a round is running, so it decides
// what happens next.
func (dc *directConn) retryFrom(d time.Duration, failed bool, fromNone bool) {
	dc.mu.Lock()
	if fromNone && dc.state != directNone {
		dc.mu.Unlock()
		return
	}
	dc.state = directBackoff
	dc.backoffUntil = time.Now().Add(d)
	dc.failed = dc.failed || failed
	if failed {
		dc.failGen++
	}
	// The round's sockets are gone, so its candidate list is not ours to offer
	// any more: onCandidates answers a peer's announcement with dc.mine, and
	// echoing a dead endpoint races the peer's own fresh list into its slot.
	dc.mine = nil
	dc.mu.Unlock()
	dc.e.log.Debug("direct punch: backoff", "peer", keyName(dc.peer), "retryIn", d.String())
	// The trace line rounds to 10ms so it never prints a long tail of
	// fractional seconds; the scheduler above still waits the exact d.
	dc.noteRound("backoff %s", d.Round(10*time.Millisecond).String())
	go func() {
		select {
		case <-dc.e.stop:
			return
		case <-time.After(d):
		}
		if dc.e.getDirect(dc.peer) != dc {
			// The engine dropped this instance while the timer ran (see
			// start): a newer directConn owns the peer, and a round from here
			// would replace its healthy underlay and re-arm this timer
			// forever. Do not punch, and do not re-arm either.
			return
		}
		// A peer that is gone cannot answer a round, so skip it: running one only
		// burns a STUN lookup, a broadcast and a timeout, forever (the field
		// case: a killed phone re-punched every 30s for over an hour). The gate
		// is peerGoneForPunch — positive evidence of death, a relay session that
		// died with no direct session serving — not peerLive, which would also
		// skip a peer this side never dialed (no relay session) whose direct
		// session just died, and so strand the accepting side of a re-punch.
		// Nothing announces a dead peer: an open relay sends no PeerGone, and
		// only the relay keepalive's silence shows the session died.
		//
		// Re-arm rather than stop. Stopping would leave the state in
		// directBackoff with no timer, and start() refuses to run from there —
		// so a peer that came back could never be punched again: the field case
		// is a phone that reconnected and sat on the relay for good.
		//
		// A peer that advertised the direct path off is skipped the same way, so
		// a round armed before that advertisement does not run behind its back —
		// the first symptom being that an endless "punch failed" keeps coming
		// from a peer that said it was never going to answer.
		gone := dc.e.peerGoneForPunch(dc.peer)
		if gone || dc.peerDirectOff() {
			// A skip is a control attempt abandoned: the round never ran, so
			// nothing was exchanged. Counted like a failed round when the
			// peer might still be there — behind a wedged registration the
			// skips are what the backoff degrades into — with the evidence
			// taken now. A peer that turned the direct path off is never
			// counted: it will not answer by design, and must not trip a
			// relay reconnect.
			if gone {
				live, fresh := dc.e.relaySessionEvidence(dc.peer)
				dc.noteControlMiss(live, fresh)
			}
			dc.retry(dc.silentPeerWait(d), false)
			return
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

func (dc *directConn) punch() {
	e := dc.e
	pname := keyName(dc.peer)

	// Candidates are exchanged over the relay: with no connection there is
	// nothing to announce and nothing to answer with, so wait for it rather
	// than failing the round.
	if !e.relayConnected() {
		e.log.Debug("direct punch: no relay connection, waiting", "peer", pname)
		dc.retry(relayWaitRetry, false)
		return
	}

	e.stats.punchAttempts.Add(1)
	dc.attempts.Add(1)
	dc.noteRound("round start")

	// 1. Collect one socket + candidate set per available family. A family that
	// cannot be set up is dropped and the round continues on whatever remains,
	// so an unreachable STUN server no longer aborts a v6-capable punch.
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
	// Resolve the IPv6 source for this round. The family is opt-in and the
	// egress is re-probed every round: an egress that appeared or changed since
	// startup is picked up without a restart (see resolveV6).
	if v6 := e.resolveV6(); v6 != nil {
		if sock, mine, err := e.collectV6(v6); err != nil {
			e.log.Debug("direct punch: v6 unavailable", "peer", pname, "error", err)
		} else {
			fams = append(fams, family{name: "v6", v6: true, sock: sock, mine: mine})
		}
	}
	// Every socket is closed on all exits except the winner, which is handed to
	// markUp (and then owned by the pair's direct underlay). A close of an
	// already-closed socket is a harmless no-op.
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
	// The direct underlay rides the pair's existing secure session (tag 0x00,
	// negotiated with the relay session); there is no separate direct secure
	// session to negotiate or rekey (Task 9 removes the direct half entirely).
	if err := e.sendCaps(dc.peer, e.caps()); err != nil {
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
	// Capture the relay-session evidence before waiting: a session that is
	// alive now proves the peer answers on the relay data path, so hearing
	// no candidates back is control-plane failure, not a dead peer. Taken
	// up front because the session may die during the wait itself.
	ctrlLive, ctrlFresh := e.relaySessionEvidence(dc.peer)
	cands, ok := dc.waitCandidates(ctx)
	if !ok {
		e.log.Debug("direct punch: no peer candidates", "peer", pname)
		closeFams()
		dc.noteErr("no peer candidates")
		dc.noteRound("no peer candidates")
		dc.noteControlMiss(ctrlLive, ctrlFresh)
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
	dc.noteRound("peer candidates: %d", len(cands))

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
		dc.noteErr("no shared family")
		dc.noteRound("no shared family")
		dc.backoff()
		return
	}

	// 4. Attempt every family at once, then adjudicate: a family outranks the
	// ones after it, so v6 wins whenever it completes and a completed v4
	// handshake is held until v6 has reported a failure.
	//
	// Running them concurrently is what keeps a blind v6 from starving v4.
	// Sequentially, each side spent its seed timeout on v6 before dialling v4,
	// so two peers whose v6 paths were both blind could keep their v4 windows
	// offset and never meet: their seeds timed out at each other forever and
	// the pair stayed on the relay. Every attempt here starts from the same
	// candidate list, so the two sides' windows overlap by construction.
	//
	// The seed requires a full own->peer->own round trip on both sides, so a
	// one-way path fails on both peers. A winning socket is registered as the
	// pair's direct underlay; the encryption it rides is the pair's relay
	// secure session, so there is no separate direct secure gate here.
	type attempt struct {
		dial netip.AddrPort
		out  seedOutcome
		err  error
	}
	dials := make(map[int]netip.AddrPort, len(order))
	done := make(map[int]<-chan attempt, len(order))
	for _, idx := range order {
		f := &fams[idx]
		dial := dialFor(f, peerV4, peerV6)
		dials[idx] = dial
		ch := make(chan attempt, 1)
		done[idx] = ch
		e.log.Debug("direct punch: seed", "peer", pname, "family", f.name, "addr", dial.String())
		dc.noteRound("%s seed %s", f.name, dial.String())
		go func(f *family, dial netip.AddrPort, ch chan<- attempt) {
			out, err := seedHandshakeUDPToken(f.sock, dial, seedTimeout)
			ch <- attempt{dial: dial, out: out, err: err}
		}(f, dial, ch)
	}

	// Adjudicate in preference order, waiting only on the families that can
	// still outrank the current best: the wait on an already-started attempt
	// costs nothing when it has finished.
	winner := -1
	var winOut seedOutcome
	waited := make(map[int]bool, len(order))
	for _, idx := range order {
		f := &fams[idx]
		res := <-done[idx]
		waited[idx] = true
		if res.err != nil {
			dc.noteSeedFailure(f.name, res.err, res.out.ProbeFrom)
			e.log.Debug("direct punch: seed failed", "peer", pname, "family", f.name, "addr", res.dial.String(), "error", res.err, "probe_from", probeFromText(res.out.ProbeFrom))
			e.noteSeed(dc.peer, "timeout", f.name, res.dial.String())
			continue
		}
		winner = idx
		winOut = res.out
		break
	}
	if winner < 0 {
		// Every available family failed this round.
		closeFams()
		dc.backoff()
		return
	}

	// The families below the winner are abandoned, not failed: close their
	// sockets and wait for their goroutines to exit before any socket here is
	// touched again (closeFams and markUp both move sockets). An abandoned
	// attempt never records a seed failure — the v4 leg of a healthy v6 round
	// is not a failure, and counting it would poison the failure rate — but a
	// handshake that had already completed records its success truthfully.
	for _, idx := range order {
		if waited[idx] {
			continue
		}
		if fams[idx].sock != nil {
			fams[idx].sock.Close()
		}
		res := <-done[idx]
		// The trace must agree with the seed record below: a handshake that
		// had already completed when the other family won is discarded with
		// its success intact, so calling it "cancelled" would contradict the
		// seed result=ok line a reader greps next to it. Only an attempt that
		// was actually cut short is cancelled.
		word := "cancelled"
		if res.err == nil {
			word = "completed, unused"
		}
		dc.noteRound("%s %s (%s up)", fams[idx].name, word, fams[winner].name)
		if res.err == nil {
			e.noteSeed(dc.peer, "ok", fams[idx].name, res.dial.String())
		}
	}

	win := &fams[winner]
	sock := win.sock
	win.sock = nil // owned by the pair's direct underlay
	closeFams()    // drop the cancelled families' sockets
	e.noteSeed(dc.peer, "ok", win.name, dials[winner].String())
	// The peer's NAT shape, as this round saw it: the endpoint it answered
	// from, against the endpoints it announced (the freshest list, in this
	// round's family). A peer that answers from somewhere else has a mapping
	// that varies by destination, or one that changed since its own STUN
	// probe. The punch still works — the learned address is what gets
	// dialled — so this is a shape fact to report, not a failure.
	announced := announcedFor(win.v6, peerV4, peerV6)
	dc.notePeerEndpoint(winOut.Answer, announced)
	// Only the winner's socket is still bound, so only its candidates are ours
	// to answer a peer's announcement with.
	dc.mu.Lock()
	dc.mine = win.mine
	dc.mu.Unlock()
	// Register the endpoint that actually answered the seed, not the stale
	// candidate that was dialed: the steady-state underlay filters by source,
	// so it must follow the completed path.
	if err := dc.markUp(sock, winOut.Answer, winOut.Token); err != nil {
		// The transport refused the underlay (a QUIC pair that closed while the
		// round was in flight): markUp closed the socket and did not mark the
		// path up, so the normal backoff owns the retry.
		e.log.Debug("direct punch: install failed", "peer", pname, "family", win.name, "error", err)
		dc.backoff()
		return
	}
	dc.noteRound("%s up", win.name)
	e.log.Debug("direct established", "peer", pname, "family", win.name,
		"mine", candAddrs(win.mine), "peerAddr", winOut.Answer.String())
}

// family is one address family's attempt in a punch round: the socket it
// punched on, the candidates it announced, and the word the trace and the logs
// use for it. A round has at most one v4 and one v6 family.
type family struct {
	name string
	v6   bool
	sock *net.UDPConn
	mine []candidate
}

// dialFor picks the peer endpoint a family's seed handshake dials. IPv6 peers
// advertise a single egress address, so "first" is unambiguous. IPv4 prefers
// the peer's public candidate, except when both ends sit behind the same public
// address (the hairpin case): there the peer's local candidate is the one that
// answers, because a NAT rarely hairpins its own mapping back.
func dialFor(f *family, peerV4, peerV6 []netip.AddrPort) netip.AddrPort {
	if f.v6 {
		return peerV6[0]
	}
	dial := peerV4[len(peerV4)-1]
	if len(peerV4) > 1 && f.mine[len(f.mine)-1].addr.Addr() == dial.Addr() {
		dial = peerV4[0]
	}
	return dial
}

// seedHandshakeUDP runs the raw-UDP token-echo seed handshake and discards the
// token. Callers that will wrap the same socket in a directUnderlay must use
// seedHandshakeUDPToken instead: the underlay needs the token to tell the
// peer's probe from this side's own returning echo (the H2 loop guard).
func seedHandshakeUDP(sock *net.UDPConn, peer netip.AddrPort, timeout time.Duration) error {
	_, err := seedHandshakeUDPToken(sock, peer, timeout)
	return err
}

// probeFromText renders the source of a peer probe for a log field: the
// address, or "(none)" when no probe arrived.
func probeFromText(probeFrom netip.AddrPort) string {
	if !probeFrom.IsValid() {
		return "(none)"
	}
	return probeFrom.String()
}

// probeOutcomeNote describes what the seed round saw of the peer's side: the
// source of the peer's last probe, or that none arrived.
//
// The two cases are different faults with different fixes. Nothing of the
// peer's reached us means the path is blocked before us — our own NAT, the
// network, or the peer's. A probe that did arrive means the arrival worked
// and the rest of the round did not: our echo, or the peer's filter, dropped
// it. A failed round that does not say which one it was leaves the reader
// guessing, and the two guesses lead to opposite fixes.
func probeOutcomeNote(probeFrom netip.AddrPort) string {
	if !probeFrom.IsValid() {
		return "no peer probe arrived"
	}
	return "peer probe arrived from " + probeFromText(probeFrom)
}

// noteSeedFailure records a failed seed round: its reason, and what the round
// saw of the peer's side.
//
// The reason carries the note, because the reason is what a status reader
// sees first: a "seed failed" line that does not say whether the peer's
// packet reached us leaves the reader with two indistinguishable faults.
func (dc *directConn) noteSeedFailure(family string, err error, probeFrom netip.AddrPort) {
	note := probeOutcomeNote(probeFrom)
	dc.noteErr(fmt.Sprintf("seed failed: %v (%s)", err, note))
	dc.noteRound("%s seed failed: %v (%s)", family, err, note)
}

// seedOutcome is what one seed handshake learned about the peer's path.
type seedOutcome struct {
	// Token is the token this side sent, which the peer echoed back.
	Token [seedTokenLen]byte
	// Answer is the source the peer's echo of our token came from: the
	// endpoint that answered, which is not necessarily the one we dialled —
	// a peer behind a per-destination NAT answers from somewhere else.
	// Valid only when the handshake succeeded.
	Answer netip.AddrPort
	// ProbeFrom is the source of the last peer probe that arrived. It is
	// valid even when the handshake failed: a valid value means the peer's
	// packet reached us and the round still did not complete, which is a
	// different fault from "nothing of the peer's arrived".
	ProbeFrom netip.AddrPort
}

// seedHandshakeUDPToken runs the symmetric token echo over a raw UDP socket and
// returns what the round learned: the local token it used, the source address
// the successful echo came from, and the source the peer's own probe came
// from. The answer is the path that actually completed — a peer behind a
// per-destination NAT answers from an endpoint that is rarely the one dialed,
// so callers registering a data underlay must use the source, not the dialed
// candidate, or the steady-state source filter drops every data datagram.
//
// It writes its own token to peer every seedRetransmit until it reads that
// same token back, and it echoes each of the peer's probes so the peer's own
// handshake can complete. A raw UDP socket has no retransmit, so the resend
// loop stands in for KCP's send window; the read deadline between sends is
// short so a retransmit interleaves with waiting for a reply.
//
// Only a datagram carrying seedProbeMagic with a full token is considered,
// from any source address: the token authenticates the peer, the source
// address cannot. A per-destination NAT maps a different public endpoint than
// the one advertised, and the endpoint that can answer is rarely the one that
// was dialed, so a source filter is what made such a path untraversable. A
// probe from an unexpected source is echoed back to that source and the resend
// loop retargets to it, so both sides complete on the path that actually works.
// Success requires a full own->peer->own round trip, so a half-open path (we
// receive but our bytes never arrive) times out instead of producing a false
// direct session. A packet carrying our own token is the success case; a peer's token
// is echoed back on every probe, with no dedupe, because our own token is
// never echoed (an echo of our echo can only carry the peer's token, which
// this side re-echoes to the peer, never back to itself). Termination is the
// handshake deadline, not a per-token count.
func seedHandshakeUDPToken(sock *net.UDPConn, peer netip.AddrPort, timeout time.Duration) (seedOutcome, error) {
	var out seedOutcome
	if _, err := rand.Read(out.Token[:]); err != nil {
		return out, err
	}
	probe := make([]byte, 0, len(seedProbeMagic)+seedTokenLen)
	probe = append(probe, seedProbeMagic[:]...)
	probe = append(probe, out.Token[:]...)
	dst := net.UDPAddrFromAddrPort(peer)
	// The underlay that later owns this socket sets its own read deadline per
	// read, so this is only hygiene; clear it so no stale short deadline
	// survives the handshake.
	defer sock.SetReadDeadline(time.Time{})

	deadline := time.Now().Add(timeout)
	next := time.Now() // send immediately
	buf := make([]byte, 2048)
	for {
		now := time.Now()
		if !now.Before(deadline) {
			return out, errSeedTimeout
		}
		if !now.Before(next) {
			if _, err := sock.WriteToUDP(probe, dst); err != nil {
				return out, err
			}
			next = now.Add(seedRetransmit)
		}
		readBy := next
		if readBy.After(deadline) {
			readBy = deadline
		}
		if err := sock.SetReadDeadline(readBy); err != nil {
			return out, err
		}
		n, src, err := sock.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue // time to retransmit or to give up
			}
			return out, err
		}
		// No source filter: the token authenticates the peer, the source
		// address cannot — a per-destination NAT maps a different public
		// endpoint than the one it advertised, and the endpoint that can
		// answer is rarely the one that was dialed. Only the magic and a
		// full token shape are required, and only an echo of this side's
		// own token completes the handshake.
		if n < len(seedProbeMagic)+seedTokenLen || !bytes.Equal(buf[:len(seedProbeMagic)], seedProbeMagic[:]) {
			continue
		}
		var got [seedTokenLen]byte
		copy(got[:], buf[len(seedProbeMagic):len(seedProbeMagic)+seedTokenLen])
		if got == out.Token {
			out.Answer = src.AddrPort()
			return out, nil // the peer echoed our probe
		}
		// A probe from the peer. Remember where it came from: a round that
		// does not complete still has to say whether the peer's packet
		// reached us at all, which is the difference between a path blocked
		// before us and a path that broke after the arrival.
		out.ProbeFrom = src.AddrPort()
		// The endpoint the peer answers from is rarely the one it advertised:
		// a per-destination NAT maps a different public endpoint per
		// destination. Learn that endpoint so the resend loop carries our
		// token to it, letting the peer echo our probe and complete this
		// side's round trip; the echo below answers the peer's own handshake
		// on the same path.
		if !sameAddrPort(src.AddrPort(), peer) {
			learned := *src
			dst = &learned
		}
		// The peer's probe: echo it. Every retransmit is echoed again — raw UDP
		// has no reliability, so an echo lost in flight must be recovered by
		// the peer's next probe rather than dropped as a duplicate. An echo of
		// our own token is never produced here (that is the success case), so
		// two handshakes cannot loop.
		echo := make([]byte, 0, len(seedProbeMagic)+seedTokenLen)
		echo = append(echo, seedProbeMagic[:]...)
		echo = append(echo, got[:]...)
		// Echo to the probe's source, not the dialed address: for the
		// expected peer they are the same, but for a peer answering from an
		// unexpected endpoint this is what lets its own handshake complete.
		_, _ = sock.WriteToUDP(echo, src)
	}
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

// announcedFor returns the peer's announced endpoints for the family this
// round dialled. The comparison must stay inside one family: a v4 answer
// judged against the v6 list would read as a mismatch on every IPv6 punch.
func announcedFor(v6Family bool, v4, v6 []netip.AddrPort) []netip.AddrPort {
	if v6Family {
		return v6
	}
	return v4
}

// containsAddr reports whether addr is one of the listed endpoints.
//
// It compares with sameAddrPort, so a v4-mapped v6 address matches its v4
// form: the underlay's source filter treats them as the same endpoint, and a
// stricter comparison here would report every healthy IPv4 direct path as a
// mapping that differs from what the peer announced.
func containsAddr(list []netip.AddrPort, addr netip.AddrPort) bool {
	for _, a := range list {
		if sameAddrPort(a, addr) {
			return true
		}
	}
	return false
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

// sendCaps advertises our capabilities to the peer. Re-sent with every
// candidate broadcast (idempotent) so a lost frame or a late-joining peer
// cannot permanently degrade negotiation; the peer ORs the bits. The QUIC
// identity rides along as a TLV when one is present.
func (e *engine) sendCaps(peer derpclient.PublicKey, info capsInfo) error {
	return e.sendControl(peer, ctrlCaps, e.priv.SealTo(peer, encodeCaps(info)))
}

// sendControl sends a control frame ([frameControl][kind][payload]) to peer.
func (e *engine) sendControl(peer derpclient.PublicKey, kind byte, payload []byte) error {
	// Fault injection (see faults): a dropped control frame is silent — the
	// caller is told it went out, exactly as it would be on a path that lost it.
	if e.faults.Load().muteCtrl(time.Now()) {
		return nil
	}
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
	// The direct path never touches the relay pump, so inbound reads on it stamp
	// the peer's last-recv. The directConn is stable across re-punches, so the
	// lookup is done once and no engine lock is taken per stream.
	var stamp *atomic.Int64
	if transport == "direct" {
		if dc := e.getDirect(peer); dc != nil {
			stamp = &dc.lastFrameAt
		}
	}
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if transport == "direct" {
				// Direct sessions die when the KCP path drops (e.g. NAT mapping
				// timeout). Log the lifetime + cause to distinguish that from an
				// orderly close.
				e.log.Debug("direct session ended", "peer", keyName(peer),
					"duration", time.Since(start).String(), "error", err)
			} else {
				// A relay session that died without closing itself (smux's
				// recvLoop exits on the read error while the session stays
				// open) is otherwise silent: report it off the data path and
				// let the handler decide whether the pair is still carrying.
				go e.peerRelaySessionEnded(sess, peer, err)
			}
			return // session dead
		}
		e.stats.countStream(transport)
		var c net.Conn = stream
		if stamp != nil {
			c = &stampConn{Conn: stream, at: stamp}
		}
		// Classification reads the stream's leading bytes, so it runs in the
		// stream's own goroutine: a silent stream must not stall the accept
		// loop (and with it every other stream on the session).
		go e.serveInbound(c, transport, peer, peerAddr)
	}
}

// serveInbound routes one inbound stream: a stream tagged with the datagram
// channel magic carries the peer's udp channel, anything else is a normal
// tunnel stream bridged to --target.
func (e *engine) serveInbound(stream net.Conn, transport string, peer derpclient.PublicKey, peerAddr string) {
	start := time.Now()
	tagged, c := peekTag(stream)
	// The tag decides everything downstream: a tagged stream is the peer's udp
	// channel, an untagged one is handed to the embedder as a byte stream (which
	// a udp target then reaches over tcp). The elapsed time tells a genuinely
	// untagged stream (bytes arrived at once) from a tag that never arrived
	// (the peek timed out), so a slow path is visible as such.
	e.log.Debug("inbound stream: classified", "peer", keyName(peer), "transport", transport,
		"tagged", tagged, "peek", time.Since(start).Round(time.Millisecond).String(),
		"tagTimeout", channelTagTimeout.String())
	if tagged {
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
			e.log.Debug("inbound datagram: adopted by a link", "peer", keyName(peer), "transport", transport)
			return
		}
		if q := e.inbound.Load(); q != nil {
			e.log.Debug("inbound datagram: delivered to the embedder", "peer", keyName(peer), "transport", transport)
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
		// The peer's udp channel that arrived untagged lands here, as a byte
		// stream: the embedder then reaches its udp target over tcp, which is
		// exactly what a misclassified datagram link looks like in the log.
		e.log.Debug("inbound stream: delivered to the embedder (untagged)", "peer", keyName(peer),
			"transport", transport, "peek", time.Since(start).Round(time.Millisecond).String())
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
