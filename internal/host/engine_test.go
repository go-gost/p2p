package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/xtaci/smux"
)

// newTestSess returns a live smux session over an in-memory pipe, for tests
// that only need a session whose IsClosed() can be flipped.
func newTestSess(t *testing.T) *smux.Session {
	t.Helper()
	c1, c2 := net.Pipe()
	sess, err := smux.Client(c1, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sess.Close()
		c2.Close()
	})
	return sess
}

// TestDirectLiveNoSideEffect pins the one trap in the transport-stats feature:
// the gauge probe must be a side-effect-free read, or a Status query would churn
// connections. live() reads the registered-underlay state and never tears
// anything down.
func TestDirectLiveNoSideEffect(t *testing.T) {
	sock := mustListenUDP(t)
	t.Cleanup(func() { sock.Close() })
	dc := &directConn{peer: derpclient.PublicKey{1}, sock: sock, state: directUp}

	if !dc.live() {
		t.Fatal("live() = false for a registered underlay, want true")
	}

	dc.mu.Lock()
	state := dc.state
	dc.mu.Unlock()
	if state != directUp {
		t.Fatalf("live() mutated state to %v, want directUp (side-effect free)", state)
	}
	// No registered underlay is not live, whatever the state word says.
	if (&directConn{state: directUp}).live() {
		t.Fatal("live() = true with no socket, want false")
	}
}

// liveDirectFor installs a live direct path for peer: the per-peer directConn
// is marked up (the punch/status signal) and, since Task 3, a real direct
// underlay is installed on the pair — that recency is what pairHasLiveDirect
// now consults. It returns the directConn so a test can inspect or tear it down.
func liveDirectFor(t *testing.T, e *engine, peer derpclient.PublicKey) *directConn {
	t.Helper()
	dc := e.directConn(peer)
	sock := mustListenUDP(t)
	t.Cleanup(func() { sock.Close() })
	dc.mu.Lock()
	dc.sock = sock
	dc.sessAt = time.Now()
	dc.state = directUp
	dc.mu.Unlock()
	installDirectUnderlayFor(t, e, peer)
	return dc
}

// installDirectUnderlayFor installs a live direct underlay on peer's pair,
// seeded to now so preferredDirect is true. It is the pair-level half of
// liveDirectFor and is also used directly by tests that drive the real punch
// (which does not register the underlay until Task 7).
func installDirectUnderlayFor(t *testing.T, e *engine, peer derpclient.PublicKey) {
	t.Helper()
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	t.Cleanup(func() { b.Close() })
	e.relayKCPPairFor(peer).setDirectUnderlay(newDirectUnderlay(a, udpAddrPort(t, b)))
}

// relaySessionFor builds the state a peer has once a relay stream has been
// served: a settled relay secure session installed on the engine and held by
// the adapter, and a built pair KCP session. It returns the adapter whose kill
// a relay loss performs.
func relaySessionFor(t *testing.T, e *engine, peer derpclient.PublicKey, settled *secureSession) *peerConn {
	t.Helper()
	e.mu.Lock()
	e.secure[secureKey{peer: peer, transport: secureTransportRelay}] = settled
	e.mu.Unlock()
	pc := e.peerConn(peer)
	pc.mu.Lock()
	pc.secure = settled
	pc.mu.Unlock()
	pc.mu.Lock()
	if _, err := pc.sessionLocked(); err != nil {
		pc.mu.Unlock()
		t.Fatalf("build relay session: %v", err)
	}
	pc.mu.Unlock()
	return pc
}

// TestRelayLossWithoutDirectResetsPair pins the safe baseline of the H1 guard:
// with no direct path, a relay link-loss resets exactly as before — the pair's
// KCP epoch ends and the relay secure session is dropped. The existing
// relay-loss tests pin the log shape; this pins the two live objects.
func TestRelayLossWithoutDirectResetsPair(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{41}
	settled, _ := settledSecurePair(t, secureTransportRelay)
	pc := relaySessionFor(t, e, peer, settled)
	if e.relayKCPPairGet(peer) == nil {
		t.Fatal("no pair KCP session built")
	}

	pc.killSession(errors.New("test: link lost"), true, reasonLinkLost)

	if got := e.relayKCPPairGet(peer); got != nil {
		t.Fatal("the pair survived a relay loss with no direct path")
	}
	e.mu.Lock()
	_, ok := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if ok {
		t.Fatal("the relay secure session survived a relay loss with no direct path")
	}
}

// TestRelayLossWithLiveDirectKeepsPair pins the H1 guard itself: while the peer
// has a live direct path, a relay link-loss must NOT end the pair's KCP epoch
// and must NOT drop the relay secure session — a relay blip cannot be allowed
// to tear down a path that does not run through the relay.
//
// "Live direct" here is the pair's direct-underlay recency (Task 3's
// preferredDirect): liveDirectFor installs a real direct underlay on the pair.
// This test deliberately asserts the guard's observable effect (pair, session,
// secure identity, nonce counter), not stream survival: killSession still closes
// the adapter's mux session, which only the unification removes.
func TestRelayLossWithLiveDirectKeepsPair(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{42}
	settled, _ := settledSecurePair(t, secureTransportRelay)
	pc := relaySessionFor(t, e, peer, settled)
	pair := e.relayKCPPairGet(peer)
	if pair == nil {
		t.Fatal("no pair KCP session built")
	}
	liveDirectFor(t, e, peer)

	// Draw a nonce the peer has already been told about. If the kill dropped the
	// session and re-handshook, this counter object would be replaced and the
	// sequence would restart under the same key — the nonce-reuse hazard the
	// guard exists to avoid.
	settled.mu.Lock()
	sendCtr := settled.sendCtr
	settled.mu.Unlock()
	sendCtr.next()

	pc.killSession(errors.New("test: link lost"), true, reasonLinkLost)

	if got := e.relayKCPPairGet(peer); got != pair {
		t.Fatal("the pair was reset despite a live direct path")
	}
	pair.mu.Lock()
	closed, sess := pair.closed, pair.sess
	pair.mu.Unlock()
	if closed {
		t.Fatal("the pair was shut down despite a live direct path")
	}
	if sess == nil {
		t.Fatal("the pair lost its KCP session despite a live direct path")
	}
	e.mu.Lock()
	got, ok := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if !ok || got != settled {
		t.Fatal("the relay secure session was dropped or replaced despite a live direct path")
	}
	settled.mu.Lock()
	gotCtr := settled.sendCtr
	settled.mu.Unlock()
	sendCtr.mu.Lock()
	n := sendCtr.n
	sendCtr.mu.Unlock()
	if gotCtr != sendCtr || n != 1 {
		t.Fatalf("nonce counter was replaced or reset: got %p n=%d, want %p n=1", gotCtr, n, sendCtr)
	}
}

// TestPeerGoneWithLiveDirectKeepsPair pins the peer-gone half of H1 (plan
// Review Focus #6): the relay's best-effort "peer gone" notice must not end a
// pair a live direct path is serving, and must not drop its relay secure session.
func TestPeerGoneWithLiveDirectKeepsPair(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{43}
	settled, _ := settledSecurePair(t, secureTransportRelay)
	relaySessionFor(t, e, peer, settled)
	pair := e.relayKCPPairGet(peer)
	if pair == nil {
		t.Fatal("no pair KCP session built")
	}
	liveDirectFor(t, e, peer)

	e.peerGone(peer)

	if got := e.relayKCPPairGet(peer); got != pair {
		t.Fatal("peerGone dropped the pair despite a live direct path")
	}
	e.mu.Lock()
	got, ok := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if !ok || got != settled {
		t.Fatal("peerGone dropped the relay secure session despite a live direct path")
	}
}

// TestPeerGoneThenDirectDeathDropsPair was removed: the pair is deliberately
// retained across peerGone even after the direct path goes idle, so a returning
// peer resumes without a rekey/re-handshake (H1). See
// TestPeerGoneKeepsLiveDirectSession and the retention comment in
// directConn.underlayDead.

// TestPeerGoneWithoutDirectResetsPair pins the safe baseline of the peer-gone
// guard: with no direct path, the notice ends the pair and drops the relay
// secure session exactly as before.
func TestPeerGoneWithoutDirectResetsPair(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{44}
	settled, _ := settledSecurePair(t, secureTransportRelay)
	relaySessionFor(t, e, peer, settled)
	if e.relayKCPPairGet(peer) == nil {
		t.Fatal("no pair KCP session built")
	}

	e.peerGone(peer)

	if got := e.relayKCPPairGet(peer); got != nil {
		t.Fatal("the pair survived peerGone with no direct path")
	}
	e.mu.Lock()
	_, ok := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if ok {
		t.Fatal("the relay secure session survived peerGone with no direct path")
	}
}

// TestRelayLinkLossKeepsLiveDirectPair drives the real relay-loss flow
// (engine.teardown) with a live direct path: the pair's KCP epoch and the relay
// secure session must survive so a relay blip cannot tear down a path that does
// not run through the relay. This is the production site the unit tests above
// only approximate through killSession.
func TestRelayLinkLossKeepsLiveDirectPair(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	// Relay-only at first, so the relay secure session settles and the pair is
	// built before the punch can win.
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()

	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()

	// Now allow the punch and wait for a live direct path.
	engineA.stunAddr, engineB.stunAddr = stun, stun
	engineA.maybeStartDirect(pubB)
	engineB.maybeStartDirect(engineA.pub)
	waitFor(t, 10*time.Second, func() bool { return hasDirect(engineA, pubB) })

	pair := engineA.relayKCPPairFor(pubB)
	// Task 3's predicate is the pair's direct-underlay recency; the real punch
	// does not register the unified underlay on the pair until Task 7, so install
	// one here to represent the live direct path the guard must honor.
	installDirectUnderlayFor(t, engineA, pubB)
	if !engineA.pairHasLiveDirect(pubB) {
		t.Fatal("A's live direct path was not recognized by pairHasLiveDirect")
	}
	engineA.mu.Lock()
	secure := engineA.secure[secureKey{peer: pubB, transport: secureTransportRelay}]
	engineA.mu.Unlock()
	if secure == nil {
		t.Fatal("A has no relay secure session for B")
	}

	// The relay link drops while the direct path is live.
	engineA.mu.Lock()
	c := engineA.client
	engineA.mu.Unlock()
	if c == nil {
		t.Fatal("A has no relay connection to lose")
	}
	engineA.teardown(c, errors.New("test: relay link lost"))

	if got := engineA.relayKCPPairGet(pubB); got != pair {
		t.Fatal("teardown dropped the pair despite a live direct path")
	}
	pair.mu.Lock()
	closed := pair.closed
	pair.mu.Unlock()
	if closed {
		t.Fatal("teardown shut down the pair despite a live direct path")
	}
	engineA.mu.Lock()
	got := engineA.secure[secureKey{peer: pubB, transport: secureTransportRelay}]
	engineA.mu.Unlock()
	if got != secure {
		t.Fatal("teardown dropped the relay secure session despite a live direct path")
	}
}

// TestRelayLossServesNewStreamOverDirect pins the follow-up T14: a relay loss
// with a live direct path keeps the pair (H1) but closes the per-build mux
// session on both ends (killSession). The dialing side rebuilds its mux on its
// next OpenStream, but the accepting side has no relay pump to trigger a
// rebuild — so without a direct-inbound trigger, a new stream opened while the
// relay is down hangs. Here the relay dies, and a fresh stream must still be
// served over the surviving direct path.
func TestRelayLossServesNewStreamOverDirect(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
	defer engineA.Close()
	defer engineB.Close()

	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// A relay stream settles the secure layer and builds the pair.
	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "before-loss")
	s.Close()

	// Punch a real direct path on both ends and let the pair prefer it.
	engineA.maybeStartDirect(pubB)
	engineB.maybeStartDirect(engineA.pub)
	waitFor(t, 10*time.Second, func() bool {
		return engineA.pairHasLiveDirect(pubB) && engineB.pairHasLiveDirect(engineA.pub)
	})

	// The relay dies on both ends (the e2e kills the derper): tear the
	// transport down, then close the listener so it cannot be re-dialed. The
	// pair and its settled keys survive on the live direct path (H1).
	engineA.mu.Lock()
	cA := engineA.client
	engineA.mu.Unlock()
	engineB.mu.Lock()
	cB := engineB.client
	engineB.mu.Unlock()
	if cA == nil || cB == nil {
		t.Fatal("a relay connection is missing before the loss")
	}
	engineA.teardown(cA, errors.New("test: relay lost"))
	engineB.teardown(cB, errors.New("test: relay lost"))
	rs.srv.Close()
	// Losing the relay is not a relay-packet proof of reachability, so a stale
	// gone mark must not shorten the open: the direct path is live.
	engineA.clearGone(pubB)
	engineB.clearGone(engineA.pub)
	if !engineA.pairHasLiveDirect(pubB) || !engineB.pairHasLiveDirect(engineA.pub) {
		t.Fatal("the pair lost its live direct path across the relay loss")
	}

	// A new stream with the relay down must be served over direct: the
	// accepting side rebuilds its mux from the inbound direct datagram.
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatalf("open with the relay down: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "after-loss")
}

// syncBuffer is a goroutine-safe bytes.Buffer for catching an engine's slog
// output: the engine logs from pump/punch/keepalive goroutines while a test
// reads the captured text.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestOpenStreamUsesPairAndReportsPath pins M3 + Task 10: every tunnel stream
// opens on the one relay pair, and its transport label is the pair's path at
// open time — "derp" before a direct underlay exists, "direct" once one is
// installed. A stream opened before the punch no longer blocks on it.
func TestOpenStreamUsesPairAndReportsPath(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// No punch has run (no STUN configured), so the pair is relay-only.
	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	os, ok := s.(*openedStream)
	if !ok {
		t.Fatalf("OpenStream returned %T, want *openedStream", s)
	}
	if got := os.Transport(); got != "derp" {
		t.Fatalf("transport before a direct underlay = %q, want derp", got)
	}
	roundTrip(t, s, "relay-before-punch")
	s.Close()

	// Install the pair-level state a punch leaves; a stream opened now reports
	// the pair's new path. Its data would ride the fake underlay, so only the
	// label is asserted here (byte-exactness across the flip is Task 5/13).
	installDirectUnderlayFor(t, engineA, pubB)

	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.(*openedStream).Transport(); got != "direct" {
		t.Fatalf("transport after a direct underlay = %q, want direct", got)
	}
	s2.Close()
}

// TestOpenStreamLogsStreamPathChange pins O6: a long-lived stream that was
// opened on the relay and then rides the pair across a migration must leave a
// reconstructable record — exactly one Info "stream path-changed" plus one bump
// of the pair's pathChanges counter. transport stays the point-in-time label.
func TestOpenStreamLogsStreamPathChange(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	logBuf := &syncBuffer{}
	engineA := newEngine(url, "", privA, slog.New(slog.NewTextHandler(logBuf, nil)))
	engineB := newEngine(url, echo, privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// Open the stream on the relay and keep it across the migration.
	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	os := s.(*openedStream)
	if got := os.Transport(); got != "derp" {
		t.Fatalf("transport at open = %q, want derp", got)
	}
	roundTrip(t, s, "before-migration")

	pair := engineA.relayKCPPairGet(pubB)
	if pair == nil {
		t.Fatal("no pair for the peer")
	}
	if got := pair.pathChanges.Load(); got != 0 {
		t.Fatalf("pathChanges before the migration = %d, want 0", got)
	}

	// The pair migrates to direct (what a punch installs on success).
	installDirectUnderlayFor(t, engineA, pubB)
	if got := pair.pathChanges.Load(); got != 1 {
		t.Fatalf("pathChanges after the migration = %d, want 1", got)
	}

	// The already-open stream notices the flip on its next I/O. The fake direct
	// socket carries nothing, so bound the read rather than round-tripping; the
	// log is emitted after the first Read/Write either way.
	s.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := s.Write([]byte("after-migration")); err != nil {
		t.Fatalf("write after migration: %v", err)
	}
	var buf [16]byte
	s.Read(buf[:])
	s.Close()

	logs := logBuf.String()
	if got := strings.Count(logs, "stream path-changed"); got != 1 {
		t.Fatalf("stream path-changed logs = %d, want 1\nlog:\n%s", got, logs)
	}
	for _, want := range []string{"from=relay", "to=direct", "reason=first-direct-datagram"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("stream path-changed log missing %q\nlog:\n%s", want, logs)
		}
	}
	// The label is a snapshot, not a lifelong plane (M1/O6): it does not change
	// just because the pair migrated underneath.
	if got := os.Transport(); got != "derp" {
		t.Fatalf("transport after migration = %q, want derp (snapshot at open)", got)
	}
}

// TestTransportCounts covers the gauge classification: a peer with a live
// direct session counts as direct and must not also be counted as derp; peers
// on the relay alone count as derp.
func TestTransportCounts(t *testing.T) {
	e := &engine{
		direct:   true,
		stunAddr: "127.0.0.1:3478",
		directs:  make(map[derpclient.PublicKey]*directConn),
		peers:    make(map[derpclient.PublicKey]*peerConn),
	}

	peerDirect := derpclient.PublicKey{1}
	peerRelay := derpclient.PublicKey{2}

	directSock := mustListenUDP(t)
	t.Cleanup(func() { directSock.Close() })
	dc := &directConn{e: e, peer: peerDirect, sock: directSock, state: directUp}
	e.directs[peerDirect] = dc
	// Both peers carry a live relay session — the base path a peer has before
	// and after a punch — so losing the direct session must leave peerDirect on
	// the relay, not drop it off the list.
	e.peers[peerDirect] = &peerConn{peer: peerDirect, sess: newTestSess(t)}
	e.peers[peerRelay] = &peerConn{peer: peerRelay, sess: newTestSess(t)}

	direct, derp := e.transportCounts()
	if direct != 1 {
		t.Fatalf("direct = %d, want 1", direct)
	}
	if derp != 1 {
		t.Fatalf("derp = %d, want 1 (the direct peer must not double-count)", derp)
	}

	// The same classification is available per peer, which is what a caller
	// listing peers uses.
	transports := e.peerTransports()
	if len(transports) != 2 {
		t.Fatalf("peerTransports = %v, want both peers", transports)
	}
	if got := transports[keyName(peerDirect)]; got != "direct" {
		t.Errorf("peer %s transport = %q, want direct", keyName(peerDirect), got)
	}
	if got := transports[keyName(peerRelay)]; got != "derp" {
		t.Errorf("peer %s transport = %q, want derp", keyName(peerRelay), got)
	}

	// Losing the direct underlay moves that peer into the relay column.
	dc.mu.Lock()
	dc.sock = nil
	dc.state = directNone
	dc.mu.Unlock()

	direct, derp = e.transportCounts()
	if direct != 0 || derp != 2 {
		t.Fatalf("after session death: direct = %d, derp = %d, want 0, 2", direct, derp)
	}
	if got := e.peerTransports()[keyName(peerDirect)]; got != "derp" {
		t.Errorf("after session death: peer transport = %q, want derp", got)
	}
}

// TestRelayRebuildCounters: a peer whose relay session is torn down and rebuilt
// reports both counts — the rebuild and, separately, the rebuild caused by the
// peer changing its secure half (the one teardown neither side triggers from its
// own config). The field case was five of those in twelve minutes, and nothing
// but a log grep showed it: a peer reads as healthy while its session is
// rebuilt every few seconds.
func TestRelayRebuildCounters(t *testing.T) {
	e := &engine{
		log:     slog.Default(),
		stop:    make(chan struct{}),
		directs: make(map[derpclient.PublicKey]*directConn),
		peers:   make(map[derpclient.PublicKey]*peerConn),
		secure:  make(map[secureKey]*secureSession),
	}
	peer := derpclient.PublicKey{3}
	pc := &peerConn{e: e, peer: peer, closeCh: make(chan struct{})}
	e.peers[peer] = pc

	// A teardown the peer caused (a changed ctrlSecure half).
	e.resetPeerSession(peer)
	if got := pc.relayRebuildPeers.Load(); got != 1 {
		t.Errorf("peer rekeys = %d, want 1", got)
	}
	if !pc.closed {
		t.Errorf("the session was not torn down")
	}

	// A peer's first relay session is not a rebuild; a second one is. Two real
	// builds over the loopback underlay, the second after the first was closed —
	// which is what "rebuilt" means.
	two := derpclient.PublicKey{4}
	// A settled session, or the forced-encryption gate refuses the build (see
	// settledSecurePair).
	settled, _ := settledSecurePair(t, secureTransportRelay)
	tpc := &peerConn{e: e, peer: two, closeCh: make(chan struct{}), secure: settled}
	e.peers[two] = tpc
	// sessionLocked's contract is "caller holds pc.mu", and startAccept's defer
	// takes it from the goroutine it just spawned — so the lock is taken here as
	// ensureSession does, or the race detector fires on our own test.
	build := func() error {
		tpc.mu.Lock()
		defer tpc.mu.Unlock()
		_, err := tpc.sessionLocked()
		return err
	}
	if err := build(); err != nil {
		t.Fatalf("first session: %v", err)
	}
	if got := tpc.relayRebuilds.Load(); got != 0 {
		t.Errorf("after the first session: rebuilds = %d, want 0", got)
	}
	tpc.sess.Close()
	if err := build(); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if got := tpc.relayRebuilds.Load(); got != 1 {
		t.Errorf("after a rebuild: rebuilds = %d, want 1", got)
	}
}

// TestStatusFacesAgreeOnWhoIsConnected: the transport map, the diagnostics and
// the encryption map are three answers to one question — "which peers have a
// live data path" — and a field bug came from one of them answering it
// differently (a killed phone stayed listed as connected while the encryption
// count said otherwise, in the same snapshot). All three must be derived from
// peerLive, so this table pins all three to it at once: any face that starts
// answering for itself fails here.
func TestStatusFacesAgreeOnWhoIsConnected(t *testing.T) {
	// Peer shapes: what path, if any, the peer has right now.
	cases := []struct {
		name string
		live func(t *testing.T) (*peerConn, *directConn)
	}{
		{"no adapter at all", func(t *testing.T) (*peerConn, *directConn) { return nil, nil }},
		{"relay adapter, no session yet", func(t *testing.T) (*peerConn, *directConn) {
			return &peerConn{}, nil
		}},
		{"relay session ended", func(t *testing.T) (*peerConn, *directConn) {
			s := newTestSess(t)
			s.Close()
			return &peerConn{sess: s}, nil
		}},
		{"relay session live", func(t *testing.T) (*peerConn, *directConn) {
			return &peerConn{sess: newTestSess(t)}, nil
		}},
		{"relay session live, direct backing off", func(t *testing.T) (*peerConn, *directConn) {
			return &peerConn{sess: newTestSess(t)}, &directConn{state: directBackoff, failed: true}
		}},
		{"relay session ended, direct live", func(t *testing.T) (*peerConn, *directConn) {
			s := newTestSess(t)
			s.Close()
			return &peerConn{sess: s}, &directConn{sock: mustListenUDP(t), state: directUp}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &engine{
				direct:   true,
				stunAddr: "127.0.0.1:3478",
				log:      slog.Default(),
				stop:     make(chan struct{}),
				directs:  make(map[derpclient.PublicKey]*directConn),
				peers:    make(map[derpclient.PublicKey]*peerConn),
			}
			peer := derpclient.PublicKey{5}
			pc, dc := tc.live(t)
			if pc != nil {
				pc.e, pc.peer = e, peer
				e.peers[peer] = pc
			}
			if dc != nil {
				dc.e, dc.peer = e, peer
				e.directs[peer] = dc
			}
			name := keyName(peer)

			transports := e.peerTransports()
			diagnostics := e.peerDiagnostics(transports)
			encryptions := e.peerEncryptions()

			for _, face := range []struct {
				what string
				set  map[string]bool
			}{
				{"peerTransports", keysOf(transports)},
				{"peerDiagnostics", keysOf(diagnostics)},
				{"peerEncryptions", keysOf(encryptions)},
			} {
				_, listed := face.set[name]
				if want := e.peerLive(peer); listed != want {
					t.Errorf("%s: listed = %v, peerLive = %v — the faces must agree", face.what, listed, want)
				}
			}
		})
	}
}

// keysOf is a map's key set, so two Status faces can be compared without their
// values (which are different words on purpose).
func keysOf[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// TestPeerTransportReasons: a relayed peer reports the most specific reason
// available — its own punch state first, then the host-wide one — which is what
// a caller turns into an icon and a tooltip. Being able to tell "STUN does not
// answer" from "punching cannot work here at all" is the point.
func TestPeerTransportReasons(t *testing.T) {
	newEngine := func() *engine {
		return &engine{
			direct:   true,
			stunAddr: "127.0.0.1:3478",
			log:      slog.Default(), // a case that changes the peer's caps logs
			directs:  make(map[derpclient.PublicKey]*directConn),
			peers:    make(map[derpclient.PublicKey]*peerConn),
		}
	}
	peer := derpclient.PublicKey{3}

	cases := []struct {
		name string
		mut  func(e *engine)
		want string
	}{
		{"punch in flight", func(e *engine) {
			e.directs[peer] = &directConn{e: e, peer: peer, state: directAttempting}
		}, transportPunching},
		{"punch failed", func(e *engine) {
			e.directs[peer] = &directConn{e: e, peer: peer, state: directBackoff, failed: true}
		}, transportFailed},
		{"failed, retry in flight", func(e *engine) {
			e.directs[peer] = &directConn{e: e, peer: peer, state: directAttempting, failed: true}
		}, transportFailed},
		{"direct switched off", func(e *engine) {
			e.direct = false
			e.directs[peer] = &directConn{e: e, peer: peer}
		}, transportDisabled},
		{"no STUN, no IPv6", func(e *engine) { e.stunAddr = "" }, transportNoCandidates},
		{"STUN silent", func(e *engine) { e.stunFailed.Store(true) }, transportStunUnreachable},
		{"STUN silent but IPv6 exists", func(e *engine) {
			e.stunFailed.Store(true)
			e.v6Available = true
		}, transportRelay},
		{"peer has the direct path off", func(e *engine) {
			// A prior round failed, and the peer then advertised that its direct
			// path is off — the asymmetry this word exists to name, so the bit is
			// set on the same adapter the failed round left behind.
			dc := &directConn{e: e, peer: peer, state: directBackoff, failed: true}
			dc.addCaps(capsNoDirect)
			e.directs[peer] = dc
		}, transportPeerDirectOff},
		{"plain relay", func(e *engine) {}, transportRelay},
	}
	for _, tc := range cases {
		e := newEngine()
		// The peer must have a live path to be reported at all (peerTransports
		// filters on it), so it carries a built relay session: these cases are
		// about the word a *connected* peer gets.
		e.peers[peer] = &peerConn{peer: peer, sess: newTestSess(t)}
		tc.mut(e)
		if got := e.peerTransports()[keyName(peer)]; got != tc.want {
			t.Errorf("%s: transport = %q, want %q", tc.name, got, tc.want)
		}
	}

	// A live punch wins over every reason.
	e := newEngine()
	e.peers[peer] = &peerConn{}
	e.stunFailed.Store(true)
	e.directs[peer] = &directConn{e: e, peer: peer, sock: mustListenUDP(t), state: directUp}
	if got := e.peerTransports()[keyName(peer)]; got != transportDirect {
		t.Errorf("live session: transport = %q, want direct", got)
	}

	// A host-wide cause outranks a peer's own failed round: with STUN silent
	// and no IPv6, that is the thing to fix, not the symptom.
	e = newEngine()
	e.peers[peer] = &peerConn{peer: peer, sess: newTestSess(t)}
	e.stunFailed.Store(true)
	e.directs[peer] = &directConn{e: e, peer: peer, state: directBackoff, failed: true}
	if got := e.peerTransports()[keyName(peer)]; got != transportStunUnreachable {
		t.Errorf("stun silent + failed round: transport = %q, want %q", got, transportStunUnreachable)
	}
}

// TestPeerTransportsReportsPairPath pins the M1 semantics of the transport
// word: it names the pair's *current* path, not a stream's lifelong plane. A
// pair with no direct underlay reads "derp"; installing one reads "direct" —
// even before (or without) a directConn, because the pair's own recency
// (pathName) is what decides, not the punch state machine.
func TestPeerTransportsReportsPairPath(t *testing.T) {
	e := &engine{
		direct:    true,
		stunAddr:  "127.0.0.1:3478",
		peers:     make(map[derpclient.PublicKey]*peerConn),
		directs:   make(map[derpclient.PublicKey]*directConn),
		relayKCPs: make(map[derpclient.PublicKey]*relayKCPPair),
	}
	peer := derpclient.PublicKey{7}
	e.peers[peer] = &peerConn{peer: peer, sess: newTestSess(t)}

	if got := e.peerTransports()[keyName(peer)]; got != transportRelay {
		t.Fatalf("no direct underlay: transport = %q, want %q", got, transportRelay)
	}

	installDirectUnderlayFor(t, e, peer)
	// The pair's pumps read the (test-mutable) directUnderlayIdle global; stop
	// them before the test ends, or the goroutine leaks into a later test that
	// changes it and trips the race detector.
	t.Cleanup(func() {
		if p := e.relayKCPPairGet(peer); p != nil {
			p.shutdown()
		}
	})
	if got := e.peerTransports()[keyName(peer)]; got != transportDirect {
		t.Fatalf("direct underlay installed: transport = %q, want %q", got, transportDirect)
	}
}

// TestPeerDiagnosticsPerUnderlayAttribution pins O3: the two underlays are
// reported separately and never merged. Bytes are partitioned by the path each
// datagram rode, the pair's current path and DirectAlive follow the direct
// recency, and a stale direct path and a fresh relay path report different
// ages — the value a merged "last recv" would hide.
func TestPeerDiagnosticsPerUnderlayAttribution(t *testing.T) {
	e := &engine{relayKCPs: make(map[derpclient.PublicKey]*relayKCPPair)}
	peer := derpclient.PublicKey{23}
	pair := e.relayKCPPairFor(peer)
	// Stop the pair's pumps before the test ends: they read the mutable
	// directUnderlayIdle global, and a leak would race a later test that
	// shortens it.
	t.Cleanup(pair.shutdown)

	// A registered relay endpoint so the relay branch has somewhere to write.
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 4),
		closeCh: make(chan struct{}),
	}
	pair.register(pc)

	// Install a fresh direct underlay: it is preferred, so the first write
	// rides it and counts on the direct side.
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	t.Cleanup(func() { a.Close(); b.Close() })
	pair.setDirectUnderlay(newDirectUnderlay(a, udpAddrPort(t, b)))
	if n, err := pair.WriteTo(make([]byte, 40), nil); err != nil || n != 40 {
		t.Fatalf("direct WriteTo = %d, %v; want 40, nil", n, err)
	}

	// Serve one relay datagram: bytesRcvd and the relay recency are stamped by
	// the relay pump as it drains the endpoint's queue.
	pc.inbound <- make([]byte, 30)
	if _, _, err := pair.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatalf("relay ReadFrom: %v", err)
	}

	// Let the direct path go stale: the pair falls back to the relay, and the
	// next write counts on the relay side. Ages now differ by construction.
	pair.mu.Lock()
	pair.lastDirectRecv = time.Now().Add(-2 * directUnderlayIdle)
	pair.mu.Unlock()
	if n, err := pair.WriteTo(make([]byte, 20), nil); err != nil || n != 20 {
		t.Fatalf("relay WriteTo = %d, %v; want 20, nil", n, err)
	}

	k := e.relayKCPStats(peer)
	if k.Path != transportRelay {
		t.Fatalf("Path = %q, want %q for a stale direct underlay", k.Path, transportRelay)
	}
	if k.DirectAlive {
		t.Fatal("DirectAlive = true for a stale direct underlay")
	}
	if k.DirectBytesSent != 40 || k.DirectBytesRcvd != 0 {
		t.Fatalf("direct bytes = sent %d / rcvd %d, want 40 / 0", k.DirectBytesSent, k.DirectBytesRcvd)
	}
	if k.RelayBytesSent != 20 || k.RelayBytesRcvd != 30 {
		t.Fatalf("relay bytes = sent %d / rcvd %d, want 20 / 30", k.RelayBytesSent, k.RelayBytesRcvd)
	}
	if k.BytesSent != 60 || k.BytesRcvd != 30 {
		t.Fatalf("totals = sent %d / rcvd %d, want 60 / 30 (per-underlay sums)", k.BytesSent, k.BytesRcvd)
	}
	if k.DirectLastRecvAge < directUnderlayIdle {
		t.Fatalf("DirectLastRecvAge = %v, want a stale (>= %v) direct age", k.DirectLastRecvAge, directUnderlayIdle)
	}
	if k.RelayLastRecvAge <= 0 || k.RelayLastRecvAge >= directUnderlayIdle {
		t.Fatalf("RelayLastRecvAge = %v, want a fresh (0, %v) relay age", k.RelayLastRecvAge, directUnderlayIdle)
	}
	if k.DirectLastRecvAge <= k.RelayLastRecvAge {
		t.Fatalf("ages not attributed per underlay: direct %v, relay %v", k.DirectLastRecvAge, k.RelayLastRecvAge)
	}
}

// TestPeerTransportsDropsPeersWithoutLivePath: the peer list says who is
// connected, and a peer is connected only while it has a live data path. A
// killed app sends no PeerGone to an open relay, so its adapter outlives it in
// the engine's maps and its relay session is noticed dead only by the smux
// keepalive. peerEncryptions already filters on exactly that; peerTransports
// must agree with it, or one snapshot reports two different peer sets (the
// field case: a phone gone for over an hour still listed, and still punched).
func TestPeerTransportsDropsPeersWithoutLivePath(t *testing.T) {
	e := &engine{
		direct:   true,
		stunAddr: "127.0.0.1:3478",
		directs:  make(map[derpclient.PublicKey]*directConn),
		peers:    make(map[derpclient.PublicKey]*peerConn),
	}
	up := derpclient.PublicKey{1}
	gone := derpclient.PublicKey{2}
	gonePunching := derpclient.PublicKey{3}

	// A live relay session: reported.
	e.peers[up] = &peerConn{peer: up, sess: newTestSess(t)}

	// A peer whose relay session has ended with no direct session to fall back
	// on: the killed-app case, adapter still cached.
	dead := newTestSess(t)
	dead.Close()
	e.peers[gone] = &peerConn{peer: gone, sess: dead}

	// The same, plus a directConn stuck in backoff — the punch keeps retrying a
	// peer that is not there, and that state must not ride the row back onto
	// the list.
	e.peers[gonePunching] = &peerConn{peer: gonePunching, sess: dead}
	e.directs[gonePunching] = &directConn{e: e, peer: gonePunching, state: directBackoff, failed: true}

	got := e.peerTransports()
	if got[keyName(up)] == "" {
		t.Errorf("live peer missing from %v", got)
	}
	if w := got[keyName(gone)]; w != "" {
		t.Errorf("peer with no live path reported as %q, want absent", w)
	}
	if w := got[keyName(gonePunching)]; w != "" {
		t.Errorf("peer with no live path reported as %q, want absent", w)
	}
}

// TestPeerDiagnosticsReasonOnlyWhenNotDirect: a peer on a live direct path must
// not also carry the host-wide reason — the row would otherwise read
// Path="direct" and Reason="stun-unreachable". peerTransports lets a live
// session outrank the reason; the diagnostics match it. A relay-only peer with
// no directConn reads State "none", the same as a directConn in directNone.
func TestPeerDiagnosticsReasonOnlyWhenNotDirect(t *testing.T) {
	e := &engine{
		direct:   true,
		stunAddr: "127.0.0.1:3478",
		directs:  make(map[derpclient.PublicKey]*directConn),
		peers:    make(map[derpclient.PublicKey]*peerConn),
	}
	e.stunFailed.Store(true) // host-wide reason: STUN silent, no IPv6 to fall back on
	peer := derpclient.PublicKey{9}
	e.peers[peer] = &peerConn{peer: peer, sess: newTestSess(t)} // connected: it carries a path word

	d := e.peerDiagnostics(e.peerTransports())[keyName(peer)]
	if d.Path != transportStunUnreachable || d.Reason != transportStunUnreachable {
		t.Errorf("relay-only: path=%q reason=%q, want %q on both", d.Path, d.Reason, transportStunUnreachable)
	}
	if d.State != "none" {
		t.Errorf("relay-only state = %q, want none", d.State)
	}

	// A live direct path outranks the reason: no stale Reason on a direct row.
	e.directs[peer] = &directConn{e: e, peer: peer, sock: mustListenUDP(t), state: directUp}
	d = e.peerDiagnostics(e.peerTransports())[keyName(peer)]
	if d.Path != transportDirect {
		t.Fatalf("live session: path = %q, want direct", d.Path)
	}
	if d.Reason != "" {
		t.Errorf("direct path reason = %q, want empty", d.Reason)
	}
}

// TestPeerDiagnosticsSnapshot: a connected peer must appear in Status with the
// path its traffic takes, its punch history and the ages a diagnosis needs.
func TestPeerDiagnosticsSnapshot(t *testing.T) {
	eA, eB, _ := newEncryptedPair(t) // the relay server is closed by the helper's t.Cleanup
	// A candidate source is what makes a punch run at all (directEnabled);
	// without one there are no attempts and no path word beyond "no-candidates".
	stun := startFakeSTUN(t, "")
	eA.stunAddr, eB.stunAddr = stun, stun

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	go conn.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	st := newServer(eA).status()
	d, ok := st.PeerDiagnostics[eB.PublicKey()]
	if !ok {
		t.Fatal("no diagnostic for the peer")
	}
	if d.Path != "direct" && d.Path != "derp" {
		t.Fatalf("path = %q", d.Path)
	}
	if d.Attempts == 0 {
		t.Fatal("attempts not reported")
	}
	if d.LastRecvAge <= 0 {
		t.Fatal("last-recv age not reported for a peer that just sent")
	}
	// A live direct session carries its age. The sandbox may keep this pair on
	// the relay (the punch's UDP send is denied here), so assert only when the
	// path really is direct.
	if d.Path == "direct" && d.SessionAge <= 0 {
		t.Fatal("a direct session must carry its age")
	}
}

// TestPeerDiagnosticsMerge covers the two map shapes the builder folds together:
// a relay-only peer must still report a path word (not the empty string), and a
// peer present in both maps takes the direct row while keeping the relay's
// last-recv age.
func TestPeerDiagnosticsMerge(t *testing.T) {
	e := &engine{
		direct:   true,
		stunAddr: "127.0.0.1:3478", // a candidate source: directReason() is empty
		directs:  make(map[derpclient.PublicKey]*directConn),
		peers:    make(map[derpclient.PublicKey]*peerConn),
	}
	relayOnly := derpclient.PublicKey{1}
	both := derpclient.PublicKey{2}

	e.peers[relayOnly] = &peerConn{peer: relayOnly, sess: newTestSess(t)}

	pcBoth := &peerConn{peer: both, sess: newTestSess(t)}
	pcBoth.lastFrameAt.Store(time.Now().Add(-3 * time.Second).UnixNano())
	e.peers[both] = pcBoth
	// The directConn's own stamp is left unset, so the relay age survives.
	e.directs[both] = &directConn{e: e, peer: both, sock: mustListenUDP(t), state: directUp}

	out := e.peerDiagnostics(e.peerTransports())

	if d := out[keyName(relayOnly)]; d.Path != transportRelay {
		t.Errorf("relay-only path = %q, want %q", d.Path, transportRelay)
	}
	d := out[keyName(both)]
	if d.Path != transportDirect {
		t.Errorf("both-maps path = %q, want %q", d.Path, transportDirect)
	}
	if d.State != "up" {
		t.Errorf("both-maps state = %q, want up", d.State)
	}
	if d.LastRecvAge <= 0 {
		t.Errorf("both-maps last-recv age = %v, want the relay age retained", d.LastRecvAge)
	}
}

// TestTransportStatsCounters drives a real punch and checks the counters the
// status reply reads.
func TestTransportStatsCounters(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
	defer engineA.Close()
	defer engineB.Close()

	engineA.Connect()
	engineB.Connect()

	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "stats")
	s.Close()

	waitFor(t, 5*time.Second, func() bool { return hasDirect(engineA, pubB) })

	// The first stream was opened before the punch and rode the relay (M3):
	// a stream's transport is a snapshot of the pair's path at open time. Open
	// another now that the pair prefers direct; that one is counted direct.
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s2, "stats-direct")
	s2.Close()

	punchAttempts, punchSuccess, streamsDirect, _ := engineA.stats.snapshot()
	if punchAttempts < 1 {
		t.Fatalf("punchAttempts = %d, want >= 1", punchAttempts)
	}
	if punchSuccess < 1 {
		t.Fatalf("punchSuccess = %d, want >= 1", punchSuccess)
	}
	if streamsDirect < 1 {
		t.Fatalf("streamsDirect = %d, want >= 1", streamsDirect)
	}
}

// relayServer is an in-process DERP-style relay: clients (engines) connect
// over WebSocket, and every SendPacket is forwarded to its destination key
// as a RecvPacket. It exercises the engine's packet pump, mux sessions, and
// bridging without needing a real derper (real-derper interop is a separate
// e2e gate).

var (
	relayPriv derpclient.PrivateKey
	relayOnce sync.Once
)

func relayKey() derpclient.PrivateKey {
	relayOnce.Do(func() { relayPriv, _, _ = derpclient.Generate() })
	return relayPriv
}

type relayServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	clients  map[[32]byte]*relayClient
	dropData bool // when true, drop 0x01 data frames (control still flows)
	dropPong bool // when true, stop answering pings (a half-open relay path)
	// dropCtrl, when set, is consulted for every forwarded control frame; true
	// drops it, so a test can lose one handshake half and prove the retry heals.
	dropCtrl func(dst [32]byte, payload []byte) bool
}

func (s *relayServer) setDropData(v bool) {
	s.mu.Lock()
	s.dropData = v
	s.mu.Unlock()
}

func (s *relayServer) setDropPong(v bool) {
	s.mu.Lock()
	s.dropPong = v
	s.mu.Unlock()
}

type relayClient struct {
	w  *frameW
	mu sync.Mutex
}

type frameW struct {
	ws *websocket.Conn
	mu sync.Mutex
}

func (w *frameW) write(t byte, body []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var hdr [5]byte
	hdr[0] = t
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(body)))
	if err := w.ws.Write(context.Background(), websocket.MessageBinary, hdr[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		return w.ws.Write(context.Background(), websocket.MessageBinary, body)
	}
	return nil
}

func (s *relayServer) start(t *testing.T) string {
	t.Helper()
	s.clients = make(map[[32]byte]*relayClient)
	mux := http.NewServeMux()
	mux.HandleFunc("/derp", func(hw http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(hw, r, &websocket.AcceptOptions{
			Subprotocols:    []string{"derp"},
			OriginPatterns:  []string{"*"},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer ws.Close(websocket.StatusInternalError, "bye")
		if ws.Subprotocol() != "derp" {
			return
		}
		s.serveClient(r.Context(), ws)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return "ws://" + s.srv.Listener.Addr().String() + "/derp"
}

func (s *relayServer) serveClient(ctx context.Context, ws *websocket.Conn) {
	skey := relayKey()
	spub := skey.Public()
	w := &frameW{ws: ws}
	// greeting: magic + server public key
	greeting := make([]byte, 0, 8+32)
	greeting = append(greeting, derpclient.Magic...)
	greeting = append(greeting, spub[:]...)
	w.write(0x01, greeting)

	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	var myPub [32]byte
	var registered bool
	defer func() {
		if !registered {
			return
		}
		// A disconnecting peer is reported gone to everyone else, like the real
		// derper (PeerGoneReasonDisconnected).
		s.mu.Lock()
		delete(s.clients, myPub)
		others := make([]*frameW, 0, len(s.clients))
		for _, c := range s.clients {
			others = append(others, c.w)
		}
		s.mu.Unlock()
		gone := append([]byte{}, myPub[:]...)
		gone = append(gone, 0x00)
		for _, oc := range others {
			oc.write(0x08, gone)
		}
	}()
	notified := map[[32]byte]bool{} // like the real derper: PeerGone once per dst
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		t := hdr[0]
		l := binary.BigEndian.Uint32(hdr[1:])
		body := make([]byte, l)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		switch t {
		case 0x02: // ClientInfo: box proof + register
			if len(body) < 32 {
				return
			}
			copy(myPub[:], body[:32])
			clientPub := derpclient.PublicKey(myPub)
			if _, ok := skey.OpenFrom(clientPub, body[32:]); !ok {
				return // bad box
			}
			s.mu.Lock()
			s.clients[myPub] = &relayClient{w: w}
			s.mu.Unlock()
			registered = true
			// ServerInfo: sealed by the server to the client.
			w.write(0x03, skey.SealTo(clientPub, []byte("{}")))
		case 0x04: // SendPacket: route by dst key
			if len(body) < 32 {
				return
			}
			var dst [32]byte
			copy(dst[:], body[:32])
			payload := body[32:]
			s.mu.Lock()
			rc := s.clients[dst]
			drop := s.dropData && len(payload) > 0 && payload[0] == 0x01
			dropCtrl := s.dropCtrl
			s.mu.Unlock()
			if rc == nil {
				// Unknown destination: tell the sender the peer is gone once,
				// like the real derper (PeerGoneReasonNotHere).
				if !notified[dst] {
					notified[dst] = true
					gone := append([]byte{}, dst[:]...)
					gone = append(gone, 0x01)
					w.write(0x08, gone)
				}
				continue
			}
			if drop {
				continue // drop data frames, keep control frames flowing
			}
			if dropCtrl != nil && len(payload) > 0 && payload[0] == 0x00 && dropCtrl(dst, payload) {
				continue // a test deliberately lost this control frame
			}
			pkt := make([]byte, 0, 32+len(payload))
			pkt = append(pkt, myPub[:]...)
			pkt = append(pkt, payload...)
			rc.w.write(0x05, pkt)
		case 0x06: // keepalive
		case 0x12: // ping → pong
			s.mu.Lock()
			drop := s.dropPong
			s.mu.Unlock()
			if drop {
				continue // a path that carries our bytes but never answers
			}
			w.write(0x13, body)
		}
	}
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestEngineRoundTripThroughRelay(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()

	// Both hosts connect to the relay at startup (rendezvous registration).
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// A opens a tunnel stream to B; B accepts and bridges to the echo
	// server. A writes, the echo bounces it back through B.
	stream, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 5)
	if _, err := stream.Write([]byte("ping!")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping!" {
		t.Fatalf("round trip payload = %q", buf)
	}

	// Reverse direction: B opens a stream to A. A has no --target, so the
	// inbound stream must be refused (closed) — the write succeeds locally
	// but the read side hits EOF.
	s2, err := engineB.OpenStream(engineA.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := s2.Write([]byte("x")); err != nil {
		t.Fatalf("write on refused inbound stream: %v", err)
	}
	s2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := s2.Read(buf); err == nil {
		t.Fatal("expected EOF on refused inbound stream")
	}
}

func TestParsePeerKey(t *testing.T) {
	_, pub, _ := derpclient.Generate()
	b64 := base64.RawURLEncoding.EncodeToString(pub[:])
	if _, err := parsePeerKey(b64); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := parsePeerKey("not-a-key"); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := parsePeerKey("AAAA"); err == nil {
		t.Fatal("short key accepted")
	}
}

// TestConnectErrorKeepsDialCause: a failed dial must surface its cause. A bare
// "connect failed" hides TLS/DNS problems the caller can act on (a self-signed
// relay, a bad CA file, a typo in the URL), which the log line alone does not
// fix for an API caller.
func TestConnectErrorKeepsDialCause(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("wss://127.0.0.1:1/derp", "", priv, slog.Default())
	defer e.Close()

	err = e.Connect()
	if err == nil {
		t.Fatal("Connect to a refused relay = nil error")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("Connect error = %v, want the dial cause (connection refused)", err)
	}
}

// TestRelaySilent: the watchdog's verdict, which is about a ping going
// unanswered — not about frames arriving, since a quiet relay carries none
// either way. It must not judge before the first probe, must tolerate a round
// trip that is merely in flight, and must fire once the outstanding probe is
// older than the ceiling.
func TestRelaySilent(t *testing.T) {
	now := time.Now()

	if relaySilent(time.Time{}, time.Time{}, now) {
		t.Error("no verdict before the first probe")
	}
	if relaySilent(now.Add(-relayDeadPeriod/4), time.Time{}, now) {
		t.Error("a fresh unanswered ping is not silence")
	}
	if relaySilent(now.Add(-relayDeadPeriod), time.Time{}, now) {
		t.Error("exactly at the ceiling is not yet silence")
	}
	if !relaySilent(now.Add(-relayDeadPeriod-time.Second), time.Time{}, now) {
		t.Error("an unanswered ping older than the ceiling is silence")
	}

	// An answered probe is never silence, however quiet the connection is: the
	// pong is newer than the ping that asked for it.
	if relaySilent(now.Add(-2*relayDeadPeriod), now.Add(-relayDeadPeriod/4), now) {
		t.Error("a fresh pong is not silence, however old the ping")
	}
	// A pong older than the ceiling, with a ping older still, is silence.
	if !relaySilent(now.Add(-2*relayDeadPeriod), now.Add(-relayDeadPeriod-time.Second), now) {
		t.Error("a pong older than the ceiling is silence")
	}
}

// TestRelaySilenceIsReconnected: a relay path can stop answering without the
// WebSocket noticing — writes sink into the kernel buffer, no frame arrives and
// nothing errors (measured on a phone switching Wi-Fi/cellular). Candidate
// exchange rides the relay, so a connection that is never torn down and redialed
// leaves every punch failing at "no peer candidates", forever. The keepalive's
// ping probe is the only thing that can see a path like that.
func TestRelaySilenceIsReconnected(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	priv, _, _ := derpclient.Generate()
	e := newEngine(url, "", priv, slog.Default())
	defer e.Close()
	if err := e.Connect(); err != nil {
		t.Fatal(err)
	}

	// An answering relay is never torn down, however short the tick.
	time.Sleep(200 * time.Millisecond)
	if !e.relayConnected() {
		t.Fatal("an answering relay was torn down")
	}

	// Stop answering pings. The connection must be declared dead (the redial is
	// the reconnect loop's business, and it does not run within this window).
	rs.setDropPong(true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !e.relayConnected() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a relay that stopped answering pings was never torn down")
}

// relayState must report the engine's own relay connection: the three states a
// status consumer has to tell apart.
func TestRelayState(t *testing.T) {
	// Never dialed.
	e := &engine{}
	if up, msg := e.relayState(); up || msg != "" {
		t.Errorf("fresh engine: up=%v msg=%q, want false/\"\"", up, msg)
	}

	// Connected.
	e.client = &derpclient.Client{}
	if up, msg := e.relayState(); !up || msg != "" {
		t.Errorf("connected: up=%v msg=%q, want true/\"\"", up, msg)
	}

	// Down, with the reason a user can act on.
	e.client = nil
	e.dialErr = errors.New("dial tcp 127.0.0.1:443: connect: connection refused")
	up, msg := e.relayState()
	if up {
		t.Error("up = true with no client")
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("msg = %q, want the dial failure", msg)
	}
}

// newEncryptedPair starts two engines on one in-process relay with the echo
// target, connected and ready.
func newEncryptedPair(t *testing.T) (*engine, *engine, *relayServer) {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)
	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	eA := newEngine(url, "", privA, slog.Default())
	eB := newEngine(url, echo, privB, slog.Default())
	t.Cleanup(func() { eA.Close(); eB.Close() })
	if err := eA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := eB.Connect(); err != nil {
		t.Fatal(err)
	}
	return eA, eB, rs
}

// peerSecureForTest reports whether this engine's session to peer is encrypted.
func (e *engine) peerSecureForTest(peer derpclient.PublicKey) bool {
	e.mu.Lock()
	pc := e.peers[peer]
	e.mu.Unlock()
	if pc == nil {
		return false
	}
	// pc.secure is reassignable at runtime now (a replacement installs a fresh
	// session), so read it under pc.mu like every production reader does.
	pc.mu.Lock()
	secure := pc.secure
	pc.mu.Unlock()
	_, _, ok := secure.keys()
	return ok
}

// TestRelaySessionEncrypted drives a stream through the relay and checks that
// both ends settled an encrypted relay session (the handshake ran, not just the
// round trip).
func TestRelaySessionEncrypted(t *testing.T) {
	eA, eB, _ := newEncryptedPair(t)

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	go conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("round trip: got %q", buf)
	}
	if !eA.peerSecureForTest(eB.pub) {
		t.Fatal("A's session did not settle encrypted")
	}
	if !eB.peerSecureForTest(eA.pub) {
		t.Fatal("B's session did not settle encrypted")
	}
}

// TestRelayLinkLossRekeys: a lost relay link must drop the pair's relay security
// session, so the reconnect re-handshakes instead of reusing counters a record
// lost mid-drop advanced (sendCtr can be one ahead of the peer's recvCtr, with no
// way to realign). Both ends must settle encrypted again and traffic must flow.
// No STUN is configured, so this is relay-only and the direct path is off.
func TestRelayLinkLossRekeys(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// Carry traffic over the relay and confirm the session is encrypted.
	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "before")
	s.Close()
	if !engineA.peerSecureForTest(pubB) || !engineB.peerSecureForTest(engineA.pub) {
		t.Fatal("relay session not encrypted before the loss")
	}

	// The relay link drops. teardown kills A's adapters; it must also drop the
	// pair's relay security session or the reconnect would reuse a counter the
	// lost record advanced and never realign.
	engineA.mu.Lock()
	c := engineA.client
	engineA.mu.Unlock()
	if c == nil {
		t.Fatal("A has no relay connection")
	}
	engineA.teardown(c, errors.New("test: relay link lost"))
	engineA.mu.Lock()
	_, cached := engineA.secure[secureKey{peer: pubB, transport: secureTransportRelay}]
	engineA.mu.Unlock()
	if cached {
		t.Fatal("teardown left the peer's relay security session cached")
	}

	// A redials on the next open. Both ends must re-handshake and settle
	// encrypted, and traffic must flow again (no permanent wedge).
	waitFor(t, 10*time.Second, func() bool {
		conn, err := engineA.OpenStream(engineB.PublicKey())
		if err != nil {
			return false
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("after")); err != nil {
			return false
		}
		buf := make([]byte, len("after"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return false
		}
		return string(buf) == "after"
	})
	if !engineA.peerSecureForTest(pubB) {
		t.Fatal("A's relay session did not settle encrypted after reconnect")
	}
	if !engineB.peerSecureForTest(engineA.pub) {
		t.Fatal("B's relay session did not settle encrypted after reconnect")
	}
}

// TestRelayHandshakeLostReplyHeals: a dropped reply must not strand one side in
// plaintext. A sends its half (want set), B settles and replies, the reply is
// lost, and A's retry — still asking — makes B answer again. Without the want
// bit A would stay unsettled (and plaintext) while B encrypts, killing both mux
// sessions and churning the shared relay.
func TestRelayHandshakeLostReplyHeals(t *testing.T) {
	defer resendInterval.Store(resendInterval.Load())
	resendInterval.Store(int64(50 * time.Millisecond))

	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)
	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	eA := newEngine(url, "", privA, slog.Default())
	eB := newEngine(url, echo, privB, slog.Default())
	t.Cleanup(func() { eA.Close(); eB.Close() })
	if err := eA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := eB.Connect(); err != nil {
		t.Fatal(err)
	}

	// Drop the first ctrlSecure frame the relay routes to A (B's first reply);
	// seen counts every such reply, so a retry reply proves A's want bit worked.
	var seen, dropped atomic.Int32
	rs.mu.Lock()
	rs.dropCtrl = func(dst [32]byte, payload []byte) bool {
		if dst != [32]byte(eA.pub) || len(payload) < 2 || payload[1] != ctrlSecure {
			return false
		}
		if seen.Add(1) == 1 {
			dropped.Add(1)
			return true
		}
		return false
	}
	rs.mu.Unlock()

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	go conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("round trip: got %q", buf)
	}
	if !eA.peerSecureForTest(eB.pub) {
		t.Fatal("A did not settle encrypted after a lost reply")
	}
	if !eB.peerSecureForTest(eA.pub) {
		t.Fatal("B did not settle encrypted")
	}
	if n := dropped.Load(); n != 1 {
		t.Fatalf("relay dropped %d replies, want exactly 1", n)
	}
	// The retry reply is the healing: without the want bit B would not answer a
	// half it had already settled on, and A would have stayed plaintext.
	if n := seen.Load(); n < 2 {
		t.Fatalf("relay routed %d replies to A, want >= 2 (the retry must draw one)", n)
	}
}

// TestStatusReportsEncryption drives an encrypted round trip and checks the host
// status counts the peer as encrypted and names it "secure".
func TestStatusReportsEncryption(t *testing.T) {
	eA, eB, _ := newEncryptedPair(t)

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "enc")

	srv := newServer(eA)
	defer srv.close()
	st := srv.status()
	if st.EncryptedPeers < 1 {
		t.Fatalf("EncryptedPeers = %d, want >= 1", st.EncryptedPeers)
	}
	if got := st.PeerEncryption[keyName(eB.pub)]; got != encStateSecure {
		t.Fatalf("PeerEncryption[peer] = %q, want %q", got, encStateSecure)
	}
}

// settledSecurePair returns two secureSessions that have exchanged their halves,
// so keys() reports ready on both — a stand-in for an encrypted (peer,
// transport) session without driving a full punch.
func settledSecurePair(t *testing.T, transport byte) (*secureSession, *secureSession) {
	t.Helper()
	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a := newSecureSession(nil, transport, privA, pubB)
	b := newSecureSession(nil, transport, privB, pubA)
	boxA, err := a.start()
	if err != nil {
		t.Fatal(err)
	}
	boxB, err := b.start()
	if err != nil {
		t.Fatal(err)
	}
	clearA, ok := privB.OpenFrom(pubA, boxA)
	if !ok {
		t.Fatal("unseal A's half")
	}
	clearB, ok := privA.OpenFrom(pubB, boxB)
	if !ok {
		t.Fatal("unseal B's half")
	}
	if ok, _ := a.respond(clearB); !ok {
		t.Fatal("A rejected B's half")
	}
	if ok, _ := b.respond(clearA); !ok {
		t.Fatal("B rejected A's half")
	}
	return a, b
}

// TestEncryptionState pins the peer-level rule: "secure" when the peer's relay
// session holds keys, else "plaintext". The direct underlay has no separate
// secure session after the pair migration (Task 7): it rides the pair's relay
// secure session, so a live direct path is exactly as encrypted as the relay it
// shares and does not change the classification.
func TestEncryptionState(t *testing.T) {
	peer := derpclient.PublicKey{7}
	encRelay, _ := settledSecurePair(t, secureTransportRelay)
	plain := newSecureSession(nil, secureTransportRelay, derpclient.PrivateKey{}, peer) // never settled

	if got := encryptionState(nil); got != encStatePlaintext {
		t.Errorf("no sessions = %q, want plaintext", got)
	}
	if got := encryptionState(&peerConn{peer: peer, secure: encRelay}); got != encStateSecure {
		t.Errorf("encrypted relay = %q, want secure", got)
	}
	if got := encryptionState(&peerConn{peer: peer, secure: plain}); got != encStatePlaintext {
		t.Errorf("plaintext relay = %q, want plaintext", got)
	}
	// A live direct path shares the relay's keys (the direct underlay has no
	// separate secure session and is not consulted), so it cannot downgrade an
	// encrypted relay session.
}

// TestRelayRefusesUnencryptedPeer: a relay that drops every ctrlSecure frame
// leaves the handshake unsettleable, and forced encryption must refuse the
// session rather than fall back to plaintext. The open fails; no cleartext
// session is built. Every ctrlSecure frame is dropped in both directions, so
// neither end settles; the shortened handshake timeout keeps the test prompt.
func TestRelayRefusesUnencryptedPeer(t *testing.T) {
	defer func(d time.Duration) { handshakeTimeout = d }(handshakeTimeout)
	handshakeTimeout = 300 * time.Millisecond
	defer resendInterval.Store(resendInterval.Load())
	resendInterval.Store(int64(50 * time.Millisecond))

	eA, eB, rs := newEncryptedPair(t)
	rs.mu.Lock()
	rs.dropCtrl = func(_ [32]byte, payload []byte) bool {
		return len(payload) > 1 && payload[1] == ctrlSecure
	}
	rs.mu.Unlock()

	start := time.Now()
	conn, err := eA.OpenStream(eB.PublicKey())
	if err == nil {
		conn.Close()
		t.Fatal("open succeeded without a settled handshake, want refusal")
	}
	if !errors.Is(err, errEncryptionRequired) {
		t.Fatalf("open error = %v, want errEncryptionRequired", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("refusal took %v, want it bounded by handshakeTimeout", elapsed)
	}

	// No cleartext session was built, and the refused peer has no live data path,
	// so it is not reported at all: PlaintextPeers stays 0 (forced encryption).
	srv := newServer(eA)
	defer srv.close()
	st := srv.status()
	if st.EncryptedPeers != 0 || st.PlaintextPeers != 0 {
		t.Errorf("EncryptedPeers=%d PlaintextPeers=%d, want 0/0 (a refused peer has no session)", st.EncryptedPeers, st.PlaintextPeers)
	}
	if got, ok := st.PeerEncryption[keyName(eB.pub)]; ok {
		t.Errorf("PeerEncryption[peer] = %q, want absent (no live session)", got)
	}
}

// TestPeerEncryptionsSkipsSessionless: a peer with no live data path (e.g. its
// session was refused) is not reported — otherwise PlaintextPeers would count a
// refused peer as a plaintext session. A live encrypted session reports secure.
func TestPeerEncryptionsSkipsSessionless(t *testing.T) {
	peer := derpclient.PublicKey{7}
	encRelay, _ := settledSecurePair(t, secureTransportRelay)
	plain := newSecureSession(nil, secureTransportRelay, derpclient.PrivateKey{}, peer)

	e := &engine{
		peers: map[derpclient.PublicKey]*peerConn{peer: {peer: peer, secure: plain}},
		log:   slog.Default(),
	}
	if got, ok := e.peerEncryptions()[keyName(peer)]; ok {
		t.Fatalf("session-less peer reported as %q, want absent", got)
	}

	// A live session is reported, and it is always secure under forced
	// encryption.
	e.peers[peer] = &peerConn{peer: peer, secure: encRelay, sess: newTestSess(t)}
	if got := e.peerEncryptions()[keyName(peer)]; got != encStateSecure {
		t.Fatalf("live encrypted peer = %q, want %q", got, encStateSecure)
	}
}

// TestEnsureSessionInboundDoesNotBlock: the pump path (wait=false) must never
// wait on the relay round trip, or one non-negotiating peer stalls inbound
// routing for every peer. With a large handshakeTimeout a non-blocking call on
// an unsettled adapter returns at once with a refusal, not after the timeout.
func TestEnsureSessionInboundDoesNotBlock(t *testing.T) {
	defer func(d time.Duration) { handshakeTimeout = d }(handshakeTimeout)
	handshakeTimeout = 30 * time.Second // a blocking call would take this long

	e := &engine{
		peers:  make(map[derpclient.PublicKey]*peerConn),
		secure: make(map[secureKey]*secureSession),
		gone:   make(map[derpclient.PublicKey]bool),
		log:    slog.Default(),
	}
	peer := derpclient.PublicKey{9}
	priv, _, _ := derpclient.Generate()
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, inboundQueueSize),
		closeCh: make(chan struct{}),
		secure:  newSecureSession(nil, secureTransportRelay, priv, peer),
	}

	start := time.Now()
	_, err := pc.ensureSession(true, false)
	if !errors.Is(err, errEncryptionRequired) {
		t.Fatalf("inbound call error = %v, want errEncryptionRequired", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("inbound call took %v with handshakeTimeout=%v: it blocked on the round trip", elapsed, handshakeTimeout)
	}
}
