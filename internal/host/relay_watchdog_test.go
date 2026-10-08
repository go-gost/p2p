package host

// Task 3 (peer liveness): the relay idle watchdog's contract. A relay pair
// whose underlay goes quiet past relayIdleWindow is a dead link, not an idle
// one (a healthy session's smux NOPs cross every 3s), and the watchdog acts in
// two strikes: strike 1 kills only the mux (clean death, pair and keys
// survive), strike 2 — after a rebuild still sees silence — kills the pair.
// Every test below fails to compile until the watchdog exists.

import (
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// shortenRelayIdle names the window/tick boundary without backdating stamps
// by hours: the production 6s/1s would make every test sleep for seconds.
func shortenRelayIdle(t *testing.T) {
	t.Helper()
	oldWindow, oldTick := relayIdleWindow, relayIdleTick
	relayIdleWindow = 150 * time.Millisecond
	relayIdleTick = 25 * time.Millisecond
	t.Cleanup(func() { relayIdleWindow, relayIdleTick = oldWindow, oldTick })
}

// shortenRelayWindowOnly shortens the window but leaves the tick at its
// production 1s: tests that drive reportRelayIdle directly finish in
// milliseconds, so the pair's own ticker can never win the first fire. Only
// tests that ride the real ticker (FirstStrike, ExitsWithPair) shorten both.
func shortenRelayWindowOnly(t *testing.T) {
	t.Helper()
	oldWindow := relayIdleWindow
	relayIdleWindow = 150 * time.Millisecond
	t.Cleanup(func() { relayIdleWindow = oldWindow })
}

// watchdogEngine builds an engine with a captured log and a live relay
// session for peer, and returns the pair. The pair's recency is left
// untouched: tests that need silence backdate it themselves.
func watchdogEngine(t *testing.T, capture *logCapture, peer derpclient.PublicKey) (*engine, *peerConn, *relayKCPPair) {
	t.Helper()
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	settled, _ := settledSecurePair(t, secureTransportRelay)
	pc := relaySessionFor(t, e, peer, settled)
	pair := e.relayKCPPairGet(peer)
	if pair == nil {
		t.Fatal("no pair KCP session built")
	}
	return e, pc, pair
}

// TestRelayWatchdogFirstStrikeKillsMuxOnly drives the full production path:
// the pair goes quiet past the window, the watchdog's own ticker fires strike
// 1, and only the mux dies — the pair and its keys survive for the cheap
// rebuild.
func TestRelayWatchdogFirstStrikeKillsMuxOnly(t *testing.T) {
	shortenRelayIdle(t)
	capture := &logCapture{}
	peer := derpclient.PublicKey{51}
	e, pc, pair := watchdogEngine(t, capture, peer)
	settled := pc.secure
	// Quiet well past the window on both underlays: nothing is carrying.
	ancient := time.Now().Add(-time.Hour)
	setPairRecency(pair, ancient, ancient)

	waitFor(t, 5*time.Second, func() bool {
		return capture.count("relay path silent") >= 1
	})
	waitFor(t, 5*time.Second, func() bool {
		return capture.count("peer session killed") >= 1
	})

	evidence := capture.nth("relay path silent", 0)
	if evidence["strike"] != "1" {
		t.Fatalf("first evidence strike = %q, want 1", evidence["strike"])
	}
	if evidence["silentFor"] == "" {
		t.Fatal("the evidence line carries no silentFor: the relay-measured silence is the reason the line exists")
	}
	if evidence["peer"] != keyName(peer) {
		t.Fatalf("evidence peer = %q, want %q", evidence["peer"], keyName(peer))
	}
	kill := capture.nth("peer session killed", 0)
	if kill["relayReason"] != string(reasonRelaySilent) {
		t.Fatalf("first-strike kill reason = %q, want %q", kill["relayReason"], reasonRelaySilent)
	}
	// Mux only: the pair survives with its keys, and nothing rebuilds on the
	// stale pair (the Task-2 gate stands the echo down).
	if got := e.relayKCPPairGet(peer); got == nil {
		t.Fatal("the pair died on strike 1: a clean kill must keep it")
	}
	e.mu.Lock()
	kept, ok := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if !ok || kept != settled {
		t.Fatal("the secure session was dropped on strike 1: a clean kill must reuse it")
	}
	if got := capture.count("relay session rebuilt"); got != 0 {
		t.Fatalf("rebuilt lines = %d, want 0: the pair is stale, nothing may rebuild on it", got)
	}
	// One episode, one strike: the latch holds for the rest of the silence.
	time.Sleep(3 * relayIdleWindow)
	if got := capture.count("relay path silent"); got != 1 {
		t.Fatalf("evidence lines = %d, want 1: the episode latch must hold while the silence continues", got)
	}
}

// TestRelayWatchdogSecondStrikeResetsPair is the escalation: strike 1 kills
// the mux, a rebuild still sees silence (the episode continues), and strike 2
// kills the pair — the epoch ends and the keys go with it.
func TestRelayWatchdogSecondStrikeResetsPair(t *testing.T) {
	shortenRelayWindowOnly(t)
	capture := &logCapture{}
	peer := derpclient.PublicKey{52}
	e, _, pair := watchdogEngine(t, capture, peer)
	ancient := time.Now().Add(-time.Hour)
	setPairRecency(pair, ancient, ancient)

	// Strike 1, driven directly: the return is the contract, not the ticker.
	strike, silentFor := pair.reportRelayIdle()
	if strike != 1 {
		t.Fatalf("first report strike = %d, want 1", strike)
	}
	if silentFor <= relayIdleWindow {
		t.Fatalf("first report silentFor = %v, want past the window", silentFor)
	}
	e.relayPathSilent(peer, pair, strike, silentFor)
	waitFor(t, 5*time.Second, func() bool {
		return capture.count("peer session killed") >= 1
	})
	if got := capture.nth("peer session killed", 0)["relayReason"]; got != string(reasonRelaySilent) {
		t.Fatalf("strike-1 kill reason = %q, want %q", got, reasonRelaySilent)
	}
	if got := e.relayKCPPairGet(peer); got == nil {
		t.Fatal("the pair died on strike 1")
	}

	// The episode continues: a rebuild over the surviving pair (keys kept, so
	// no re-handshake), still with no relay traffic. The rebuild re-arms the
	// latch for the new session — the silence, not the timer, is what carries
	// the strikes.
	e.mu.Lock()
	settled := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if settled == nil {
		t.Fatal("strike 1 dropped the secure session: a clean kill must keep it")
	}
	pc2 := relaySessionFor(t, e, peer, settled)
	_ = pc2
	if got := e.relayKCPPairGet(peer); got == nil {
		t.Fatal("the pair died on the strike-1 rebuild")
	}

	strike, silentFor = pair.reportRelayIdle()
	if strike != 2 {
		t.Fatalf("second report strike = %d, want 2: the rebuild re-arms the latch, the continued silence escalates", strike)
	}
	e.relayPathSilent(peer, pair, strike, silentFor)
	if got := e.relayKCPPairGet(peer); got != nil {
		t.Fatal("the pair survived strike 2: a continued silence must end the epoch")
	}
	// The epoch ends but the keys stay: strike 2 passes dropSecure=false, so
	// the rebuild reuses keys and counters, and any nonce gap from the lost
	// segments heals through the desync re-handshake (secureDesyncThreshold).
	e.mu.Lock()
	kept, ok := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if !ok || kept != settled {
		t.Fatal("the secure session was dropped on strike 2: the epoch reset keeps keys by design")
	}
	found := false
	for i := 0; i < capture.count("peer session killed"); i++ {
		if capture.nth("peer session killed", i)["relayReason"] == string(reasonLinkLost) {
			found = true
		}
	}
	if !found {
		t.Fatal("no link-lost kill line: strike 2 must kill with the pair-resetting reason")
	}
}

// TestRelayWatchdogRearmsOnTraffic is the latch's other half: a relay
// datagram inside the episode closes it — strikes clear, and the next silence
// starts over at strike 1, not at an escalation.
func TestRelayWatchdogRearmsOnTraffic(t *testing.T) {
	shortenRelayWindowOnly(t)
	capture := &logCapture{}
	peer := derpclient.PublicKey{53}
	e, pc, pair := watchdogEngine(t, capture, peer)
	ancient := time.Now().Add(-time.Hour)
	setPairRecency(pair, ancient, ancient)

	if strike, _ := pair.reportRelayIdle(); strike != 1 {
		t.Fatalf("first report strike = %d, want 1", strike)
	}
	// A real relay datagram through the real read path — not a stamp
	// assignment: the rearm lives at readRelay's stamp site, and this test
	// must execute it. pumpRelay is the inbound queue's only reader, so the
	// push is consumed by the pump; the wait below observes the rearm it
	// performed.
	select {
	case pc.inbound <- []byte("relay traffic"):
	default:
		t.Fatal("the adapter's inbound queue is full")
	}
	waitFor(t, 5*time.Second, func() bool {
		pair.mu.Lock()
		defer pair.mu.Unlock()
		return pair.relayStrikes == 0 && !pair.relayIdleFired
	})

	// The episode closed: silence again starts at strike 1.
	setPairRecency(pair, ancient, ancient)
	if strike, _ := pair.reportRelayIdle(); strike != 1 {
		t.Fatalf("report after traffic strike = %d, want 1: traffic must clear the strikes", strike)
	}
	if got := capture.count("peer session killed"); got != 0 {
		t.Fatalf("killed lines = %d, want 0: reporting is not acting", got)
	}
	if got := e.relayKCPPairGet(peer); got == nil {
		t.Fatal("the pair died without any strike acting on it")
	}
}

// TestRelayWatchdogLiveDirectSuppressesStrike: the fire condition is pair
// silence, not relay silence. A session living on direct sends nothing over
// the relay underlay — relay goes quiet while the pair carries — and killing
// its mux every window would flap every stable direct connection into a
// rebuild loop. Direct-fresh means (0, 0), however ancient the relay stamp.
func TestRelayWatchdogLiveDirectSuppressesStrike(t *testing.T) {
	shortenRelayWindowOnly(t)
	capture := &logCapture{}
	peer := derpclient.PublicKey{56}
	_, _, pair := watchdogEngine(t, capture, peer)

	setPairRelayRecency(pair, time.Now().Add(-time.Hour))
	setPairDirectRecency(pair, time.Now())
	if strike, _ := pair.reportRelayIdle(); strike != 0 {
		t.Fatalf("report strike = %d, want 0: the pair is carrying on direct, relay silence alone is not an outage", strike)
	}
	if got := capture.count("relay path silent"); got != 0 {
		t.Fatalf("evidence lines = %d, want 0: no strike, no evidence", got)
	}
}

// TestRelayWatchdogRearmsOnDirectTraffic is the direct half of the rearm: a
// direct datagram inside the episode closes it like a relay one does —
// otherwise a path that flaps direct-up then down again would never escalate,
// the latch held from the first silence forever.
func TestRelayWatchdogRearmsOnDirectTraffic(t *testing.T) {
	shortenRelayWindowOnly(t)
	capture := &logCapture{}
	peer := derpclient.PublicKey{57}
	e, _, pair := watchdogEngine(t, capture, peer)
	ancient := time.Now().Add(-time.Hour)
	setPairRecency(pair, ancient, ancient)

	if strike, _ := pair.reportRelayIdle(); strike != 1 {
		t.Fatalf("first report strike = %d, want 1", strike)
	}
	// A real direct datagram through the real pump — not a stamp assignment:
	// the rearm lives at pumpDirect's stamp site, and this test must execute
	// it. The underlay drops datagrams from any source but the punched peer
	// (see readFrom), so the peer end is kept and the packet is sent from it.
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	t.Cleanup(func() { b.Close() })
	e.relayKCPPairFor(peer).setDirectUnderlay(newDirectUnderlay(a, udpAddrPort(t, b)))
	if _, err := b.WriteToUDP([]byte("direct traffic"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		pair.mu.Lock()
		defer pair.mu.Unlock()
		return pair.relayStrikes == 0 && !pair.relayIdleFired
	})

	// The episode closed: silence again starts at strike 1.
	setPairRecency(pair, ancient, ancient)
	if strike, _ := pair.reportRelayIdle(); strike != 1 {
		t.Fatalf("report after direct traffic strike = %d, want 1: direct traffic must clear the episode", strike)
	}
}

// TestRelayWatchdogStaleDispatchStandsDown: a strike dispatched from a pair
// that is reset before the dispatch runs must not kill the replacement
// adapter. The dispatch carries no identity today — it kills whatever adapter
// is current — so a scheduling stall across a pair reset turns one outage's
// strike into a second, unrelated kill.
func TestRelayWatchdogStaleDispatchStandsDown(t *testing.T) {
	shortenRelayWindowOnly(t)
	capture := &logCapture{}
	peer := derpclient.PublicKey{58}
	e, pc, pair := watchdogEngine(t, capture, peer)

	// Reset the pair out from under the strike: the strike-2 kill ends P1
	// and its adapter, and the rebuild comes up on a new pair P2 with a new
	// adapter — the production interleaving a stalled dispatch lands in.
	// dropSecure=false keeps the keys, like the real strike 2.
	killsBefore := capture.count("peer session killed")
	pc.killSession(errors.New("test: strike 2"), false, reasonLinkLost)
	if got := e.relayKCPPairGet(peer); got != nil {
		t.Fatal("the pair survived the link-lost kill")
	}
	e.mu.Lock()
	settled := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if settled == nil {
		t.Fatal("the link-lost kill dropped the secure session")
	}
	pc2 := relaySessionFor(t, e, peer, settled)
	pair2 := e.relayKCPPairGet(peer)
	if pair2 == nil || pair2 == pair {
		t.Fatal("no replacement pair carries the rebuilt session")
	}
	setPairRecency(pair2, time.Now(), time.Now())

	// The stale strike, dispatched from P1 before the reset, runs now.
	e.relayPathSilent(peer, pair, 1, time.Second)
	if got := capture.count("peer session killed"); got != killsBefore+1 {
		t.Fatalf("killed lines = %d, want %d: a stale dispatch must not kill the replacement adapter", got, killsBefore+1)
	}
	pc2.mu.Lock()
	closed := pc2.sess.IsClosed()
	pc2.mu.Unlock()
	if closed {
		t.Fatal("the replacement session is closed: the stale strike killed it")
	}
}

// TestRelayWatchdogIgnoresSessionlessPair: a pair that never built a session
// (sessAt zero — no mux to kill) must not be killed by the watchdog, however
// silent. There is nothing to rebuild and no outage to date.
func TestRelayWatchdogIgnoresSessionlessPair(t *testing.T) {
	shortenRelayWindowOnly(t)
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{54}
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)
	ancient := time.Now().Add(-time.Hour)
	setPairRecency(pair, ancient, ancient)

	strike, silentFor := pair.reportRelayIdle()
	if strike != 1 {
		t.Fatalf("report strike = %d, want 1: the pair-side report does not know about sessions", strike)
	}
	e.relayPathSilent(peer, pair, strike, silentFor)

	if got := capture.count("peer session killed"); got != 0 {
		t.Fatalf("killed lines = %d, want 0: a sessionless pair has no mux to kill", got)
	}
	if got := e.relayKCPPairGet(peer); got == nil {
		t.Fatal("the pair died on a sessionless strike")
	}
}

// TestRelayWatchdogZeroRelayStampClampsEvidence: a pair that never received a
// relay datagram (raised on direct, or virgin) has a zero relay stamp.
// Reporting "since the zero time" would emit uptime-shaped noise as evidence;
// the report clamps it to 0 — "cannot say", matching silentFor=0's standing
// meaning on the kill/rebuild lines.
func TestRelayWatchdogZeroRelayStampClampsEvidence(t *testing.T) {
	shortenRelayWindowOnly(t)
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{59}
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)
	// Relay stamp stays zero (never observed); direct stale past the window
	// so the pair reads as silent and the report fires.
	setPairDirectRecency(pair, time.Now().Add(-time.Hour))

	strike, silentFor := pair.reportRelayIdle()
	if strike != 1 {
		t.Fatalf("report strike = %d, want 1", strike)
	}
	if silentFor != 0 {
		t.Fatalf("report silentFor = %v, want 0: a zero relay stamp is unmeasured, not ancient", silentFor)
	}
}

// TestRelayWatchdogExitsWithPair: the watchdog shares the pair's lifetime —
// dropRelayKCP (the strike-2 end, or any pair reset) must end its goroutine,
// not leak one ticker per dead pair.
func TestRelayWatchdogExitsWithPair(t *testing.T) {
	shortenRelayIdle(t)
	capture := &logCapture{}
	peer := derpclient.PublicKey{55}
	e, _, pair := watchdogEngine(t, capture, peer)

	before := capture.count("relay path silent")
	e.dropRelayKCP(peer, nil, errors.New("test: pair reset"), 0)
	if got := e.relayKCPPairGet(peer); got != nil {
		t.Fatal("the pair survived dropRelayKCP")
	}
	// The watchdog is gone with the pair: continued silence fires nothing.
	// (The pair object is shut down; its ticker must not report again.)
	setPairRelayRecency(pair, time.Now().Add(-time.Hour))
	time.Sleep(3 * relayIdleTick)
	if got := capture.count("relay path silent"); got != before {
		t.Fatalf("evidence lines grew %d -> %d after the pair died: the watchdog outlived it", before, got)
	}
}
