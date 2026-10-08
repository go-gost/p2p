package host

// Task 2 (peer liveness): the death handler's contract. A relay mux session
// can die without closing itself — smux's recvLoop exits on a read error while
// the session stays open (IsClosed()==false) — and the relay-side accept loop
// returns silently on it. peerRelaySessionEnded is the handler the accept loop
// dispatches when that happens: it reports the death, force-closes the
// session, and rebuilds only when the pair proves the link is still carrying.
// Every test below fails to compile until the handler exists.

import (
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// buildRelaySession builds a live relay mux session over settled keys and
// returns the engine, adapter, session, and pair. The pair's recency is left
// untouched: tests that need a live gate stamp it themselves.
func buildRelaySession(t *testing.T, capture *logCapture, peer derpclient.PublicKey) (*engine, *peerConn, *relayKCPPair) {
	t.Helper()
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)

	settled, _ := settledSecurePair(t, secureTransportRelay)
	// Installed as the engine's cached session AND the adapter's, mirroring
	// relaySessionFor: the kill's compare-and-delete drop only removes the
	// entry when it is still this object.
	e.mu.Lock()
	e.secure[secureKey{peer: peer, transport: secureTransportRelay}] = settled
	e.mu.Unlock()
	pc := e.peerConn(peer)
	pc.mu.Lock()
	pc.secure = settled
	if _, err := pc.sessionLocked(); err != nil {
		pc.mu.Unlock()
		t.Fatalf("build session: %v", err)
	}
	old := pc.sess
	pc.mu.Unlock()
	if old == nil || old.IsClosed() {
		t.Fatal("sessionLocked returned no live session")
	}
	return e, pc, pair
}

// TestSessionEndReportedWithoutKill drives the full production path: the
// session's underlay view is retired out from under it (what a dead link
// looks like to smux — recvLoop exits on a read error, the session never
// closes itself), the relay-side accept loop returns on it, and the handler
// it dispatches reports the death and rebuilds over the still-live pair.
// No kill runs anywhere in this test: the ended line is the only trace.
func TestSessionEndReportedWithoutKill(t *testing.T) {
	capture := &logCapture{}
	peer := derpclient.PublicKey{41}
	_, pc, pair := buildRelaySession(t, capture, peer)
	// The pair is still carrying: the gate must let the rebuild through.
	setPairRelayRecency(pair, time.Now())

	pc.mu.Lock()
	old := pc.sess
	pc.mu.Unlock()
	pc.startAccept()

	// Retire the view the session reads. The next build's claim would close
	// it the same way; doing it here stands in for the link dying first.
	pair.newStream()

	waitFor(t, 5*time.Second, func() bool {
		return capture.count("peer relay session ended") == 1
	})
	waitFor(t, 5*time.Second, func() bool {
		pc.mu.Lock()
		defer pc.mu.Unlock()
		return pc.sess != nil && pc.sess != old
	})

	attrs := capture.nth("peer relay session ended", 0)
	if attrs == nil {
		t.Fatal("the ended line was counted but its record was not captured")
	}
	if attrs["peer"] != keyName(peer) {
		t.Fatalf("ended peer = %q, want %q", attrs["peer"], keyName(peer))
	}
	if attrs["deduped"] != "false" || attrs["pairFresh"] != "true" {
		t.Fatalf("ended outcome = deduped:%q pairFresh:%q, want false/true: the pair was carrying, the rebuild must have been accepted", attrs["deduped"], attrs["pairFresh"])
	}
	if attrs["error"] == "" {
		t.Fatal("the ended line carries no error: the accept loop's cause is the reason the line exists")
	}
	if !old.IsClosed() {
		t.Fatal("the dead session was never force-closed: a not-closed session the handler saw must not stay open")
	}

	rebuilt := capture.nth("relay session rebuilt", 0)
	if rebuilt == nil {
		t.Fatal("no rebuild followed the reported death over a live pair")
	}
	if rebuilt["downFor"] == "" {
		t.Fatal("the rebuild carries no downFor: the ended line dates the death, the rebuild must date the outage")
	}
}

// TestDeathHandlerDedupsAgainstKill pins the A/B mutual exclusion: a kill
// closes the adapter, so a death report arriving for the old session must
// stand down — a superseded error, no rebuild, and no resurrection of what
// the kill dropped.
func TestDeathHandlerDedupsAgainstKill(t *testing.T) {
	capture := &logCapture{}
	peer := derpclient.PublicKey{42}
	e, pc, _ := buildRelaySession(t, capture, peer)

	pc.mu.Lock()
	old := pc.sess
	pc.mu.Unlock()

	// reasonLinkLost drops the pair and the secure session: the report must
	// resurrect neither.
	pc.killSession(errors.New("test: link lost"), true, reasonLinkLost)

	err := e.peerRelaySessionEnded(old, peer, errors.New("test: read error"))
	if !errors.Is(err, errRelaySessionSuperseded) {
		t.Fatalf("report after kill = %v, want %v", err, errRelaySessionSuperseded)
	}
	// The stand-down is itself reported, marked deduped: the line is the
	// event, deduped=true is what says "the kill owns this death". Two
	// lines, not one: the kill's own sess.Close wakes the parked accept
	// loop, whose exit reports the same session asynchronously — also
	// deduped, since the kill closed the adapter first. Both orders are
	// possible; the set is what matters.
	waitFor(t, 5*time.Second, func() bool {
		return capture.count("peer relay session ended") == 2
	})
	for i := 0; i < 2; i++ {
		if got := capture.nth("peer relay session ended", i)["deduped"]; got != "true" {
			t.Fatalf("ended line %d deduped = %q, want true", i, got)
		}
	}
	// The lookup behind the report must not resurrect what the kill dropped:
	// peerConn's creating lookup re-creates the e.secure entry and logs a
	// "relay session rebuilt" line for a session nobody built.
	if got := capture.count("relay session rebuilt"); got != 0 {
		t.Fatalf("rebuilt lines = %d, want 0: standing down must build nothing", got)
	}
	e.mu.Lock()
	_, ok := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if ok {
		t.Fatal("the e.secure entry the kill dropped is back: the report re-created it")
	}
}

// TestDeathHandlerRebuildsOnFreshPair is the handler's core contract, called
// directly: a live pair means the death was the session's, not the link's,
// so the handler closes the session and rebuilds immediately.
func TestDeathHandlerRebuildsOnFreshPair(t *testing.T) {
	capture := &logCapture{}
	peer := derpclient.PublicKey{43}
	e, pc, pair := buildRelaySession(t, capture, peer)
	setPairRelayRecency(pair, time.Now())

	pc.mu.Lock()
	old := pc.sess
	pc.mu.Unlock()

	if err := e.peerRelaySessionEnded(old, peer, errors.New("test: read error")); err != nil {
		t.Fatalf("report over a live pair: %v", err)
	}
	if !old.IsClosed() {
		t.Fatal("the dead session was never force-closed")
	}
	pc.mu.Lock()
	cur := pc.sess
	pc.mu.Unlock()
	if cur == nil || cur == old {
		t.Fatal("no rebuild followed the report over a live pair")
	}
	// Two lines: the accepted report, then the echo. The handler's Close
	// wakes the parked accept loop, whose exit reports the same session —
	// deduped, because lastEnded was recorded before the Close and the
	// rebuild has already replaced sess. The direct line is logged before
	// the Close, so the order is deterministic.
	waitFor(t, 5*time.Second, func() bool {
		return capture.count("peer relay session ended") == 2
	})
	first, second := capture.nth("peer relay session ended", 0), capture.nth("peer relay session ended", 1)
	if first["deduped"] != "false" || first["pairFresh"] != "true" {
		t.Fatalf("first ended outcome = deduped:%q pairFresh:%q, want false/true", first["deduped"], first["pairFresh"])
	}
	if second["deduped"] != "true" {
		t.Fatalf("echo ended deduped = %q, want true", second["deduped"])
	}
	if capture.nth("relay session rebuilt", 0) == nil {
		t.Fatal("the rebuild logged no \"relay session rebuilt\" record")
	}
}

// TestDeathHandlerStandsDownOnStalePair is the gate's other half: a pair
// silent past the window means the link is down, and rebuilding smux on a
// dead pair is the 15s-death loop. The handler reports the death and stops.
func TestDeathHandlerStandsDownOnStalePair(t *testing.T) {
	capture := &logCapture{}
	peer := derpclient.PublicKey{44}
	e, pc, pair := buildRelaySession(t, capture, peer)
	// Both underlays quiet well past the window: nothing is carrying.
	old := time.Now().Add(-(relayLiveWindow + time.Minute))
	setPairRecency(pair, old, old)

	pc.mu.Lock()
	sess := pc.sess
	pc.mu.Unlock()

	err := e.peerRelaySessionEnded(sess, peer, errors.New("test: read error"))
	if !errors.Is(err, errRelaySessionStale) {
		t.Fatalf("report over a stale pair = %v, want %v", err, errRelaySessionStale)
	}
	// Two lines: the accepted report, then the echo. The handler still
	// force-closes on the stale path (the §2.3 invariant holds regardless
	// of the gate), and the Close wakes the parked accept loop — deduped,
	// because lastEnded was recorded before the Close. Neither rebuilds.
	waitFor(t, 5*time.Second, func() bool {
		return capture.count("peer relay session ended") == 2
	})
	if attrs := capture.nth("peer relay session ended", 0); attrs["deduped"] != "false" || attrs["pairFresh"] != "false" {
		t.Fatalf("ended outcome = deduped:%q pairFresh:%q, want false/false: accepted, but the pair was stale", attrs["deduped"], attrs["pairFresh"])
	}
	if got := capture.nth("peer relay session ended", 1)["deduped"]; got != "true" {
		t.Fatalf("echo ended deduped = %q, want true", got)
	}
	if got := capture.count("relay session rebuilt"); got != 0 {
		t.Fatalf("rebuilt lines = %d, want 0: a stale pair must not be rebuilt on", got)
	}
	pc.mu.Lock()
	cur := pc.sess
	pc.mu.Unlock()
	if cur != sess {
		t.Fatal("the adapter was rebuilt despite the stale gate")
	}
}

// TestDeathReportRacingKillStandsDown hammers the handler against kills: it
// asserts nothing about who wins, only that the race is safe — no panic, no
// deadlock — and that the logs stay within what 100 deaths can produce.
func TestDeathReportRacingKillStandsDown(t *testing.T) {
	capture := &logCapture{}
	peer := derpclient.PublicKey{45}
	e, pc, pair := buildRelaySession(t, capture, peer)
	setPairRelayRecency(pair, time.Now())

	pc.mu.Lock()
	sess := pc.sess
	pc.mu.Unlock()

	var wg sync.WaitGroup
	var resMu sync.Mutex
	accepted := 0
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := e.peerRelaySessionEnded(sess, peer, errors.New("test: read error")); err == nil {
				resMu.Lock()
				accepted++
				resMu.Unlock()
			}
		}()
		go func(n int) {
			defer wg.Done()
			cur := e.peerConn(peer)
			cur.killSession(errors.New("test: racing kill"), true, reasonLocalKill)
		}(i)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("handler/kill race did not finish: suspected deadlock")
	}

	total := capture.count("peer relay session ended") + capture.count("peer session killed")
	if total == 0 || total > 100 {
		t.Fatalf("ended + killed lines = %d, want in (0, 100]: every death accounted for, none invented", total)
	}
	// Every rebuild line has a cause: an accepted report's single ensureSession
	// call, or a dead adapter left by an effective kill (whose replacement
	// logs the rebuild on the next lookup — repeat kills on a closed adapter
	// return early and log nothing). A kill racing an accepted report can
	// never conjure a rebuild from neither: kills resurrect nothing.
	kills := capture.count("peer session killed")
	if got := capture.count("relay session rebuilt"); got > accepted+kills {
		t.Fatalf("rebuilt lines = %d, accepted reports + kills = %d: a rebuild without a cause", got, accepted+kills)
	}
}

// TestDuplicateDeathReportIsIdempotent: reporting one session twice must
// rebuild only once. Three lines, not two: the accepted report's Close wakes
// the parked accept loop, whose exit reports the same session asynchronously
// — deduped, like the explicit second report. The echo and the duplicate
// race; the set is what matters.
func TestDuplicateDeathReportIsIdempotent(t *testing.T) {
	capture := &logCapture{}
	peer := derpclient.PublicKey{46}
	e, pc, pair := buildRelaySession(t, capture, peer)
	setPairRelayRecency(pair, time.Now())

	pc.mu.Lock()
	sess := pc.sess
	pc.mu.Unlock()

	if err := e.peerRelaySessionEnded(sess, peer, errors.New("test: read error")); err != nil {
		t.Fatalf("first report: %v", err)
	}
	err := e.peerRelaySessionEnded(sess, peer, errors.New("test: read error"))
	if !errors.Is(err, errRelaySessionSuperseded) {
		t.Fatalf("second report = %v, want %v", err, errRelaySessionSuperseded)
	}
	// All three reports are events; only the first rebuilds. The echo and
	// the duplicate arrive in either order; both stand down.
	waitFor(t, 5*time.Second, func() bool {
		return capture.count("peer relay session ended") == 3
	})
	if got := capture.nth("peer relay session ended", 0)["deduped"]; got != "false" {
		t.Fatalf("first ended deduped = %q, want false: the direct line precedes the Close", got)
	}
	for i := 1; i < 3; i++ {
		if got := capture.nth("peer relay session ended", i)["deduped"]; got != "true" {
			t.Fatalf("ended line %d deduped = %q, want true", i, got)
		}
	}
	if got := capture.count("relay session rebuilt"); got != 1 {
		t.Fatalf("rebuilt lines = %d, want 1: the duplicate must not rebuild again", got)
	}
}
