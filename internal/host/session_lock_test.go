package host

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestDetachSessionKeepsInFlightRound pins the markDead/session fix: a punch
// round already in flight owns dc.mine, so a dying session must not clear it
// (that stops this side answering the peer's announcements), and must not reset
// the state to directNone (that let a second round start on the same candidate
// channel). Only a session that itself owned the state (directUp) hands the
// re-punch back.
func TestDetachSessionKeepsInFlightRound(t *testing.T) {
	own := []candidate{{addr: netip.MustParseAddrPort("203.0.113.7:2222")}}

	// A round is in flight: state and mine must survive the session's death.
	dc := newSlotConn(t)
	sess := newTestSess(t)
	dc.mu.Lock()
	dc.sess, dc.mine, dc.state = sess, own, directAttempting
	dc.mu.Unlock()

	dc.mu.Lock()
	_, repunch := dc.detachSessionLocked(sess)
	mine, state := dc.mine, dc.state
	dc.mu.Unlock()

	if repunch {
		t.Fatal("detach scheduled a re-punch while a round is in flight")
	}
	if state != directAttempting {
		t.Fatalf("state = %v after detach, want directAttempting (round left to finish)", state)
	}
	if len(mine) != 1 || mine[0].addr != own[0].addr {
		t.Fatalf("mine = %v after detach, want the in-flight round's candidates kept", candAddrs(mine))
	}

	// A live session (directUp) hands the re-punch back and clears its state.
	dc2 := newSlotConn(t)
	sess2 := newTestSess(t)
	dc2.mu.Lock()
	dc2.sess, dc2.mine, dc2.state = sess2, own, directUp
	dc2.mu.Unlock()

	dc2.mu.Lock()
	_, repunch2 := dc2.detachSessionLocked(sess2)
	got2, mine2, state2 := dc2.sess, dc2.mine, dc2.state
	dc2.mu.Unlock()

	if !repunch2 {
		t.Fatal("detach did not hand the re-punch back for a directUp session")
	}
	if state2 != directNone || got2 != nil || mine2 != nil {
		t.Fatalf("directUp detach left sess=%v mine=%v state=%v, want nil/nil/directNone",
			got2, candAddrs(mine2), state2)
	}
}

// TestEnsureSessionNoLockInversion drives the two writers of a peerConn's
// session state at once: peerConn takes e.mu then pc.mu, while ensureSession
// takes pc.mu, releases it, and only then (via maybeStartDirect) takes e.mu.
// With the punch started under pc.mu — where it used to be — these two invert
// and deadlock, so a bounded completion here is the regression guard for the
// lock-order fix. Run under -race, it also covers the pc.sess race the pump's
// unguarded call used to produce.
func TestEnsureSessionNoLockInversion(t *testing.T) {
	e := newTestEngine(t)
	e.stunAddr = "127.0.0.1:3478" // makes directEnabled true, so the punch path takes e.mu
	peer := derpclient.PublicKey{7}

	// A live session and a backed-off punch: the loop then only exercises the
	// locking, not session or punch creation.
	pc := e.peerConn(peer)
	pc.mu.Lock()
	pc.sess = newTestSess(t)
	pc.sessAt = time.Now()
	pc.mu.Unlock()
	dc := e.directConn(peer)
	dc.mu.Lock()
	dc.state = directBackoff
	dc.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			e.peerConn(peer) // e.mu -> pc.mu
		}
	}()
	for i := 0; i < 500; i++ {
		pc.ensureSession(true, true) // pc.mu, released, then e.mu
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("peerConn + ensureSession deadlocked: lock order inverted")
	}
}

// TestRelaySessionChurnReconnectsRelay: a pair whose packets the relay stopped
// routing rebuilds its session every keepalive timeout, forever, while the
// shared connection stays busy with every other peer — the one shape the
// connection-level silence check cannot see (frames still arrive; they are just
// not this pair's). The engine tears the transport down itself, because the
// stale registration that caused it is cleared by nothing smaller.
func TestRelaySessionChurnReconnectsRelay(t *testing.T) {
	defer func(w time.Duration, m int) { relayChurnWindow, relayChurnMax = w, m }(relayChurnWindow, relayChurnMax)
	relayChurnWindow, relayChurnMax = time.Minute, 2

	rs := &relayServer{}
	url := rs.start(t)
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(url, "", priv, slog.Default())
	defer e.Close()
	e.Connect()
	if !e.relayConnected() {
		t.Fatal("engine did not connect to the test relay")
	}

	// A real, registered peer: it answers the relay-session handshake. A
	// fabricated key would make the relay answer our handshake with PeerGone (it
	// reports one for a key it does not hold, like derper's ReasonNotHere), which
	// kills the adapter between builds and defeats the churn accounting here.
	privB, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	eB := newEngine(url, "", privB, slog.Default())
	defer eB.Close()
	if err := eB.Connect(); err != nil {
		t.Fatal(err)
	}

	pc := e.peerConn(eB.pub)
	// One build more than the window allows, each preceded by killing the
	// session it would have reused: rebuild after rebuild, as a pair left
	// un-routed looks from here.
	for i := 0; i <= relayChurnMax; i++ {
		if i > 0 {
			// Exactly what sessionLocked leaves behind when it finds the
			// session dead. Closing the live session directly hangs here: smux
			// retires a session by handing its error to the read loop, and that
			// loop is parked in peerConn.Read, which nothing has woken (see the
			// note on retireSession). This test is about the churn accounting,
			// not that path.
			pc.mu.Lock()
			pc.sess = nil
			pc.mu.Unlock()
		}
		if _, err := pc.ensureSession(false, true); err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
	}

	if e.relayConnected() {
		t.Fatal("a churned peer did not take the relay down with it")
	}
	// One-shot: the count is cleared, so a later window can trip again.
	pc.mu.Lock()
	churn, tripped := pc.churn, pc.churnTripped
	pc.mu.Unlock()
	if churn != 0 || tripped {
		t.Fatalf("after the trip: churn=%d tripped=%v, want 0/false", churn, tripped)
	}
}
