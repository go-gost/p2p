package host

// Task 2b (peer liveness): the churn guard's blast radius. The counter is
// per-peer — noteBuildLocked trips when one pair rebuilds its relay session
// more than relayChurnMax times inside relayChurnWindow — but the cure it
// applied had been reconnecting the relay, which tears the ONE shared relay
// client down and with it every peer's session and every pair's KCP session.
//
// The evidence was in production: one phone hanging up left other peers'
// sessions being killed too, and the victims were only visible by grepping
// "peer session killed" for peers that had done nothing.
//
// The contract these tests pin: a churn trip cures the churning pair and
// nothing else. TestRelaySessionChurnSparesOtherPeers is the collateral test;
// TestRelaySessionChurnStillCuresTheChurningPeer keeps the original intent —
// the flapping peer does get a fresh registration.

import (
	"log/slog"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// churnPeer drives one relay session more than the window allows, the way a
// pair left un-routed looks from here: each rebuild preceded by clearing the
// session the next would have reused. Returns the peer conn once tripped.
func churnPeer(t *testing.T, e *engine, pc *peerConn) {
	t.Helper()
	for i := 0; i <= relayChurnMax; i++ {
		if i > 0 {
			pc.mu.Lock()
			pc.sess = nil
			pc.mu.Unlock()
		}
		if _, err := pc.ensureSession(false, true); err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
	}
}

// registeredEngine builds and connects an engine that answers the relay-session
// handshake, so a churned peer's kill cannot be mistaken for PeerGone.
func registeredEngine(t *testing.T, url string) (*engine, derpclient.PublicKey) {
	t.Helper()
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(url, "", priv, slog.Default())
	t.Cleanup(e.Close)
	if err := e.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return e, e.pub
}

// TestRelaySessionChurnSparesOtherPeers: tripping the guard on one peer must
// leave other peers' relay sessions and the shared relay connection alone.
// Before the per-peer cure, the trip called reconnectRelay, which tore the
// relay down engine-wide and killed every peer's session.
func TestRelaySessionChurnSparesOtherPeers(t *testing.T) {
	defer func(w time.Duration, m int) { relayChurnWindow, relayChurnMax = w, m }(relayChurnWindow, relayChurnMax)
	relayChurnWindow, relayChurnMax = time.Minute, 2

	rs := &relayServer{}
	url := rs.start(t)

	e, _ := registeredEngine(t, url)
	// The peer that will churn, and an innocent one whose session must survive.
	_, churnPub := registeredEngine(t, url)
	_, innocentPub := registeredEngine(t, url)

	pcChurn := e.peerConn(churnPub)
	pcInnocent := e.peerConn(innocentPub)

	// The innocent peer has a working session, built once and left alone.
	if _, err := pcInnocent.ensureSession(false, true); err != nil {
		t.Fatalf("innocent build: %v", err)
	}

	pcInnocent.mu.Lock()
	innocentGen := pcInnocent.sessionGen.Load()
	pcInnocent.mu.Unlock()

	churnPeer(t, e, pcChurn)

	// The relay client itself must survive: a peer's churn is not evidence
	// about the shared connection, and reconnecting it is what broke everybody.
	if !e.relayConnected() {
		t.Fatal("a churning peer took the shared relay down with it")
	}

	pcInnocent.mu.Lock()
	sess := pcInnocent.sess
	gen := pcInnocent.sessionGen.Load()
	pcInnocent.mu.Unlock()
	if sess == nil || sess.IsClosed() {
		t.Fatal("an innocent peer's session was killed by another peer's churn trip")
	}
	if gen != innocentGen {
		t.Fatalf("innocent peer's session was rebuilt (gen %d -> %d) by another peer's churn trip",
			innocentGen, gen)
	}
}

// TestRelaySessionChurnStillCuresTheChurningPeer: the trip's original intent,
// kept. The flapping pair gets a fresh registration — its relay keys are
// dropped and its session killed — because the stale registration is what the
// churn is a symptom of. Narrowing the blast radius must not become ignoring
// the peer that actually has the problem.
func TestRelaySessionChurnStillCuresTheChurningPeer(t *testing.T) {
	defer func(w time.Duration, m int) { relayChurnWindow, relayChurnMax = w, m }(relayChurnWindow, relayChurnMax)
	relayChurnWindow, relayChurnMax = time.Minute, 2

	rs := &relayServer{}
	url := rs.start(t)

	e, _ := registeredEngine(t, url)
	_, churnPub := registeredEngine(t, url)

	pc := e.peerConn(churnPub)
	churnPeer(t, e, pc)

	// The cure is the per-peer one: this pair's relay keys are gone (so the
	// next build re-handshakes), and its adapter is closed.
	e.mu.Lock()
	_, secureKept := e.secure[secureKey{peer: churnPub, transport: secureTransportRelay}]
	e.mu.Unlock()
	if secureKept {
		t.Fatal("the churning peer's stale relay registration was not dropped")
	}
	pc.mu.Lock()
	closed := pc.closed
	pc.mu.Unlock()
	if !closed {
		t.Fatal("the churning peer's adapter was not replaced by a churn trip")
	}

	// One-shot: the count is cleared, so a later window can trip again.
	pc2 := e.peerConn(pc.peer)
	pc2.mu.Lock()
	churn, tripped := pc2.churn, pc2.churnTripped
	pc2.mu.Unlock()
	if churn != 0 || tripped {
		t.Fatalf("after the trip: churn=%d tripped=%v, want 0/false", churn, tripped)
	}
}
