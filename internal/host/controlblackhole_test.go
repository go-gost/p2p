package host

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// The control-blackhole tripwire (noteControlMiss / healControlBlackhole) and
// the backoff kick: the field case is a phone's Wi-Fi ↔ cellular switch behind
// a stale relay registration — the punch control plane hears nothing for
// minutes while its backoff doubles, and a reconnect that finally clears the
// registration then sits out the stale backoff. These tests pin the three
// halves: the trip fires on control silence with a live relay session, a dead
// peer never trips it, and the reconnect re-punches at once.

// controlMissesOf reads the tripwire count out from under the punch.
func controlMissesOf(dc *directConn) (misses int, liveSeen bool) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.controlMisses, dc.controlLiveSeen
}

func lastControlHealOf(e *engine) time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastControlHeal
}

func relayClientOf(e *engine) *derpclient.Client {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.client
}

// TestControlBlackholeHealsWedgedRegistration replays the field case: both
// ends hold a live relay session, then the relay stops delivering candidate
// frames while the data path keeps answering. The punch control plane hears
// nothing round after round; the tripwire must reconnect the relay (the same
// cure the pong watchdog applies, but tripped by control-plane evidence), and
// once control flows again the direct path must come up — the minutes-long
// outage becoming seconds.
func TestControlBlackholeHealsWedgedRegistration(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	// Relay-only at first, so the relay session settles before any punch runs.
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

	clientA := relayClientOf(engineA)
	if clientA == nil {
		t.Fatal("A has no relay connection")
	}

	// The registration goes stale for control only: candidate frames are
	// dropped in both directions (one direction would let loopback UDP probes
	// reach a socket the other side never opened, muddying the experiment),
	// while the handshake, caps and data planes keep answering.
	rs.mu.Lock()
	rs.dropCtrl = func(_ [32]byte, payload []byte) bool {
		return len(payload) > 1 && payload[1] == ctrlPunchCandidates
	}
	rs.mu.Unlock()

	engineA.stunAddr, engineB.stunAddr = stun, stun
	engineA.maybeStartDirect(pubB)
	engineB.maybeStartDirect(engineA.pub)

	// Each round burns punchTimeout waiting for candidates that never arrive;
	// the trip must fire after controlBlackholeThreshold of them.
	waitFor(t, 25*time.Second, func() bool {
		return !lastControlHealOf(engineA).IsZero()
	})

	// The trip tears the wedged transport down: the relay connection cycles.
	waitFor(t, 10*time.Second, func() bool {
		return relayClientOf(engineA) != clientA
	})

	// Control heals: candidates flow again, and the direct path must come up
	// on the fresh registration instead of after minutes of doubling backoff.
	rs.mu.Lock()
	rs.dropCtrl = nil
	rs.mu.Unlock()
	waitFor(t, 25*time.Second, func() bool {
		return hasDirect(engineA, pubB) && hasDirect(engineB, engineA.pub)
	})
}

// TestControlBlackholeIgnoresDeadPeer pins the tripwire's discriminator: a
// peer with no relay session at all — a killed phone, not a wedged
// registration — must never trip a relay reconnect, however many rounds fail.
func TestControlBlackholeIgnoresDeadPeer(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")

	privA, _, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	defer engineA.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	engineA.stunAddr = stun

	// Nobody holds this key: the relay answers with PeerGone and no session
	// is ever built, so every round fails with no evidence behind it.
	var peer derpclient.PublicKey
	peer[0] = 0xDB
	engineA.maybeStartDirect(peer)
	dc := engineA.getDirect(peer)
	if dc == nil {
		t.Fatal("no punch state for the peer")
	}

	waitFor(t, 25*time.Second, func() bool {
		a, _, _ := dc.punchCounters()
		return a >= 3
	})
	if misses, _ := controlMissesOf(dc); misses != 0 {
		t.Fatalf("controlMisses = %d for a peer with no relay session, want 0", misses)
	}
	if heal := lastControlHealOf(engineA); !heal.IsZero() {
		t.Fatalf("a dead peer tripped a relay reconnect at %v", heal)
	}
}

// TestControlMissGating drives the tripwire's counting rules synchronously:
// what counts, what resets, and the one thing that fires. The firing itself
// runs through reconnectRelay, which needs a real transport, so the top of
// the count (the exact threshold) is covered by
// TestControlBlackholeHealsWedgedRegistration; here every case stops short of
// tearing anything down.
func TestControlMissGating(t *testing.T) {
	newLiveConn := func(t *testing.T) *directConn {
		t.Helper()
		dc := newSlotConn(t)
		dc.e.client = &derpclient.Client{} // relay up
		dc.e.peers[dc.peer] = &peerConn{peer: dc.peer, sess: newTestSess(t)}
		return dc
	}

	t.Run("counts with live evidence, short of the trip", func(t *testing.T) {
		dc := newLiveConn(t)
		if live, fresh := dc.e.relaySessionEvidence(dc.peer); !live || !fresh {
			t.Fatalf("evidence = (%v, %v) for a live session, want (true, true)", live, fresh)
		}
		for i := 0; i < controlBlackholeThreshold-1; i++ {
			dc.noteControlMiss(true, true)
		}
		if misses, liveSeen := controlMissesOf(dc); misses != controlBlackholeThreshold-1 || !liveSeen {
			t.Fatalf("misses = %d liveSeen = %v, want %d/true",
				misses, liveSeen, controlBlackholeThreshold-1)
		}
		if heal := lastControlHealOf(dc.e); !heal.IsZero() {
			t.Fatalf("tripped below the threshold at %v", heal)
		}
	})

	t.Run("fresh but never live never fires", func(t *testing.T) {
		dc := newSlotConn(t)
		dc.e.client = &derpclient.Client{}
		// A session built recently, then dead: exactly what a killed phone
		// leaves behind (killSession preserves sessAt).
		dc.e.peers[dc.peer] = &peerConn{peer: dc.peer, sessAt: time.Now()}
		if live, fresh := dc.e.relaySessionEvidence(dc.peer); live || !fresh {
			t.Fatalf("evidence = (%v, %v) for a recently dead session, want (false, true)", live, fresh)
		}
		for i := 0; i < controlBlackholeThreshold+2; i++ {
			dc.noteControlMiss(false, true)
		}
		// Counted — the misses are real — but the reconnect never comes:
		// without one live sighting the peer may simply be gone.
		if misses, liveSeen := controlMissesOf(dc); misses != controlBlackholeThreshold+2 || liveSeen {
			t.Fatalf("misses = %d liveSeen = %v, want %d/false",
				misses, liveSeen, controlBlackholeThreshold+2)
		}
		if heal := lastControlHealOf(dc.e); !heal.IsZero() {
			t.Fatalf("a never-live peer tripped a relay reconnect at %v", heal)
		}
	})

	t.Run("stale evidence resets", func(t *testing.T) {
		dc := newLiveConn(t)
		dc.noteControlMiss(true, true)
		dc.noteControlMiss(true, true)
		if live, fresh := dc.e.relaySessionEvidence(dc.peer); !live || !fresh {
			t.Fatalf("evidence = (%v, %v) for a live session, want (true, true)", live, fresh)
		}
		// The session died long ago: the old misses describe a peer that is
		// gone, not a registration that is wedged.
		dc.e.peers[dc.peer] = &peerConn{peer: dc.peer, sessAt: time.Now().Add(-2 * controlBlackholeGrace)}
		if live, fresh := dc.e.relaySessionEvidence(dc.peer); live || fresh {
			t.Fatalf("evidence = (%v, %v) for a long-dead session, want (false, false)", live, fresh)
		}
		dc.noteControlMiss(false, false)
		if misses, _ := controlMissesOf(dc); misses != 0 {
			t.Fatalf("misses = %d after the evidence went stale, want 0", misses)
		}
	})

	t.Run("relay down resets", func(t *testing.T) {
		dc := newSlotConn(t) // no client: the relay is down
		dc.noteControlMiss(true, true)
		if misses, _ := controlMissesOf(dc); misses != 0 {
			t.Fatalf("misses = %d with the relay down, want 0", misses)
		}
	})

	t.Run("direct-off peer resets", func(t *testing.T) {
		dc := newLiveConn(t)
		dc.mu.Lock()
		dc.peerCaps |= capsNoDirect
		dc.mu.Unlock()
		// The peer said it will not punch: unanswered rounds are by design,
		// and must never trip a relay reconnect.
		dc.noteControlMiss(true, true)
		if misses, _ := controlMissesOf(dc); misses != 0 {
			t.Fatalf("misses = %d for a direct-off peer, want 0", misses)
		}
	})

	t.Run("candidates reset", func(t *testing.T) {
		dc := newLiveConn(t)
		dc.noteControlMiss(true, true)
		dc.noteControlMiss(true, true)
		// A list this round has not seen: the channel works, so the counted
		// misses describe a channel that no longer exists.
		dc.onCandidates([]candidate{{addr: netip.MustParseAddrPort("203.0.113.7:2222")}})
		if misses, liveSeen := controlMissesOf(dc); misses != 0 || liveSeen {
			t.Fatalf("misses = %d liveSeen = %v after candidates arrived, want 0/false",
				misses, liveSeen)
		}
	})
}

// TestKickRestartsBackedOffPunch pins the reconnect half: a backoff armed on
// a dead registration was earned on a channel that no longer exists, so the
// kick a relay reconnect delivers must start a round at once instead of
// sitting out the remainder behind a stale timer — while the silent-peer
// doubling is kept, so a dead peer stays a slow re-probe.
func TestKickRestartsBackedOffPunch(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	privA, _, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer engineA.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	// STUN never answers: every round burns the lookup timeout and backs off.
	// (TEST-NET-1: unroutable, so nothing can answer.)
	engineA.stunAddr = "192.0.2.1:9"

	// Nobody holds this key, so the peer can never answer and the backoff
	// grows geometrically toward the cap — the stale timer the kick must cut.
	var peer derpclient.PublicKey
	peer[0] = 0xDB
	engineA.maybeStartDirect(peer)
	dc := engineA.getDirect(peer)
	if dc == nil {
		t.Fatal("no punch state for the peer")
	}
	waitFor(t, 25*time.Second, func() bool {
		a, _, _ := dc.punchCounters()
		return a >= 2 && dc.nextPunchIn() > 1500*time.Millisecond
	})
	before, _, _ := dc.punchCounters()
	if d := dc.nextPunchIn(); d <= 1500*time.Millisecond {
		t.Fatalf("next punch in %v, want the stale timer armed well out", d)
	}

	dc.kick()

	// A round starts at once, not when the stale timer would have fired.
	waitFor(t, 2*time.Second, func() bool {
		a, _, _ := dc.punchCounters()
		return a > before
	})
	if got := dc.stateOf(); got != directAttempting {
		t.Fatalf("state = %v right after the kick, want a round in flight", got)
	}

	// The kick's round fails the same way, and the doubling resumes where it
	// was — the kick cut the wait short without forgiving the silence.
	waitFor(t, 10*time.Second, func() bool {
		return lastBackoffWait(t, dc) >= 2*time.Second
	})
	if heal := lastControlHealOf(engineA); !heal.IsZero() {
		t.Fatalf("a peer with no relay session tripped a relay reconnect at %v", heal)
	}
}
