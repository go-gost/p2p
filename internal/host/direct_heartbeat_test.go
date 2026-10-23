package host

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestDirectHeartbeatKeepsIdlePath is the sticky-direct regression: an
// installed direct path that answers heartbeats must survive KCP silence past
// directUnderlayIdle — silence alone is not death. Before heartbeats, every
// idle peer flapped direct↔relay every ~6.6s (probe-pod/vscode-docker live,
// 2026-10-14): seed ok, then retire reason=idle, re-punch, repeat.
func TestDirectHeartbeatKeepsIdlePath(t *testing.T) {
	oldIdle := directUnderlayIdle.Load()
	oldHb := directHeartbeatInterval.Load()
	// Both stay above the pump's 1s silence-tick granularity
	// (directUnderlayReadTimeout is a const): shrinking idle below one tick
	// would judge before any heartbeat round trip can complete.
	directUnderlayIdle.Store(int64(2500 * time.Millisecond))
	directHeartbeatInterval.Store(int64(200 * time.Millisecond))
	defer func() {
		directUnderlayIdle.Store(oldIdle)
		directHeartbeatInterval.Store(oldHb)
	}()

	e := newTestEngine(t)
	peer := derpclient.PublicKey{12}
	pair := e.relayKCPPairFor(peer)
	defer pair.shutdown()

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer a.Close()
	defer b.Close()

	var tokA, tokB [seedTokenLen]byte
	tokA[0], tokB[0] = 0xA1, 0xB2
	uA := newDirectUnderlayToken(a, udpAddrPort(t, b), tokA)
	uB := newDirectUnderlayToken(b, udpAddrPort(t, a), tokB)

	// The far end echoes heartbeats the way a live peer does: its readFrom
	// answers our heartbeat token (it matches neither its seed token nor its
	// own heartbeat token) and never delivers it upward.
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, 2048)
		for {
			if _, err := uB.readFrom(buf); err != nil {
				return
			}
		}
	}()
	defer func() {
		uB.close()
		<-echoDone
	}()

	pair.setDirectUnderlay(uA)

	var fires atomic.Int64
	pair.mu.Lock()
	pair.onDirectIdle = func(u *directUnderlay) { fires.Add(1) }
	pair.mu.Unlock()

	// Stay silent past one full idle window with no KCP traffic at all. The
	// pump's heartbeats must prove the path within the window and the
	// watchdog must never fire. (Old code fires at the first window.)
	time.Sleep(3500 * time.Millisecond)
	if got := fires.Load(); got != 0 {
		t.Fatalf("onDirectIdle fired %d times on a heartbeat-live path, want 0", got)
	}
	pair.mu.Lock()
	held, preferred := pair.direct == uA, pair.preferredDirectLocked()
	pair.mu.Unlock()
	if !held {
		t.Fatal("pair dropped a heartbeat-live direct underlay while silent")
	}
	if !preferred {
		t.Fatal("pair stopped preferring a heartbeat-live direct underlay while silent")
	}
}

// TestDirectHeartbeatDeadPathRetires pins the other half of the contract: a
// path whose heartbeats go unanswered must still retire exactly as before.
// Here the far end is gone (its socket closed), so no echo ever comes back;
// the idle watchdog must fire once past the window. Heartbeats add a proof
// step, not an exemption from death.
func TestDirectHeartbeatDeadPathRetires(t *testing.T) {
	oldIdle := directUnderlayIdle.Load()
	oldHb := directHeartbeatInterval.Load()
	directUnderlayIdle.Store(int64(2500 * time.Millisecond))
	directHeartbeatInterval.Store(int64(200 * time.Millisecond))
	defer func() {
		directUnderlayIdle.Store(oldIdle)
		directHeartbeatInterval.Store(oldHb)
	}()

	e := newTestEngine(t)
	peer := derpclient.PublicKey{13}
	pair := e.relayKCPPairFor(peer)
	defer pair.shutdown()

	a := mustListenUDP(t)
	defer a.Close()
	b := mustListenUDP(t)
	// The far end dies before the test starts: close its socket so nothing
	// answers seeds, heartbeats, or data.
	peerAddr := udpAddrPort(t, b)
	b.Close()

	var tokA [seedTokenLen]byte
	tokA[0] = 0xA1
	pair.setDirectUnderlay(newDirectUnderlayToken(a, peerAddr, tokA))

	fired := make(chan struct{}, 1)
	pair.mu.Lock()
	pair.onDirectIdle = func(u *directUnderlay) { fired <- struct{}{} }
	pair.mu.Unlock()

	select {
	case <-fired:
	case <-time.After(8 * time.Second):
		t.Fatal("onDirectIdle never fired for a path whose heartbeats go unanswered")
	}
}
