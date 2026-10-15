package host

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// The peer-session event is the embedder-agnostic signal that whatever a
// consumer registered with the peer for this session is now stale. A tun peer's
// addresses are registered with the far tun server per session, so the address
// set has to be re-pushed; the engine's job is only to say "the session
// changed", never to know what was registered.
//
// This closes the gap ① left behind. Keeping the link alive removed the
// consumer's only cue to re-register — the link ending — so a link that now
// survives its session needs a replacement cue. Without it, a fresh session
// carries a stale address set, which is exactly the route the far side cannot
// build: the blackhole comes back on the recovery path instead of the death
// path.

// eventPeer builds an engine with one built relay session and returns the
// engine and its adapter.
func eventPeer(t *testing.T, label string) (*engine, *peerConn) {
	t.Helper()
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(&logCapture{}))
	t.Cleanup(e.Close)

	peer := eventKey(t, label)
	pc := e.peerConn(peer)

	// A relay session needs settled keys, the same way buildRelaySession sets
	// them up: both the engine's cache and the adapter must hold the pair.
	settled, _ := settledSecurePair(t, secureTransportRelay)
	e.mu.Lock()
	e.secure[secureKey{peer: peer, transport: secureTransportRelay}] = settled
	e.mu.Unlock()
	pc.mu.Lock()
	pc.secure = settled
	if _, err := pc.sessionLocked(); err != nil {
		pc.mu.Unlock()
		t.Fatalf("build session: %v", err)
	}
	pc.mu.Unlock()
	return e, pc
}

// eventKey derives a deterministic peer key from a label. A fixed pattern, not
// a real key: these tests drive session-layer building, not crypto.
func eventKey(t *testing.T, label string) derpclient.PublicKey {
	t.Helper()
	var key derpclient.PublicKey
	for i := range key {
		key[i] = byte(label[i%len(label)])
	}
	return key
}

// rebuildSession forces a real rebuild: sessionLocked returns the live session
// untouched when there is one, so a second call without this is a no-op that
// notifies nobody. Closing the old session is what makes the next call build.
func rebuildSession(t *testing.T, pc *peerConn) {
	t.Helper()
	pc.mu.Lock()
	old := pc.sess
	pc.sess = nil
	pc.mu.Unlock()
	if old != nil {
		old.Close()
	}
	pc.mu.Lock()
	if _, err := pc.sessionLocked(); err != nil {
		pc.mu.Unlock()
		t.Fatalf("rebuild session: %v", err)
	}
	pc.mu.Unlock()
}

// TestPeerSessionEventFiresOnBuild: a subscriber is woken when a relay session
// is built for its peer. Without this the consumer cannot re-register on a
// fresh session and stays registered against a session that is gone.
func TestPeerSessionEventFiresOnBuild(t *testing.T) {
	e, pc := eventPeer(t, "peer-ev-build")
	// The subscription lands after this build, so it is for the next one: the
	// event channel is close-and-replaced per build, not a level that latches.
	before := e.peerSessionEvents(pc.peer)

	rebuildSession(t, pc)

	select {
	case <-before:
	case <-time.After(5 * time.Second):
		t.Fatal("a session build did not notify a subscriber")
	}
}

// TestPeerSessionEventFiresOnRebuild: the notification is per build, not per
// peer lifetime. A close-and-remember channel would wake a subscriber exactly
// once and then never again, so a consumer that re-registers on every event
// would stop being told after the first session.
func TestPeerSessionEventFiresOnRebuild(t *testing.T) {
	e, pc := eventPeer(t, "peer-ev-rebuild")

	for i := 0; i < 2; i++ {
		// A fresh subscription per iteration: each build must wake the one taken
		// for it, which is what a consumer does when it re-registers in a loop.
		sub := e.peerSessionEvents(pc.peer)
		rebuildSession(t, pc)
		select {
		case <-sub:
		case <-time.After(5 * time.Second):
			t.Fatalf("build %d did not notify a subscriber taken for it", i)
		}
	}
}

// TestPeerSessionEventNotifiesLateSubscriber: a subscription taken after builds
// still sees the next one. The channel is handed out per build rather than
// consumed, or a consumer that subscribes on its first dial only ever hears
// about the first session.
func TestPeerSessionEventNotifiesLateSubscriber(t *testing.T) {
	e, pc := eventPeer(t, "peer-ev-late")

	late := e.peerSessionEvents(pc.peer)
	rebuildSession(t, pc)

	select {
	case <-late:
	case <-time.After(5 * time.Second):
		t.Fatal("a late subscriber was not notified of the next build")
	}
}

// TestPeerSessionEventSurvivesAdapterSwap: the subscription must survive the
// peerConn being replaced, which is what a peer rekey does (peerConn builds a
// fresh adapter and carries state across). An event channel parked on the
// adapter would be dropped with it, and a consumer subscribed before the rekey
// would never hear about the session that replaces it.
func TestPeerSessionEventSurvivesAdapterSwap(t *testing.T) {
	e, pc := eventPeer(t, "peer-ev-swap")

	sub := e.peerSessionEvents(pc.peer)

	// A rekey kills the adapter and the next peerConn lookup replaces it with a
	// fresh one for the same peer (peerConn drops the dead adapter and carries
	// the counters across). That is the adapter swap a consumer's subscription
	// must outlive.
	pc.killSession(errors.New("test: rekeyed"), false, reasonPeerRekeyed)
	fresh := e.peerConn(pc.peer)
	rebuildSession(t, fresh)

	select {
	case <-sub:
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription did not survive the adapter being replaced")
	}
}
