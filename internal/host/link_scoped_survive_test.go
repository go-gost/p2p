package host

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// peerSessionGen returns the peer's relay session generation, or 0 when the
// engine holds no session for it. A test-side read: the accessor the link
// itself needs lands with the implementation.
func peerSessionGen(t *testing.T, e *engine, peer derpclient.PublicKey) uint64 {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if pc, ok := e.peers[peer]; ok {
		return pc.sessionGen.Load()
	}
	return 0
}

// newSessionGen installs a peer session at the given generation. The peerConn
// is removed again on cleanup: a bare one is not a live session, and engine.Close
// walks e.peers.
func newSessionGen(t *testing.T, e *engine, peer derpclient.PublicKey, gen uint64) {
	t.Helper()
	e.mu.Lock()
	pc, ok := e.peers[peer]
	if !ok {
		pc = &peerConn{peer: peer}
		e.peers[peer] = pc
		t.Cleanup(func() {
			e.mu.Lock()
			if e.peers[peer] == pc {
				delete(e.peers, peer)
			}
			e.mu.Unlock()
		})
	}
	e.mu.Unlock()
	pc.sessionGen.Store(gen)
}

// scopedEdgeOpener hands out pipe ends as presentation edges, draining the
// channel tag the presenter writes first, and records every one.
func scopedEdgeOpener() (func(string) (net.Conn, error), <-chan net.Conn) {
	sides := make(chan net.Conn, 8)
	open := func(string) (net.Conn, error) {
		edge, side := net.Pipe()
		// The presenter writes the channel tag before handing the stream over
		// (openTaggedStream); on an unbuffered pipe that needs a reader.
		go func() { io.ReadFull(side, make([]byte, len(channelTag))) }()
		sides <- side
		return edge, nil
	}
	return open, sides
}

// A session-scoped ("ip") link whose peer edge dies keeps itself while its local
// carrier is still alive: the carrier did not end, so the tunnel did not end,
// and closing the link would tell it to. This is the 45-minute blackhole
// regression: the link ended on a lost peer edge, the carrier took that as the
// end of its tunnel, and nothing ever re-dialed.
func TestScopedLinkSurvivesPeerEdgeDeathWhileLocalLives(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()

	open, sides := scopedEdgeOpener()
	l := newScopedTestLink(t, e, peerKey, open, true)
	local := attachLocal(t, l)

	first := <-sides
	waitFor(t, 3*time.Second, l.hasEdge)

	first.Close() // the peer edge is lost

	// The link must not end: done stays open.
	select {
	case <-l.done:
		t.Fatal("the link ended while its local carrier was still alive")
	case <-time.After(2 * time.Second):
	}
	// The local carrier must not be closed: the consumer cannot distinguish
	// "your tunnel is over" from "this link died", so it never re-dials.
	local.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := local.Write([]byte("x")); err != nil {
		t.Fatalf("the local carrier was closed with the link: %v", err)
	}
	// And it must not present over the stale session the lost edge rode.
	select {
	case <-sides:
		t.Fatal("the link presented a new edge on a stale peer session")
	default:
	}
}

// The same link recovers on its own once the peer builds a newer relay session:
// the engine bumps sessionGen on every build (sessionLocked), which is the
// embedder-agnostic signal that the state the peer holds for this link is new.
// No consumer input is involved.
func TestScopedLinkRePresentsAfterNewPeerSession(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()

	open, sides := scopedEdgeOpener()
	l := newScopedTestLink(t, e, peerKey, open, true)
	attachLocal(t, l)

	first := <-sides
	waitFor(t, 3*time.Second, l.hasEdge)
	first.Close()

	// The edge rode generation 1. The peer rekeys / restarts: generation 2.
	newSessionGen(t, e, peerKey, 1)
	newSessionGen(t, e, peerKey, 2)

	select {
	case second := <-sides:
		if second == first {
			t.Fatal("the presenter re-published the dead edge")
		}
		if got := peerSessionGen(t, e, peerKey); got != 2 {
			t.Fatalf("peer session generation = %d, want 2", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the link did not re-present after the peer built a new session")
	}
}

// A non-session-scoped link keeps its old behaviour: it re-presents without
// waiting for a generation bump, because it registered nothing per session.
func TestLinkRePresentsWithoutNewPeerSession(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()

	open, sides := scopedEdgeOpener()
	l := newScopedTestLink(t, e, peerKey, open, false)

	first := <-sides
	waitFor(t, 3*time.Second, l.hasEdge)
	first.Close()

	select {
	case second := <-sides:
		if second == first {
			t.Fatal("the presenter re-published the dead edge")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an unscoped link did not re-present after the edge died")
	}
}

// The local carrier still owns the lifetime of the link: its stream ending is
// the dial ending, session-scoped or not. Without this, a repair that only
// stops the edge from ending the link would leak the tunnel forever.
func TestScopedLinkStillEndsWhenLocalCarrierEnds(t *testing.T) {
	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()

	open, sides := scopedEdgeOpener()
	l := newScopedTestLink(t, e, peerKey, open, true)
	local := attachLocal(t, l)

	<-sides
	waitFor(t, 3*time.Second, l.hasEdge)

	local.Close() // the carrier's stream ends: the dial ends

	select {
	case <-l.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the link did not end when its local carrier ended")
	}
}

// A session-scoped ("ip") link whose peer session stays gone past the re-present
// grace ENDS, so the consumer's conn ends and it re-dials — re-registering the
// per-session state the dead edge rode. d58096a instead kept the link alive by
// re-presenting into the stale session, so the consumer's conn never ended and it
// never re-dialed: the 56-minute blackhole, where 23 rebuilt edges all logged
// read=0 written=0 and the consumer wrote into a link nothing carried.
//
// The quick-recovery half — the peer session comes back, so the link re-attaches
// rather than ending — is pinned by TestScopedLinkRePresentsAfterNewPeerSession.
func TestScopedLinkEndsWhenPeerSessionStaysGone(t *testing.T) {
	old := scopedRePresentGrace
	scopedRePresentGrace = 100 * time.Millisecond
	t.Cleanup(func() { scopedRePresentGrace = old })

	e := newTestEngine(t)
	_, peerKey, _ := derpclient.Generate()

	open, sides := scopedEdgeOpener()
	l := newScopedTestLink(t, e, peerKey, open, true)
	local := attachLocal(t, l)

	first := <-sides
	waitFor(t, 3*time.Second, l.hasEdge)

	first.Close() // the peer edge is lost; the peer session never comes back

	select {
	case <-l.done:
	case <-time.After(5 * time.Second):
		t.Fatal("a session-scoped link whose peer session stayed gone never ended: the consumer would write into it forever")
	}
	// The consumer observes the end on its own conn: the link closed the local
	// stream, so a read errors instead of blocking and a write fails instead of
	// silently queueing into the link's buffer.
	local.SetDeadline(time.Now().Add(time.Second))
	if _, err := local.Read(make([]byte, 4)); err == nil {
		t.Fatal("Read on the ended link's local edge returned no error, want the link's end to be observable")
	}
	if _, err := local.Write([]byte("x")); err == nil {
		t.Fatal("Write on the ended link's local edge succeeded, want it closed")
	}
}
