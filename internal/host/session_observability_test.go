package host

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestRebuildStormWindow pins the rebuild-storm rate window: a peer that
// rebuilds its relay session more than rebuildStormThreshold times within
// rebuildStormWindow is flagged exactly once per window, with the count and the
// oldest-first sequence of end reasons. The clock is injected so the window is
// driven deterministically, with no sleeps and no wall-clock dependence.
func TestRebuildStormWindow(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	storm := &rebuildStorm{now: func() time.Time { return now }}

	// Fewer than the threshold within the window: no WARN, and no state that
	// would suppress a later legitimate WARN (the 4th still fires below).
	for _, r := range []sessionEndReason{"a", "b", "c"} {
		count, _, warn := storm.note(r)
		if warn {
			t.Fatalf("rebuild %q warned with only %d rebuilds in the window", r, count)
		}
		now = now.Add(time.Second)
	}

	// The 4th rebuild within 30s trips it once, carrying the count and all four
	// reasons, oldest first.
	count, reasons, warn := storm.note("d")
	if !warn {
		t.Fatal("the 4th rebuild within the window did not warn")
	}
	if count != 4 {
		t.Fatalf("count = %d, want 4", count)
	}
	want := []sessionEndReason{"a", "b", "c", "d"}
	if len(reasons) != len(want) {
		t.Fatalf("reasons = %v, want %v", reasons, want)
	}
	for i := range want {
		if reasons[i] != want[i] {
			t.Fatalf("reasons[%d] = %q, want %q (got %v)", i, reasons[i], want[i], reasons)
		}
	}

	// A 5th rebuild inside the same window must not warn again.
	now = now.Add(time.Second)
	if _, _, warn := storm.note("e"); warn {
		t.Fatal("the 5th rebuild inside the same window warned again")
	}

	// After the window expires, a fresh burst is allowed to warn again.
	now = now.Add(rebuildStormWindow + time.Second)
	for _, r := range []sessionEndReason{"f", "g", "h"} {
		if _, _, warn := storm.note(r); warn {
			t.Fatalf("rebuild %q warned before the new window reached the threshold", r)
		}
		now = now.Add(time.Second)
	}
	count, reasons, warn = storm.note("i")
	if !warn {
		t.Fatal("a rebuild after the window expired did not warn again")
	}
	if count != 4 {
		t.Fatalf("second burst count = %d, want 4", count)
	}
	want = []sessionEndReason{"f", "g", "h", "i"}
	if len(reasons) != len(want) {
		t.Fatalf("second burst reasons = %v, want %v", reasons, want)
	}
	for i := range want {
		if reasons[i] != want[i] {
			t.Fatalf("second burst reasons[%d] = %q, want %q (got %v)", i, reasons[i], want[i], reasons)
		}
	}
}

// TestRebuildStormWarnOncePerWindow pins the emission half: recordRebuild — the
// rebuild path's only storm hook — emits exactly one WARN the first time the
// window's threshold is crossed, and none on the rebuilds that follow inside the
// same window. It asserts on the structured fields (count), not on formatted
// text.
func TestRebuildStormWarnOncePerWindow(t *testing.T) {
	capture := &logCapture{}
	e := &engine{log: slog.New(capture)}
	peer := derpclient.PublicKey{42}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	pc := &peerConn{e: e, peer: peer, storm: rebuildStorm{now: func() time.Time { return now }}}

	for _, r := range []sessionEndReason{
		reasonPeerRekeyed, reasonSecureDesync, reasonLinkLost, reasonQueueOverflow,
	} {
		pc.recordRebuild(r)
		now = now.Add(time.Second)
	}

	if got := capture.count("derp: peer relay rebuild storm"); got != 1 {
		t.Fatalf("storm WARNs = %d, want exactly 1", got)
	}
	attrs := capture.nth("derp: peer relay rebuild storm", 0)
	if attrs == nil {
		t.Fatal("the storm WARN was not captured")
	}
	if got := attrs["count"]; got != "4" {
		t.Fatalf("storm WARN count = %q, want 4", got)
	}
	if attrs["window"] == "" {
		t.Fatal("the storm WARN carries no window")
	}

	// A 5th rebuild inside the same window must not add a second WARN.
	now = now.Add(time.Second)
	pc.recordRebuild(reasonPeerRekeyed)
	if got := capture.count("derp: peer relay rebuild storm"); got != 1 {
		t.Fatalf("storm WARNs after the 5th rebuild = %d, want still 1", got)
	}
}

// TestSessionGenerationMonotonicAndDistinct pins the session-generation
// identifier: every built relay session gets a process-unique, strictly
// increasing generation, so two peers never collide and a rebuild advances it.
// It asserts on the field values (pc.sessionGen), not on log text.
func TestSessionGenerationMonotonicAndDistinct(t *testing.T) {
	e := &engine{
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		stop:    make(chan struct{}),
		directs: make(map[derpclient.PublicKey]*directConn),
		peers:   make(map[derpclient.PublicKey]*peerConn),
		secure:  make(map[secureKey]*secureSession),
	}
	build := func(peer derpclient.PublicKey) *peerConn {
		t.Helper()
		settled, _ := settledSecurePair(t, secureTransportRelay)
		pc := &peerConn{
			e:       e,
			peer:    peer,
			inbound: make(chan []byte, inboundQueueSize),
			closeCh: make(chan struct{}),
			secure:  settled,
		}
		e.mu.Lock()
		e.peers[peer] = pc
		e.mu.Unlock()
		pc.mu.Lock()
		_, err := pc.sessionLocked()
		pc.mu.Unlock()
		if err != nil {
			t.Fatalf("build session: %v", err)
		}
		return pc
	}

	peerA := derpclient.PublicKey{1}
	pcA := build(peerA)
	genA := pcA.sessionGen.Load()
	if genA == 0 {
		t.Fatal("a built session got generation 0")
	}

	peerB := derpclient.PublicKey{2}
	pcB := build(peerB)
	genB := pcB.sessionGen.Load()
	if genB == 0 {
		t.Fatal("the second built session got generation 0")
	}
	if genA == genB {
		t.Fatalf("two peers share generation %d", genA)
	}
	if genB <= genA {
		t.Fatalf("generations not monotonic across peers: genB=%d <= genA=%d", genB, genA)
	}

	// A rebuild on the same peer advances its generation.
	pcA.mu.Lock()
	pcA.sess.Close()
	pcA.mu.Unlock()
	pcA.mu.Lock()
	_, err := pcA.sessionLocked()
	pcA.mu.Unlock()
	if err != nil {
		t.Fatalf("rebuild session: %v", err)
	}
	if gen := pcA.sessionGen.Load(); gen <= genA {
		t.Fatalf("rebuild generation not greater: gen=%d after %d", gen, genA)
	}
}

// TestSessionGenerationOnRebuildLog pins that the generation appears on the
// rebuild log line, carried as a structured field. A killed adapter's
// replacement logs "relay session rebuilt" with the generation of the session
// being replaced, so a grep for `gen=` ties the kill, the desync and the KCP
// reset on that session to its rebuild.
func TestSessionGenerationOnRebuildLog(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{7}
	// A settled security session, or sessionLocked refuses to build (see
	// settledSecurePair).
	settled, _ := settledSecurePair(t, secureTransportRelay)
	pc1 := e.peerConn(peer)
	pc1.mu.Lock()
	pc1.secure = settled
	pc1.mu.Unlock()
	pc1.mu.Lock()
	if _, err := pc1.sessionLocked(); err != nil {
		pc1.mu.Unlock()
		t.Fatalf("build session: %v", err)
	}
	gen := pc1.sessionGen.Load()
	pc1.mu.Unlock()
	if gen == 0 {
		t.Fatal("a built session got generation 0")
	}

	pc1.killSession(errors.New("test: clean kill"), true, reasonLocalKill)
	pc2 := e.peerConn(peer)
	if pc2 == pc1 {
		t.Fatal("the killed adapter was handed back instead of a replacement")
	}

	attrs := capture.nth("relay session rebuilt", 0)
	if attrs == nil {
		t.Fatal("replacing a killed adapter logged no \"relay session rebuilt\" record")
	}
	if got := attrs["gen"]; got != fmt.Sprint(gen) {
		t.Fatalf("rebuild log gen = %q, want %d (the replaced session's generation)", got, gen)
	}
}
