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
	if got := attrs["reasons"]; got != "[peer-rekeyed secure-desync link-lost queue-overflow]" {
		t.Fatalf("storm WARN reasons = %q, want the four reasons in order", got)
	}

	// A 5th rebuild inside the same window must not add a second WARN.
	now = now.Add(time.Second)
	pc.recordRebuild(reasonPeerRekeyed)
	if got := capture.count("derp: peer relay rebuild storm"); got != 1 {
		t.Fatalf("storm WARNs after the 5th rebuild = %d, want still 1", got)
	}
}

// TestRebuildStormFiresAcrossAdapterSwaps pins that the storm accumulates over
// kill-driven rebuilds. Every killSession closes the adapter, so the next build
// goes through peerConn — a fresh peerConn — which must carry the storm state
// over (like the rebuild counters), or the ring restarts at one event per swap
// and the WARN never fires. Four kill -> fresh-adapter -> rebuild cycles inside
// the window must produce exactly one WARN with count=4.
func TestRebuildStormFiresAcrossAdapterSwaps(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{9}
	// A settled security session installed as the engine's cached relay session,
	// so every adapter — original and replacement — builds over settled keys and
	// a clean kill keeps them across the swap.
	settled, _ := settledSecurePair(t, secureTransportRelay)
	e.mu.Lock()
	e.secure[secureKey{peer: peer, transport: secureTransportRelay}] = settled
	e.mu.Unlock()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base

	pc := e.peerConn(peer)
	// The storm's clock is carried across the swap too (see peerConn), so
	// setting it once on the first adapter drives every replacement.
	pc.storm.now = func() time.Time { return now }

	build := func() {
		pc.mu.Lock()
		if _, err := pc.sessionLocked(); err != nil {
			pc.mu.Unlock()
			t.Fatalf("build: %v", err)
		}
		pc.mu.Unlock()
		now = now.Add(time.Second)
	}

	// The first build is not a rebuild, so it records no storm event.
	build()

	// Four kill-driven rebuilds, each through a fresh adapter. The reason value
	// is incidental (any clean kill exercises the same swap); it is the
	// kill -> fresh-peerConn -> rebuild path under test.
	for i := 0; i < 4; i++ {
		pc.killSession(errors.New("test: kill"), true, reasonLocalKill)
		pc = e.peerConn(peer)
		build()
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
	if got := attrs["reasons"]; got != "[local-kill local-kill local-kill local-kill]" {
		t.Fatalf("storm WARN reasons = %q, want four local-kill entries in order", got)
	}
}

// TestKillRecordsItsDeathBeforeTheAdapterReadsAsDead pins the ordering inside
// killSession that the peer-down line depends on: the death must be recorded in
// the same pc.mu block that publishes pc.closed, because pc.closed is what a
// concurrent rebuild reads to decide the adapter is dead. Date the death after
// that unlock and a rebuild landing in the gap consumes an unset death — it
// emits a line carrying no downFor, and the stamp lands on an adapter already
// out of e.peers, so nothing ever reports it.
//
// The gap is made deterministic rather than raced for: relayKCPFreshness takes
// e.kcpMu, so holding that lock freezes the kill at its pair read.
func TestKillRecordsItsDeathBeforeTheAdapterReadsAsDead(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{37}
	settled, _ := settledSecurePair(t, secureTransportRelay)
	pc := e.peerConn(peer)
	pc.mu.Lock()
	pc.secure = settled
	if _, err := pc.sessionLocked(); err != nil {
		pc.mu.Unlock()
		t.Fatalf("build session: %v", err)
	}
	pc.mu.Unlock()

	// Park the kill on its pair read. reasonLocalKill is a clean kill, so this is
	// the only e.kcpMu it waits on and holding the lock freezes it in place.
	e.kcpMu.Lock()

	done := make(chan struct{})
	go func() {
		pc.killSession(errors.New("test: clean kill"), true, reasonLocalKill)
		close(done)
	}()
	// Let the kill get as far as it can. It cannot pass its pair read while this
	// lock is held, so whatever it has published by now is all a rebuild arriving
	// now could ever see — and it must not have published "dead" without the
	// death to go with it.
	time.Sleep(200 * time.Millisecond)
	pc.mu.Lock()
	closed := pc.closed
	pc.mu.Unlock()
	if closed {
		e.kcpMu.Unlock()
		<-done
		t.Fatal("the adapter reads as dead before its death is recorded: a rebuild landing here emits no downFor, and the stamp is orphaned")
	}

	e.kcpMu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the kill did not finish after the pair lock was released")
	}

	e.peerConn(peer)
	attrs := capture.nth("relay session rebuilt", 0)
	if attrs == nil {
		t.Fatal("a kill-driven rebuild logged no \"relay session rebuilt\" record")
	}
	if attrs["downFor"] == "" {
		t.Fatal("the rebuild line carries no downFor: the kill published the adapter dead before it recorded the death")
	}
	if attrs["silentFor"] == "" {
		t.Fatal("the rebuild line carries no silentFor")
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
	// This engine is hand-rolled (no Close), so its pairs outlive the test
	// unless shut down here: each pair's idle watchdog ticks for the suite's
	// lifetime otherwise, reading the window vars across later tests.
	t.Cleanup(func() {
		for _, peer := range []derpclient.PublicKey{{1}, {2}} {
			if pair := e.relayKCPPairGet(peer); pair != nil {
				pair.shutdown()
			}
		}
	})

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

// TestSessionRebuildLogCarriesReasonAndDownDurations pins how the rebuild log
// answers the question a reader of "peer session killed" actually has: what
// killed this peer, how long it had been down by the time the rebuild ran, and
// how long it had already been silent when it died.
//
// The two paths are pinned separately because they are different code, and
// reading either through the other asserts on a line the other never emits: a
// kill-driven rebuild goes through peerConn (killSession closed the adapter), a
// self-died one through ensureSession's replacement branch.
func TestSessionRebuildLogCarriesReasonAndDownDurations(t *testing.T) {
	// A pair whose last underlay datagram is backdated, so silentFor has a real
	// recency to measure from instead of "heard from microseconds ago".
	const quiet = 2 * time.Second

	t.Run("kill-driven rebuild names the reason", func(t *testing.T) {
		capture := &logCapture{}
		priv, _, err := derpclient.Generate()
		if err != nil {
			t.Fatal(err)
		}
		e := newEngine("", "", priv, slog.New(capture))
		t.Cleanup(e.Close)

		peer := derpclient.PublicKey{31}
		pair := e.relayKCPPairFor(peer)
		t.Cleanup(pair.shutdown)
		setPairRelayRecency(pair, time.Now().Add(-quiet))

		settled, _ := settledSecurePair(t, secureTransportRelay)
		pc := e.peerConn(peer)
		pc.mu.Lock()
		pc.secure = settled
		_, err = pc.sessionLocked()
		pc.mu.Unlock()
		if err != nil {
			t.Fatalf("build session: %v", err)
		}

		pc.killSession(errors.New("test: clean kill"), true, reasonLocalKill)
		if got := e.peerConn(peer); got == pc {
			t.Fatal("the killed adapter was handed back instead of a replacement")
		}

		attrs := capture.nth("relay session rebuilt", 0)
		if attrs == nil {
			t.Fatal("a kill-driven rebuild logged no \"relay session rebuilt\" record")
		}
		if got, ok := attrs["relayReason"]; !ok || got != string(reasonLocalKill) {
			t.Fatalf("relayReason = %q (present=%v), want %q", got, ok, reasonLocalKill)
		}
		if attrs["downFor"] == "" {
			t.Fatal("the rebuild log carries no downFor: how long the peer was down is the line's reason to exist")
		}
		got := attrs["silentFor"]
		if got == "" {
			t.Fatal("the rebuild log carries no silentFor: how long the peer was already quiet is the part that tells a stall from a kill")
		}
		d, err := time.ParseDuration(got)
		if err != nil {
			t.Fatalf("silentFor = %q, not a duration: %v", got, err)
		}
		if d < quiet || d > quiet+2*time.Second {
			t.Fatalf("silentFor = %v, want about %v (the pair's last underlay datagram)", d, quiet)
		}
	})

	t.Run("self-died rebuild has no reason but still has durations", func(t *testing.T) {
		capture := &logCapture{}
		priv, _, err := derpclient.Generate()
		if err != nil {
			t.Fatal(err)
		}
		e := newEngine("", "", priv, slog.New(capture))
		t.Cleanup(e.Close)

		peer := derpclient.PublicKey{32}
		settled, _ := settledSecurePair(t, secureTransportRelay)
		pc := e.peerConn(peer)
		pc.mu.Lock()
		pc.secure = settled
		pc.mu.Unlock()
		// A dead session standing in for one the smux keepalive timeout expired
		// in place: closed, with the adapter still live — the state the
		// replacement branch sees, and the one that leaves no kill behind it.
		dead := newTestSess(t)
		if err := dead.Close(); err != nil {
			t.Fatal(err)
		}
		pc.mu.Lock()
		pc.sess, pc.sessAt = dead, time.Now()
		pc.mu.Unlock()

		if _, err := pc.ensureSession(false, true); err != nil {
			t.Fatalf("replace the dead session: %v", err)
		}

		attrs := capture.nth("relay session rebuilt", 0)
		if attrs == nil {
			t.Fatal("replacing a self-died session logged no \"relay session rebuilt\" record")
		}
		if got, ok := attrs["relayReason"]; !ok || got != "" {
			t.Fatalf("relayReason = %q (present=%v), want \"\": nothing killed this session, so there is no reason to name", got, ok)
		}
		if attrs["downFor"] == "" {
			t.Fatal("a self-died rebuild carries no downFor: the no-kill path is the one that most needs it, having no kill line to read a time off")
		}
		if attrs["silentFor"] == "" {
			t.Fatal("a self-died rebuild carries no silentFor")
		}
	})
}

// TestRelayDownAttrsWithoutAnObservedDeath pins the zero rule shared by both
// rebuild paths: with no observed death there is a reason to report but no
// durations. A duration measured from an unset time is the 1970 bug this
// codebase already hit once on sessionAge (see killSession), and it would read
// as an outage that started in year 1 and never ends.
func TestRelayDownAttrsWithoutAnObservedDeath(t *testing.T) {
	pairs := relayDownAttrs(reasonLocalKill, time.Time{}, 0, time.Now())
	attrs := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		attrs[fmt.Sprint(pairs[i])] = fmt.Sprint(pairs[i+1])
	}
	if got := attrs["relayReason"]; got != string(reasonLocalKill) {
		t.Fatalf("relayReason = %q, want %q — the reason does not depend on a death being timed", got, reasonLocalKill)
	}
	for _, name := range []string{"downFor", "silentFor"} {
		if _, ok := attrs[name]; ok {
			t.Fatalf("%s reported for an adapter with no observed death", name)
		}
	}
}

// TestChurnSurvivesAdapterSwap pins the pair scope of the churn window: two
// kills of the same peer with one adapter swap between them must count as two
// builds in one window, not two fresh windows of one. The swap carries the
// rebuild counters, the storm and the reason across (see peerConn); the churn
// window is the same class of pair state, and without it the A path (repeated
// active kills, one swap each) restarts at zero every time and the churn guard
// can never trip there.
func TestChurnSurvivesAdapterSwap(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{38}
	settled, _ := settledSecurePair(t, secureTransportRelay)
	build := func() *peerConn {
		t.Helper()
		pc := e.peerConn(peer)
		pc.mu.Lock()
		pc.secure = settled
		if _, err := pc.sessionLocked(); err != nil {
			pc.mu.Unlock()
			t.Fatalf("build session: %v", err)
		}
		pc.mu.Unlock()
		return pc
	}

	pc1 := build()
	pc1.killSession(errors.New("test: first kill"), true, reasonLocalKill)
	pc2 := build()
	pc2.killSession(errors.New("test: second kill"), true, reasonLocalKill)
	pc3 := e.peerConn(peer)

	pc3.mu.Lock()
	churn := pc3.churn
	pc3.mu.Unlock()
	if churn != 2 {
		t.Fatalf("churn after two kills across one swap = %d, want 2 — the swap restarted the window", churn)
	}
}
