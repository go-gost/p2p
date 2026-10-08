package host

// T11 commit 2 (O1/O2/O4/O5) unit tests: pair-level path events, migration
// counters, the fallback reason, the path-change trace, and the H1 relay-loss
// suppression signal. They are deliberately white-box on the pair (a raw
// engine) so the flips can be driven without a relay or a real punch.

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

// countEvents counts captured log records carrying event=<event>, so a test can
// assert "exactly one path-change" without depending on log text.
func countEvents(c *logCapture, event string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, attrs := range c.attrs {
		for _, a := range attrs {
			if a.Key == "event" && a.Value.String() == event {
				n++
				break
			}
		}
	}
	return n
}

// pairUnderlay installs a fresh direct underlay on pair and returns it plus the
// peer-side socket (closed at cleanup). The pair takes ownership of the
// underlay socket and closes it on retirement/shutdown.
func pairUnderlay(t *testing.T, pair *relayKCPPair) *directUnderlay {
	t.Helper()
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	t.Cleanup(func() { b.Close() })
	u := newDirectUnderlay(a, udpAddrPort(t, b))
	pair.setDirectUnderlay(u)
	return u
}

// TestPairPathChangeLogsOncePerFlip pins O1's centerpiece: every preferred-path
// flip emits exactly one event=path-change with a finite reason, and the O2
// counters move with it.
func TestPairPathChangeLogsOncePerFlip(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	capture := &logCapture{}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{61}
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)

	u := pairUnderlay(t, pair)

	// Install: relay -> direct, exactly one event.
	if got := countEvents(capture, "path-change"); got != 1 {
		t.Fatalf("path-change events after install = %d, want 1", got)
	}
	ev := capture.nth("pair path changed", 0)
	if ev["from"] != "relay" || ev["to"] != "direct" || ev["reason"] != pathChangeFirstDirect {
		t.Fatalf("install event = %v, want relay->direct %s", ev, pathChangeFirstDirect)
	}
	if ev["migrations"] != "1" || ev["fallbacks"] != "0" {
		t.Fatalf("install counters = migrations %s / fallbacks %s, want 1/0", ev["migrations"], ev["fallbacks"])
	}
	if pair.migrations.Load() != 1 || pair.fallbacks.Load() != 0 || pair.pathChanges.Load() != 1 {
		t.Fatalf("pair counters after install = migrations %d / fallbacks %d / pathChanges %d, want 1/0/1",
			pair.migrations.Load(), pair.fallbacks.Load(), pair.pathChanges.Load())
	}

	// Retire: direct -> relay, exactly one more event with the clear reason.
	if !pair.clearDirectUnderlayIf(u, pathChangeClear) {
		t.Fatal("clearDirectUnderlayIf did not retire the installed underlay")
	}
	if got := countEvents(capture, "path-change"); got != 2 {
		t.Fatalf("path-change events after clear = %d, want 2", got)
	}
	ev = capture.nth("pair path changed", 1)
	if ev["from"] != "direct" || ev["to"] != "relay" || ev["reason"] != pathChangeClear {
		t.Fatalf("clear event = %v, want direct->relay %s", ev, pathChangeClear)
	}
	if ev["fallbacks"] != "1" {
		t.Fatalf("clear event fallbacks = %s, want 1", ev["fallbacks"])
	}
	if pair.migrations.Load() != 1 || pair.fallbacks.Load() != 1 || pair.pathChanges.Load() != 2 {
		t.Fatalf("pair counters after clear = migrations %d / fallbacks %d / pathChanges %d, want 1/1/2",
			pair.migrations.Load(), pair.fallbacks.Load(), pair.pathChanges.Load())
	}
}

// TestPairDirectIdleFallbackDiagnostic pins O4/O5: an idle fallback records its
// reason and the idle subset counter, and the path-change ring reconstructs the
// pair's recent history oldest-first.
func TestPairDirectIdleFallbackDiagnostic(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{62}
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)

	u := pairUnderlay(t, pair)

	// Let the direct path go silent past the idle bound, then report it exactly
	// as the pump's watchdog does.
	setPairDirectRecency(pair, time.Now().Add(-2*directUnderlayIdle))
	pair.reportDirectIdle(u)

	pd := pair.diag()
	if pd.fallbackReason != pathChangeDirectIdle {
		t.Fatalf("FallbackReason = %q, want %q", pd.fallbackReason, pathChangeDirectIdle)
	}
	if pd.migrations != 1 || pd.fallbacks != 1 || pd.directIdleEvictions != 1 {
		t.Fatalf("counters = migrations %d / fallbacks %d / idleEvictions %d, want 1/1/1",
			pd.migrations, pd.fallbacks, pd.directIdleEvictions)
	}
	wantTrace := []string{
		"relay->direct " + pathChangeFirstDirect,
		"direct->relay " + pathChangeDirectIdle,
	}
	if len(pd.pathTrace) != len(wantTrace) {
		t.Fatalf("pathTrace = %v, want %v", pd.pathTrace, wantTrace)
	}
	for i := range wantTrace {
		if pd.pathTrace[i] != wantTrace[i] {
			t.Fatalf("pathTrace[%d] = %q, want %q", i, pd.pathTrace[i], wantTrace[i])
		}
	}

	// The engine surfaces the same view per peer (in-process only).
	var d p2p.PeerDiagnostic
	e.fillPairDiag(&d, peer)
	if d.FallbackReason != pathChangeDirectIdle || d.PairFallbacks != 1 || d.DirectIdleEvictions != 1 {
		t.Fatalf("PeerDiagnostic = reason %q / fallbacks %d / idle %d, want %q/1/1",
			d.FallbackReason, d.PairFallbacks, d.DirectIdleEvictions, pathChangeDirectIdle)
	}
	if len(d.PathTrace) != len(wantTrace) {
		t.Fatalf("PathTrace = %v, want %v", d.PathTrace, wantTrace)
	}
}

// TestRelayLossSuppressionCounter pins O2's H1 signal: a relay loss with a live
// direct path is suppressed and counted; without one it resets the pair and is
// not counted as suppressed.
func TestRelayLossSuppressionCounter(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	// Without a live direct path: the relay loss resets the pair (the safe
	// baseline) and is not counted as suppressed.
	peerA := derpclient.PublicKey{71}
	settledA, _ := settledSecurePair(t, secureTransportRelay)
	relaySessionFor(t, e, peerA, settledA)
	pairA := e.relayKCPPairGet(peerA)
	if !e.resetsPairKCPFor(peerA, reasonLinkLost) {
		t.Fatal("relay loss without a live direct did not reset the pair")
	}
	if got := pairA.diag().relayLossSuppressed; got != 0 {
		t.Fatalf("relayLossSuppressed without a live direct = %d, want 0", got)
	}

	// With a live direct path: the relay loss is suppressed and counted.
	peerB := derpclient.PublicKey{72}
	settledB, _ := settledSecurePair(t, secureTransportRelay)
	relaySessionFor(t, e, peerB, settledB)
	liveDirectFor(t, e, peerB)
	pairB := e.relayKCPPairGet(peerB)
	if e.resetsPairKCPFor(peerB, reasonLinkLost) {
		t.Fatal("relay loss with a live direct reset the pair, want suppression")
	}
	if got := pairB.diag().relayLossSuppressed; got != 1 {
		t.Fatalf("relayLossSuppressed with a live direct = %d, want 1", got)
	}
}

// TestPairSeedFailureCounter pins O2's SeedFailures: a failed seed handshake
// counts, a successful one does not.
func TestPairSeedFailureCounter(t *testing.T) {
	e := &engine{relayKCPs: make(map[derpclient.PublicKey]*relayKCPPair)}
	peer := derpclient.PublicKey{81}
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)

	pair.noteSeed("timeout", "udp4", "203.0.113.7:5000")
	pair.noteSeed("ok", "udp6", "[2001:db8::1]:5000")

	if got := pair.seedFailures.Load(); got != 1 {
		t.Fatalf("seedFailures = %d, want 1 (only the timeout)", got)
	}
	if got := pair.diag().seedFailures; got != 1 {
		t.Fatalf("diag seedFailures = %d, want 1", got)
	}
}
