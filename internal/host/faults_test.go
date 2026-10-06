package host

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

// TestFaultsOffByDefault: the fault set is off in the zero value — that is the
// whole safety story of the feature. A missing config, an empty one, and a nil
// state (an engine built without host.New, as these tests build them) must all
// inject nothing rather than crash on the hot path.
func TestFaultsOffByDefault(t *testing.T) {
	now := time.Now()
	for name, f := range map[string]*faults{
		"nil config":  newFaults(nil),
		"zero config": newFaults(&p2p.FaultsConfig{}),
		"nil state":   nil,
	} {
		if f.muteCtrl(now) || f.muteData(now) || f.muteDirect() || f.pong() || f.silenced(now) {
			t.Fatalf("%s must inject nothing", name)
		}
	}
}

// TestFaultsSilenceWindow pins the timed mute: the first SilenceFor of every
// SilenceEvery, counted from the fault's creation. The origin is pinned here so
// the phases are the test's, not the clock's.
func TestFaultsSilenceWindow(t *testing.T) {
	f := newFaults(&p2p.FaultsConfig{SilenceFor: time.Second, SilenceEvery: 10 * time.Second})
	start := time.Unix(0, 0)
	f.since = start
	if !f.silenced(start) {
		t.Fatal("the window must start muted")
	}
	if !f.silenced(start.Add(999 * time.Millisecond)) {
		t.Fatal("inside the window must stay muted")
	}
	if f.silenced(start.Add(2 * time.Second)) {
		t.Fatal("outside the window must send")
	}
	if !f.silenced(start.Add(10 * time.Second)) {
		t.Fatal("the next window must mute again")
	}
	// A for-without-every is a no-op, not a permanent mute: a broken host is not
	// a reproducible fault.
	if g := newFaults(&p2p.FaultsConfig{SilenceFor: time.Second}); g.silenced(start) {
		t.Fatal("silenceFor without silenceEvery must inject nothing")
	}
}

// TestFaultsWarnNamesTheKnobs: the startup line is the only thing separating a
// deliberately broken host from a genuinely broken one, so it has to name what
// is on — and stay silent when nothing is.
func TestFaultsWarnNamesTheKnobs(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	newFaults(nil).warn(log)
	if buf.Len() != 0 {
		t.Fatalf("an inert state logged %q", buf.String())
	}

	newFaults(&p2p.FaultsConfig{
		DropData:     true,
		DropDirect:   true,
		DropDataRate: 0.25,
		SilenceFor:   time.Second,
		SilenceEvery: time.Minute,
	}).warn(log)
	for _, want := range []string{"fault injection", "dropData", "dropDirect", "dropDataRate(0.25)", "silence(1s every 1m0s)"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("warning %q does not name %q", buf.String(), want)
		}
	}
}

// startPunchedPair brings two engines up through the in-process relay and waits
// for a live hole-punched session on both sides — the state every per-frame
// fault test starts from. Faults are off; each test turns one on at the moment
// it is measuring.
func startPunchedPair(t *testing.T) (a, b *engine, pubB derpclient.PublicKey) {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a = newEngine(url, "", privA, slog.Default())
	b = newEngine(url, echo, privB, slog.Default())
	a.stunAddr, b.stunAddr = stun, stun
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})

	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := b.Connect(); err != nil {
		t.Fatal(err)
	}

	s, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()

	waitFor(t, 5*time.Second, func() bool { return hasDirect(a, pubB) && hasDirect(b, a.pub) })
	return a, b, pubB
}

// watchDirect captures B's directConn to A: the direct path every fault test
// watches go stale, held directly so it cannot be confused with a path a
// re-punch would build. "Gone" is !isUp(): the idle watchdog retired the
// underlay.
func watchDirect(t *testing.T, b, a *engine) *directConn {
	t.Helper()
	dcB := b.getDirect(a.pub)
	if dcB == nil {
		t.Fatal("B has no direct state to watch")
	}
	if !dcB.isUp() {
		t.Fatal("B has no direct path to watch")
	}
	return dcB
}

// TestDropCtrlStopsNegotiation: with the control plane dropped, nothing settles.
// Encryption is forced and negotiates on that same channel, so the symptom is
// not "stays on relay" — no session is built at all, which is what a peer that
// cannot negotiate looks like from here. The punch must not produce a direct
// path either.
func TestDropCtrlStopsNegotiation(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a := newEngine(url, "", privA, slog.Default())
	b := newEngine(url, echo, privB, slog.Default())
	a.stunAddr, b.stunAddr = stun, stun
	a.faults.Store(newFaults(&p2p.FaultsConfig{DropCtrl: true}))
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})

	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := b.Connect(); err != nil {
		t.Fatal(err)
	}

	_, err := a.OpenStream(b.PublicKey())
	if !errors.Is(err, errEncryptionRequired) {
		t.Fatalf("open with the control plane dropped = %v, want %v", err, errEncryptionRequired)
	}
	if hasDirect(a, pubB) {
		t.Fatal("a control-plane drop still punched a direct path")
	}
}

// TestDropPongMakesALiveRelayLookSilent: the pong fault is the host-side twin of
// the relay-silence watchdog's test — the relay answers every ping, and the
// engine still declares the path dead, because the answers are thrown away
// before they are stamped. A live relay must not be able to look healthier than
// it is.
func TestDropPongMakesALiveRelayLookSilent(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	priv, _, _ := derpclient.Generate()
	e := newEngine(url, "", priv, slog.Default())
	e.faults.Store(newFaults(&p2p.FaultsConfig{DropPong: true}))
	t.Cleanup(func() { e.Close() })

	if err := e.Connect(); err != nil {
		t.Fatal(err)
	}
	// The relay answers (the double does), so a healthy engine never tears the
	// connection down; the watchdog fires only because the answer was swallowed.
	waitFor(t, 3*time.Second, func() bool { return !e.relayConnected() })
}

// TestDropDataStarvesADirectSession: dropData is the in-process reproduction of
// the field failure that killed direct sessions at 18s — the peer's frames stop
// arriving while the path stays up. smux is fed only by the frames the peer
// sends, so the session must be given up on its own keepalive (2s here, 15s in
// production), not left looking live.
func TestDropDataStarvesADirectSession(t *testing.T) {
	a, b, _ := startPunchedPair(t)

	dcB := watchDirect(t, b, a)

	// B's direct path is fed by A's frames alone, and A now stops sending them —
	// on both planes at once, since dropData is applied at the pair's write path.
	a.faults.Store(newFaults(&p2p.FaultsConfig{DropData: true}))

	// 1-2x the direct idle bound plus a tick: the bound is what separates a
	// starved path from one that is merely idle.
	waitFor(t, 2*directUnderlayIdle, func() bool { return dcB.drops.Load() >= 1 })
}

// TestFaultMuteDirectFallsBackToRelay pins the per-path mute (Task 12 / O7):
// DropDirect silences the direct underlay alone, in both directions, while the
// relay keeps working. A's direct goes silent, so both sides' direct paths
// stale out and are retired; the pair falls back to the relay and a fresh stream
// still completes byte-exact. That is "direct dies, relay recovers" — the
// complement of the all-path mute, which retires direct without a relay to
// recover onto.
func TestFaultMuteDirectFallsBackToRelay(t *testing.T) {
	a, b, _ := startPunchedPair(t)

	dcB := watchDirect(t, b, a)
	pairB := b.relayKCPPairFor(a.pub)
	if !pairB.preferredDirect() {
		t.Fatal("B must prefer direct before a direct-only mute")
	}

	// A mutes the direct underlay only: its relay control and data stay up.
	a.faults.Store(newFaults(&p2p.FaultsConfig{DropDirect: true}))

	// A stops sending on direct (so B stales) and drops what B sends (so A
	// stales). B's direct underlay is retired by its idle watchdog while the
	// relay stays up — "direct dies" without the relay going with it.
	waitFor(t, 3*directUnderlayIdle, func() bool {
		return dcB.drops.Load() >= 1 && !pairB.preferredDirect()
	})
	if !b.relayConnected() {
		t.Fatal("the relay connection died with the direct-only mute")
	}

	// "Relay recovers": a stream opened now completes byte-exact. A opens
	// because B holds the echo target in this harness (the base stream in
	// startPunchedPair ran the same direction); A's pair has fallen back to the
	// relay (its direct is stale, so not preferred), and B's has.
	s, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	roundTrip(t, s, "direct is muted, relay carried this")
}

// TestFaultsDropDataRate pins the probabilistic data-frame loss injector: a
// configured ratio drops every round(1/rate)th relay data frame exactly, so a
// test can assert counts rather than a statistical band. A zero ratio is off.
func TestFaultsDropDataRate(t *testing.T) {
	// Zero means off: no frames are dropped.
	f := newFaults(&p2p.FaultsConfig{DropDataRate: 0})
	for i := 0; i < 100; i++ {
		if f.dropDataPacket() {
			t.Fatal("zero rate must not drop any packet")
		}
	}

	// 0.25 => one packet in four is dropped, deterministically.
	f = newFaults(&p2p.FaultsConfig{DropDataRate: 0.25})
	var drops int
	for i := 0; i < 100; i++ {
		if f.dropDataPacket() {
			drops++
		}
	}
	if drops != 25 {
		t.Fatalf("rate 0.25 over 100 packets dropped %d, want 25", drops)
	}

	// The first three calls pass, the fourth is dropped.
	f = newFaults(&p2p.FaultsConfig{DropDataRate: 0.25})
	for i := 0; i < 3; i++ {
		if f.dropDataPacket() {
			t.Fatalf("packet %d should pass", i+1)
		}
	}
	if !f.dropDataPacket() {
		t.Fatal("packet 4 should drop")
	}
}

// TestSilenceShorterThanTimeoutIsSurvived: the measured field failure — a
// one-way silence with the path intact — at test speed. A mute shorter than the
// direct idle bound is survived; one well beyond it retires the direct path.
// That pair is the regression the shipped 15s smux timeout fixes: the 6s
// timeout it replaced died at exactly 18s to ~12s of one-way silence from RF
// batching. The idle bound (directUnderlayIdle, 2× the keepalive interval) is
// what the direct underlay's watchdog uses.
func TestSilenceShorterThanTimeoutIsSurvived(t *testing.T) {
	a, b, _ := startPunchedPair(t)

	dcB := watchDirect(t, b, a)
	pairB := b.relayKCPPairFor(a.pub)

	// A window well below the idle bound, then a sleep well past it: A goes quiet
	// for idle/3 and comes back, and the direct path must not be retired. The
	// sleep past idle is what makes this a boundary test — a watchdog that fired
	// on any silence (or did not re-arm on resumed data) would retire the path
	// even though the mute ended before the threshold. The window opens when the
	// fault is built.
	short := newFaults(&p2p.FaultsConfig{
		SilenceFor:   directUnderlayIdle / 3,
		SilenceEvery: time.Minute,
	})
	a.faults.Store(short)
	if !short.silenced(time.Now()) {
		t.Fatal("the silence window must be open at the fault's creation")
	}
	time.Sleep(directUnderlayIdle + directUnderlayReadTimeout)
	if got := dcB.drops.Load(); got != 0 {
		t.Fatalf("a silence shorter than the idle bound retired the direct path %d time(s)", got)
	}
	if !pairB.preferredDirect() {
		t.Fatal("the direct path was not preferred after a silence shorter than the idle bound")
	}

	// Well beyond the idle bound: the path must be retired and the drop counted.
	a.faults.Store(newFaults(&p2p.FaultsConfig{
		SilenceFor:   3 * directUnderlayIdle,
		SilenceEvery: time.Minute,
	}))
	waitFor(t, 3*directUnderlayIdle, func() bool { return dcB.drops.Load() >= 1 })
}

// TestHostAppliesFaultsToEngine pins the config→engine wiring the embedder path
// (wisper's acquire) depends on: a Faults block on p2p.Config must not merely be
// copied — it must land on the engine's atomic faults pointer with the drop
// decision actually active. A config that reaches the field but not the engine
// would pass a struct-copy check and still inject nothing.
func TestHostAppliesFaultsToEngine(t *testing.T) {
	h, err := New(&p2p.Config{
		Derp:   "wss://127.0.0.1:1/derp",
		KeyHex: strings.Repeat("cc", 32),
		Faults: &p2p.FaultsConfig{DropDataRate: 0.5},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if h.engine == nil {
		t.Fatal("a relay-configured host built no engine")
	}
	f := h.engine.faults.Load()
	if f == nil {
		t.Fatal("the engine holds no faults state")
	}
	// rate 0.5 => drop every round(1/0.5)=2nd frame: the first call passes, the
	// second drops. This is the engine's drop decision, not a config echo.
	if f.dropDataPacket() {
		t.Fatal("the first relay data frame must pass")
	}
	if !f.dropDataPacket() {
		t.Fatal("the second relay data frame must be dropped (rate 0.5)")
	}
}

// TestHostIgnoresFaultsInStubMode: a host with no relay has no engine, so a
// faults config cannot take effect. It must say so — a silent no-op would read
// as "injection is on" and waste exactly the debugging the config exists to
// avoid.
func TestHostIgnoresFaultsInStubMode(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	h, err := New(&p2p.Config{Faults: &p2p.FaultsConfig{DropData: true}}, WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if h.engine != nil {
		t.Fatal("stub mode built an engine; faults would not be ignored")
	}
	if got := buf.String(); !strings.Contains(got, "fault injection configured but ignored") {
		t.Fatalf("stub mode did not warn about the ignored faults config: %q", got)
	}

	// A faults config with every knob off is not an error: no warning, no engine.
	buf.Reset()
	h2, err := New(&p2p.Config{Faults: &p2p.FaultsConfig{}}, WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if buf.Len() != 0 {
		t.Fatalf("a zero faults config must not warn: %q", buf.String())
	}
}
