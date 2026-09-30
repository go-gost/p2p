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
	"github.com/xtaci/smux"
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
		if f.muteCtrl(now) || f.muteData(now) || f.pong() || f.silenced(now) {
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
		SilenceFor:   time.Second,
		SilenceEvery: time.Minute,
	}).warn(log)
	for _, want := range []string{"fault injection", "dropData", "silence(1s every 1m0s)"} {
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

// watchSession captures B's live direct session to A: the thing every fault test
// watches die, held directly so it cannot be confused with the session a
// re-punch would build.
func watchSession(t *testing.T, b, a *engine) *smux.Session {
	t.Helper()
	dcB := b.getDirect(a.pub)
	if dcB == nil {
		t.Fatal("B has no direct state to watch")
	}
	dcB.mu.Lock()
	defer dcB.mu.Unlock()
	if dcB.sess == nil {
		t.Fatal("B has no direct session to watch")
	}
	return dcB.sess
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

	sessB := watchSession(t, b, a)

	// B's session is fed by A's frames alone, and A now stops sending them — on
	// both planes at once, since dropData covers the relay adapter and the direct
	// underlay with the same knob.
	a.faults.Store(newFaults(&p2p.FaultsConfig{DropData: true}))

	// 1-2x the direct timeout plus a tick: the bound is what separates a starved
	// session from one that is merely idle.
	waitFor(t, 8*time.Second, func() bool { return sessB.IsClosed() })
}

// TestSilenceShorterThanTimeoutIsSurvived: the measured field failure — a
// one-way silence with the path intact — at test speed. A mute shorter than the
// session's keepalive timeout is survived; one well beyond it kills the session.
// That pair is the regression the shipped 15s default fixes: the 6s timeout it
// replaced died at exactly 18s to ~12s of one-way silence from RF batching.
func TestSilenceShorterThanTimeoutIsSurvived(t *testing.T) {
	a, b, _ := startPunchedPair(t)

	sessB := watchSession(t, b, a)

	// Half the timeout: A goes quiet and comes back, and the session must not
	// notice. The window opens when the fault is built.
	short := newFaults(&p2p.FaultsConfig{
		SilenceFor:   directSmuxKeepAliveTimeout / 2,
		SilenceEvery: time.Minute,
	})
	a.faults.Store(short)
	if !short.silenced(time.Now()) {
		t.Fatal("the silence window must be open at the fault's creation")
	}
	time.Sleep(directSmuxKeepAliveTimeout)
	if sessB.IsClosed() {
		t.Fatal("a silence shorter than the keepalive timeout killed the session")
	}

	// Three times the timeout: this is the mute a 6s timeout could not survive,
	// and from here the session must die.
	a.faults.Store(newFaults(&p2p.FaultsConfig{
		SilenceFor:   3 * directSmuxKeepAliveTimeout,
		SilenceEvery: time.Minute,
	}))
	waitFor(t, 3*3*directSmuxKeepAliveTimeout, func() bool { return sessB.IsClosed() })
}
