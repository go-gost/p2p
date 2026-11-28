package host

import (
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

func TestResolvePunchDefaults(t *testing.T) {
	got, err := resolvePunch(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.mode != "" || got.afterRounds != 1 || got.sprayPorts != 1000 ||
		got.sprayEvery != 2*time.Second || got.sockets != 150 ||
		got.socketWindow != 20*time.Second || got.seedGrace != 500*time.Millisecond {
		t.Fatalf("defaults = %+v", got)
	}
}

func TestResolvePunchRejectsUnknownMode(t *testing.T) {
	if _, err := resolvePunch(&p2p.PunchConfig{Mode: "sprayx"}); err == nil {
		t.Fatal("want error for unknown mode")
	}
}

func TestResolvePunchClampsAndValidates(t *testing.T) {
	got, err := resolvePunch(&p2p.PunchConfig{Mode: "spray", SprayPorts: 99999, Sockets: 99999})
	if err != nil {
		t.Fatal(err)
	}
	if got.sprayPorts != 2048 || got.sockets != 512 {
		t.Fatalf("clamp = %+v", got)
	}
	for _, bad := range []*p2p.PunchConfig{
		{Mode: "spray", SprayEvery: 100 * time.Millisecond},
		{Mode: "sockets", SocketWindow: 61 * time.Second},
		{Mode: "spray", SeedGrace: 61 * time.Second},
	} {
		if _, err := resolvePunch(bad); err == nil {
			t.Fatalf("want error for %+v", bad)
		}
	}
}

func TestSprayEnabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		want bool
	}{
		{name: "spray", mode: "spray", want: true},
		{name: "sockets", mode: "sockets", want: true},
		{name: "empty", mode: "", want: false},
		{name: "off", mode: "off", want: false},
		{name: "unknown", mode: "bogus", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &engine{punch: punchSettings{mode: tc.mode}}
			if got := e.sprayEnabled(); got != tc.want {
				t.Fatalf("sprayEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEngineCapsSprayModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		want bool
	}{
		{name: "spray", mode: "spray", want: true},
		{name: "sockets", mode: "sockets", want: true},
		{name: "empty", mode: "", want: false},
		{name: "off", mode: "off", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &engine{punch: punchSettings{mode: tc.mode}}
			if got := e.caps().Bits&capsSpray != 0; got != tc.want {
				t.Fatalf("capsSpray advertised = %v, want %v", got, tc.want)
			}
		})
	}
}

// fallbackPublicV4 is a public IPv4 endpoint: the kind of peer candidate that
// can be sprayed. It is distinct from the TEST-NET addresses used elsewhere.
func fallbackPublicV4() []netip.AddrPort {
	return []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:443")}
}

// fallbackTreatAsPublic lets an in-process loopback fake peer stand in for a
// public endpoint: the real predicate rejects loopback by design. It restores
// the seam on cleanup so other tests keep the production classification.
func fallbackTreatAsPublic(t *testing.T, ap netip.AddrPort) {
	t.Helper()
	old := isPublicIPv4Fn
	isPublicIPv4Fn = func(candidate netip.AddrPort) bool {
		return candidate == ap || old(candidate)
	}
	t.Cleanup(func() { isPublicIPv4Fn = old })
}

// newFallbackTestConn builds a directConn with the given punch settings. Its
// engine has no relay client and does not track the connection, so a retry's
// timer exits without starting another round.
func newFallbackTestConn(t *testing.T, mode string, afterRounds int, peerBits uint8) *directConn {
	t.Helper()
	e := &engine{
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		stop:    make(chan struct{}),
		directs: make(map[derpclient.PublicKey]*directConn),
		punch:   punchSettings{mode: mode, afterRounds: afterRounds},
	}
	dc := &directConn{e: e, peer: derpclient.PublicKey{0x42}}
	if peerBits != 0 {
		dc.addCaps(capsInfo{Bits: peerBits})
	}
	return dc
}

func normalFailuresOf(dc *directConn) int {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.normalFailures
}

func fallbackFailuresOf(dc *directConn) int {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.fallbackFailures
}

func TestFallbackArmsAfterSeedFailures(t *testing.T) {
	for _, tc := range []struct {
		name                string
		after               int
		failuresBeforeReady int
	}{
		{name: "one round", after: 1, failuresBeforeReady: 1},
		{name: "two rounds", after: 2, failuresBeforeReady: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dc := newFallbackTestConn(t, "spray", tc.after, capsSpray)
			if dc.fallbackReady(fallbackPublicV4()) {
				t.Fatal("armed before any failure")
			}
			for i := 1; i <= tc.failuresBeforeReady; i++ {
				dc.noteNormalSeedFailure()
				got := dc.fallbackReady(fallbackPublicV4())
				if want := i >= tc.after; got != want {
					t.Fatalf("after %d failures, ready = %v, want %v", i, got, want)
				}
			}
		})
	}
}

func TestFallbackNotArmedWithoutPeerCaps(t *testing.T) {
	for _, bits := range []uint8{0, capsIPv6, capsQUIC} {
		dc := newFallbackTestConn(t, "spray", 1, bits)
		dc.noteNormalSeedFailure()
		if dc.fallbackReady(fallbackPublicV4()) {
			t.Fatalf("armed with peer caps %#x (no capsSpray)", bits)
		}
	}
}

func TestFallbackNotArmedWithoutPublicV4(t *testing.T) {
	bad := []string{
		"10.0.0.1:443",        // RFC1918
		"172.16.0.1:443",      // RFC1918
		"192.168.1.1:443",     // RFC1918
		"127.0.0.1:443",       // loopback
		"169.254.1.1:443",     // link-local
		"0.0.0.0:443",         // unspecified
		"224.0.0.1:443",       // multicast
		"100.64.0.1:443",      // CGNAT, not covered by IsPrivate
		"100.127.255.255:443", // CGNAT upper edge
		"[::1]:443",           // not IPv4
		"[2001:db8::1]:443",   // not IPv4
	}
	dc := newFallbackTestConn(t, "spray", 1, capsSpray)
	dc.noteNormalSeedFailure()
	if dc.fallbackReady(nil) {
		t.Fatal("armed with no peer candidates")
	}
	for _, spec := range bad {
		if dc.fallbackReady([]netip.AddrPort{netip.MustParseAddrPort(spec)}) {
			t.Fatalf("armed with non-public candidate %s", spec)
		}
	}
	// One public address among local ones is enough to arm.
	mixed := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.1:443"),
		fallbackPublicV4()[0],
	}
	if !dc.fallbackReady(mixed) {
		t.Fatal("not armed with a public candidate among local ones")
	}
}

// TestFallbackTargetSelectsPublicNotLast pins the target both fallback branches
// use: a public entry earlier in the list wins even when a private or loopback
// entry comes after it. fallbackReady alone only proves some entry armed.
func TestFallbackTargetSelectsPublicNotLast(t *testing.T) {
	dc := newFallbackTestConn(t, "spray", 1, capsSpray)
	dc.noteNormalSeedFailure()
	want := netip.MustParseAddrPort("8.8.8.8:443")
	mixed := []netip.AddrPort{
		want,
		netip.MustParseAddrPort("10.0.0.1:443"),
		netip.MustParseAddrPort("127.0.0.1:9"),
	}
	if !dc.fallbackReady(mixed) {
		t.Fatal("fallback not armed with a public candidate before private ones")
	}
	got, ok := dc.fallbackTarget(mixed)
	if !ok {
		t.Fatal("fallbackTarget did not select an armed public endpoint")
	}
	if got != want {
		t.Fatalf("fallbackTarget = %v, want the public endpoint %v", got, want)
	}
	if got, ok := dc.fallbackTarget([]netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.1:443"),
		netip.MustParseAddrPort("127.0.0.1:9"),
	}); ok || got.IsValid() {
		t.Fatalf("fallbackTarget = (%v, %v), want (invalid, false) with no public endpoint", got, ok)
	}
}

func TestFallbackOffModesNeverArm(t *testing.T) {
	for _, mode := range []string{"", "off", "bogus"} {
		dc := newFallbackTestConn(t, mode, 1, capsSpray)
		dc.noteNormalSeedFailure()
		if dc.fallbackReady(fallbackPublicV4()) {
			t.Fatalf("armed with punch mode %q", mode)
		}
	}
}

func TestFallbackSeedSuccessResets(t *testing.T) {
	dc := newFallbackTestConn(t, "spray", 1, capsSpray)
	dc.noteNormalSeedFailure()
	if !dc.fallbackReady(fallbackPublicV4()) {
		t.Fatal("not armed before success")
	}
	dc.noteFallbackSuccess()
	if dc.fallbackReady(fallbackPublicV4()) || normalFailuresOf(dc) != 0 {
		t.Fatal("success did not clear the failure run")
	}

	// A successful normal round goes through markUp, which owns the reset for
	// both the normal and the fallback path.
	e := newTestEngine(t)
	e.punch = punchSettings{mode: "spray", afterRounds: 1}
	peer := derpclient.PublicKey{0x43}
	dc2 := e.directConn(peer)
	dc2.addCaps(capsInfo{Bits: capsSpray})
	dc2.noteNormalSeedFailure()
	if !dc2.fallbackReady(fallbackPublicV4()) {
		t.Fatal("not armed before markUp")
	}
	sock := mustListenUDP(t)
	t.Cleanup(func() { sock.Close() })
	peerAddr := udpAddrPort(t, mustListenUDP(t))
	if err := dc2.markUp(sock, peerAddr, [seedTokenLen]byte{0x11}); err != nil {
		t.Fatalf("markUp: %v", err)
	}
	if dc2.fallbackReady(fallbackPublicV4()) || normalFailuresOf(dc2) != 0 {
		t.Fatal("a successful round through markUp did not clear the failure run")
	}
}

func TestFallbackFailureKeepsArmed(t *testing.T) {
	dc := newFallbackTestConn(t, "spray", 1, capsSpray)
	dc.noteNormalSeedFailure()
	dc.noteFallbackFailure()
	if !dc.fallbackReady(fallbackPublicV4()) {
		t.Fatal("a fallback failure disarmed the fallback")
	}
	if got := fallbackFailuresOf(dc); got != 1 {
		t.Fatalf("fallbackFailures = %d, want 1", got)
	}
	// The next round still sees an armed fallback and gets the short retry.
	dc.seedFailureRetry(fallbackPublicV4())
	if d := dc.nextPunchIn(); d <= 0 || d > time.Second {
		t.Fatalf("next retry after a fallback failure = %s, want ~%s", d, fallbackRetry)
	}
}

func TestFallbackRetryIsShort(t *testing.T) {
	oldBackoff := backoffPeriod.Load()
	backoffPeriod.Store(int64(5 * time.Second))
	defer backoffPeriod.Store(oldBackoff)

	armed := newFallbackTestConn(t, "spray", 1, capsSpray)
	armed.noteNormalSeedFailure()
	armed.seedFailureRetry(fallbackPublicV4())
	if d := armed.nextPunchIn(); d <= 0 || d > time.Second {
		t.Fatalf("armed retry = %s, want ~%s, not the 5s backoff", d, fallbackRetry)
	}

	unarmed := newFallbackTestConn(t, "spray", 1, 0)
	unarmed.seedFailureRetry(fallbackPublicV4())
	if d := unarmed.nextPunchIn(); d < 2*time.Second {
		t.Fatalf("unarmed retry = %s, want the long backoff", d)
	}
	if got := normalFailuresOf(unarmed); got != 1 {
		t.Fatalf("normalFailures = %d after a failed round, want 1", got)
	}
}

func TestFallbackControlFailureDoesNotArm(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(url, "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)
	e.stunAddr = startFakeSTUN(t, "")
	e.punch = punchSettings{mode: "spray", afterRounds: 1}
	peer := derpclient.PublicKey{0x44}
	dc := e.directConn(peer)
	dc.addCaps(capsInfo{Bits: capsSpray})
	e.Connect()
	dc.start()

	waitFor(t, 6*time.Second, func() bool {
		for _, line := range dc.traceLines() {
			if line == "no peer candidates" {
				return true
			}
		}
		return false
	})

	if got := normalFailuresOf(dc); got != 0 {
		t.Fatalf("normalFailures = %d after a no-peer-candidates round, want 0", got)
	}
	if dc.fallbackReady(fallbackPublicV4()) {
		t.Fatal("the fallback armed on a control-plane failure")
	}
}

func TestResolvePunchOffSkipsValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
	}{
		{name: "off", mode: "off"},
		{name: "empty", mode: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolvePunch(&p2p.PunchConfig{
				Mode:         tc.mode,
				AfterRounds:  -1,
				SprayPorts:   -1,
				SprayEvery:   500 * time.Millisecond,
				Sockets:      -1,
				SocketWindow: 61 * time.Second,
				SeedGrace:    -time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got.mode != "" || got.afterRounds != 1 || got.sprayPorts != 1000 ||
				got.sprayEvery != 2*time.Second || got.sockets != 150 ||
				got.socketWindow != 20*time.Second || got.seedGrace != 500*time.Millisecond {
				t.Fatalf("off settings = %+v", got)
			}
		})
	}
}

// fallbackDiagnostics reads the peer's diagnostic the way a status caller does.
func fallbackDiagnostics(dc *directConn) p2p.PeerDiagnostic {
	name := keyName(dc.peer)
	st := dc.e.peerDiagnostics(map[string]string{name: "derp"})
	return st[name]
}

// TestPeerDiagnosticFallback pins the in-process diagnostic fields: the opted-in
// mode and resolved budgets, plus one completed fallback attempt's outcome. The
// counters are per attempt, not consecutive failures, so a later failure must
// add to the same round count and replace the winner with its reason.
func TestPeerDiagnosticFallback(t *testing.T) {
	const winner = "203.0.113.9:51000"
	for _, mode := range []string{"spray", "sockets"} {
		t.Run(mode, func(t *testing.T) {
			dc := newFallbackTestConn(t, mode, 1, capsSpray)
			dc.e.punch.sprayPorts = 64
			dc.e.punch.sockets = 7
			dc.e.directs[dc.peer] = dc
			dc.noteFallbackResult(winner, "")

			d := fallbackDiagnostics(dc)
			if d.PunchFallback != mode {
				t.Fatalf("PunchFallback = %q, want %q", d.PunchFallback, mode)
			}
			if d.FallbackRounds != 1 {
				t.Fatalf("FallbackRounds = %d, want 1", d.FallbackRounds)
			}
			if d.SprayPorts != 64 || d.Sockets != 7 {
				t.Fatalf("budgets = (%d ports, %d sockets), want (64, 7)", d.SprayPorts, d.Sockets)
			}
			if d.FallbackWinner != winner || d.FallbackError != "" {
				t.Fatalf("outcome = (%q, %q), want (%q, empty)",
					d.FallbackWinner, d.FallbackError, winner)
			}

			dc.noteFallbackResult("", "spray failed: timeout")
			d = fallbackDiagnostics(dc)
			if d.FallbackRounds != 2 {
				t.Fatalf("FallbackRounds = %d after a second attempt, want 2", d.FallbackRounds)
			}
			if d.FallbackWinner != "" || d.FallbackError != "spray failed: timeout" {
				t.Fatalf("outcome = (%q, %q), want (empty, spray failed: timeout)",
					d.FallbackWinner, d.FallbackError)
			}

			// FallbackFailures is the consecutive-failure counter, distinct from
			// the cumulative FallbackRounds, and a success clears it.
			dc.noteFallbackFailure()
			d = fallbackDiagnostics(dc)
			if d.FallbackFailures != 1 || d.FallbackRounds != 2 {
				t.Fatalf("failures/rounds = (%d, %d), want (1, 2)", d.FallbackFailures, d.FallbackRounds)
			}
			dc.noteFallbackSuccess()
			d = fallbackDiagnostics(dc)
			if d.FallbackFailures != 0 || d.FallbackRounds != 2 {
				t.Fatalf("failures/rounds after success = (%d, %d), want (0, 2)", d.FallbackFailures, d.FallbackRounds)
			}
		})
	}

	t.Run("off", func(t *testing.T) {
		dc := newFallbackTestConn(t, "off", 1, capsSpray)
		dc.e.punch.sprayPorts = 64
		dc.e.punch.sockets = 7
		dc.e.directs[dc.peer] = dc

		d := fallbackDiagnostics(dc)
		if d.PunchFallback != "" || d.FallbackRounds != 0 || d.SprayPorts != 0 || d.Sockets != 0 {
			t.Fatalf("off diagnostic = %+v, want all-empty fallback fields", d)
		}
	})
}

// TestPunchFallbackTraceAndWinner drives both fallback branches so the trace
// lines and the recorded outcome come from punch(), not from a test helper.
func TestPunchFallbackTraceAndWinner(t *testing.T) {
	t.Run("spray success", func(t *testing.T) {
		dc, _ := sprayTestRound(t, "spray", "203.0.113.7:41000")
		peerAddr := sprayTestEchoPeer(t)
		var gotIP netip.Addr
		var gotN int
		spraySetTargets(t, &gotIP, &gotN, []netip.AddrPort{peerAddr})
		dc.cand <- sprayPublicV4(41000)
		if !dc.start() {
			t.Fatal("punch did not start")
		}
		waitFor(t, 4*time.Second, func() bool {
			return sprayTraceHas(dc, "fallback up via") || sprayTraceHas(dc, "spray failed")
		})
		if !dc.isUp() {
			t.Fatalf("spray did not install a direct path; trace = %v", dc.traceLines())
		}
		winner := peerAddr.String()
		for _, want := range []string{"fallback spray ports=2", "fallback up via " + winner} {
			if !sprayTraceHas(dc, want) {
				t.Fatalf("no trace line %q: %v", want, dc.traceLines())
			}
		}
		d := fallbackDiagnostics(dc)
		if d.FallbackWinner != winner || d.FallbackRounds != 1 || d.FallbackError != "" {
			t.Fatalf("fallback outcome = (%q, %d rounds, %q), want (%q, 1, empty)",
				d.FallbackWinner, d.FallbackRounds, d.FallbackError, winner)
		}
	})

	t.Run("spray failure", func(t *testing.T) {
		dc, _ := sprayTestRound(t, "spray", "203.0.113.7:42000")
		dc.e.punch.socketWindow = 150 * time.Millisecond
		var gotIP netip.Addr
		var gotN int
		spraySetTargets(t, &gotIP, &gotN, nil)
		dc.cand <- sprayPublicV4(42000)
		if !dc.start() {
			t.Fatal("punch did not start")
		}
		waitFor(t, 4*time.Second, func() bool {
			return fallbackDiagnostics(dc).FallbackError != ""
		})
		d := fallbackDiagnostics(dc)
		if d.FallbackRounds != 1 || d.FallbackWinner != "" ||
			!strings.Contains(d.FallbackError, "spray failed") {
			t.Fatalf("fallback outcome = (%q, %d rounds, %q), want an empty winner and a spray failure",
				d.FallbackWinner, d.FallbackRounds, d.FallbackError)
		}
	})

	t.Run("sockets success", func(t *testing.T) {
		socketsSetStartDelay(t, 10*time.Millisecond)
		dc, _ := sprayTestRound(t, "sockets", "203.0.113.7:41000")
		dc.e.punch.sockets = 3
		dc.e.punch.socketWindow = 2 * time.Second
		peerAddr := sprayTestEchoPeer(t)
		fallbackTreatAsPublic(t, peerAddr) // the fake peer occupies the public slot
		dc.cand <- []candidate{{addr: peerAddr}}
		if !dc.start() {
			t.Fatal("punch did not start")
		}
		waitFor(t, 5*time.Second, func() bool {
			return sprayTraceHas(dc, "fallback up via") || sprayTraceHas(dc, "sockets failed")
		})
		if !dc.isUp() {
			t.Fatalf("sockets did not install a direct path; trace = %v", dc.traceLines())
		}
		winner := peerAddr.String()
		for _, want := range []string{"fallback sockets=3", "fallback up via " + winner} {
			if !sprayTraceHas(dc, want) {
				t.Fatalf("no trace line %q: %v", want, dc.traceLines())
			}
		}
		d := fallbackDiagnostics(dc)
		if d.FallbackWinner != winner || d.FallbackRounds != 1 || d.FallbackError != "" {
			t.Fatalf("fallback outcome = (%q, %d rounds, %q), want (%q, 1, empty)",
				d.FallbackWinner, d.FallbackRounds, d.FallbackError, winner)
		}
	})

	t.Run("sockets failure", func(t *testing.T) {
		socketsSetStartDelay(t, 10*time.Millisecond)
		dc, _ := sprayTestRound(t, "sockets", "203.0.113.7:42000")
		dc.e.punch.sockets = 2
		dc.e.punch.socketWindow = 100 * time.Millisecond
		dc.cand <- sprayPublicV4(42000)
		if !dc.start() {
			t.Fatal("punch did not start")
		}
		waitFor(t, 5*time.Second, func() bool {
			return fallbackDiagnostics(dc).FallbackError != ""
		})
		d := fallbackDiagnostics(dc)
		if d.FallbackRounds != 1 || d.FallbackWinner != "" ||
			!strings.Contains(d.FallbackError, "sockets failed") {
			t.Fatalf("fallback outcome = (%q, %d rounds, %q), want an empty winner and a sockets failure",
				d.FallbackWinner, d.FallbackRounds, d.FallbackError)
		}
	})
}
