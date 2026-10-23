package host

// The punch attempts both address families at once and still prefers IPv6.
//
// The sequential loop it replaced could phase-lock: each round spends its seed
// timeout on v6 before v4, so when both peers' v6 paths are blind their v4
// windows can be offset and never overlap — the pair never converges off the
// relay. These tests pin the concurrent adjudication and its reporting rules:
// v6 wins whenever it works, a completed v4 handshake is discarded (not
// counted as a failure) when v6 wins, and a round with both families blind
// still backs off.

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// startV6Engines builds the two-engine harness the family tests share: a
// relay, a fake STUN (so v4 has candidates), and a v6 egress at ::1 on both
// sides. No stream is opened and no direct path is awaited — each test drives
// the punch itself.
// stunA/stunB are the addresses each side's fake STUN reports as its public
// v4 endpoint ("" reflects the sender's real one, which the pair can reach; a
// reserved address makes the other side dial a blackhole).
func startV6Engines(t *testing.T, stunA, stunB string) (a, b *engine, pubB derpclient.PublicKey) {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a = newEngine(url, "", privA, slog.Default())
	b = newEngine(url, echo, privB, slog.Default())
	a.stunAddr, b.stunAddr = startFakeSTUN(t, stunA), startFakeSTUN(t, stunB)
	a.v6Enabled, b.v6Enabled = true, true
	a.v6Addr, b.v6Addr = loopbackV6(), loopbackV6()
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
	return a, b, pubB
}

// openRelayStream opens a stream A→B and completes one round trip, which starts
// the punch without the stream depending on it (the relay carries it).
func openRelayStream(t *testing.T, a, b *engine) {
	t.Helper()
	s, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()
}

// blackholeV6 announces a reserved, unreachable v6 address: the peer dials it
// and its seed handshake times out, which is the blind-family case.
func blackholeV6(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), port)
}

// TestPunchPrefersV6WhenBothWork: with both families able to complete, the
// round must register v6 and must cancel — not fail — the v4 attempt.
func TestPunchPrefersV6WhenBothWork(t *testing.T) {
	if !v6LoopbackAvailable(t) {
		t.Skip("no IPv6 loopback")
	}
	a, b, pubB := startV6Engines(t, "", "")
	openRelayStream(t, a, b)

	waitFor(t, 15*time.Second, func() bool {
		return hasDirect(a, pubB) && hasDirect(b, a.pub)
	})
	assertDirectFamily(t, a, pubB, true)
	assertDirectFamily(t, b, a.pub, true)

	// The loser was cancelled, not failed: no seed failure is recorded, and the
	// trace says why the v4 attempt ended.
	if got := a.relayKCPPairFor(pubB).seedFailures.Load(); got != 0 {
		t.Fatalf("seed failures = %d, want 0 (the v4 attempt was cancelled, not failed)", got)
	}
	if !traceHas(a.directConn(pubB), "cancelled") {
		t.Fatalf("trace = %v, want a line naming the cancelled family", a.directConn(pubB).traceLines())
	}
	if got := a.directConn(pubB).lastErrOf(); got != "" {
		t.Fatalf("lastErr = %q, want empty after the win", got)
	}
}

// TestPunchBothFamiliesFailBacksOff: with both families blind the round must
// register nothing and leave the punch in backoff — not spin retrying.
func TestPunchBothFamiliesFailBacksOff(t *testing.T) {
	if !v6LoopbackAvailable(t) {
		t.Skip("no IPv6 loopback")
	}
	// Each side reports a *different* reserved public v4 address, so the
	// hairpin rule does not divert the dial to the peer's reachable local
	// candidate, and both sides advertise a v6 blackhole: every family's seed
	// is unreachable in both directions.
	a, b, pubB := startV6Engines(t, "192.0.2.1:9", "192.0.2.2:9")
	a.v6Announce, b.v6Announce = blackholeV6, blackholeV6
	openRelayStream(t, a, b)

	waitFor(t, 15*time.Second, func() bool {
		dc := a.getDirect(pubB)
		return dc != nil && dc.hasFailed()
	})
	dc := a.getDirect(pubB)
	if dc.isUp() {
		t.Fatal("a round with both families blind registered a direct path")
	}
	if got := dc.stateName(); got != "backoff" {
		t.Fatalf("state = %q, want backoff after a round where every family failed", got)
	}
	if got := dc.lastErrOf(); got == "" {
		t.Fatal("a failed round must keep its reason")
	}
}
