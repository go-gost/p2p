package main

import (
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// v6LoopbackAvailable reports whether this host can bind an IPv6 loopback UDP
// socket. The IPv6 integration tests skip where it cannot (no v6 stack).
func v6LoopbackAvailable(t *testing.T) bool {
	t.Helper()
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func loopbackV6() *net.UDPAddr { return &net.UDPAddr{IP: net.IPv6loopback} }

// assertDirectFamily checks the family of a peer's dialed direct endpoint.
func assertDirectFamily(t *testing.T, e *Engine, peer derpclient.PublicKey, v6 bool) {
	t.Helper()
	dc := e.getDirect(peer)
	if dc == nil {
		t.Fatal("no direct conn")
	}
	dc.mu.Lock()
	addr := dc.peerAddr
	dc.mu.Unlock()
	if got := addr.Addr().Is6(); got != v6 {
		t.Fatalf("direct family v6=%v, want v6=%v (peerAddr %s)", got, v6, addr)
	}
}

// TestEncodeCandidatesFamily covers the family-aware codec: a mixed list round
// trips with the right family byte per entry, a legacy v4-only frame still
// decodes, and an unknown family is still rejected.
func TestEncodeCandidatesFamily(t *testing.T) {
	in := []candidate{
		{addr: netip.MustParseAddrPort("192.0.2.1:1234")},
		{addr: netip.MustParseAddrPort("[2001:db8::5]:5678")},
		{addr: netip.MustParseAddrPort("[::1]:9")},
	}
	enc := encodeCandidates(in)
	// Layout: [count] [4][6B] [6][18B] [6][18B].
	if enc[0] != 3 || enc[1] != 4 || enc[8] != 6 || enc[27] != 6 {
		t.Fatalf("unexpected encoding: % x", enc)
	}
	got, err := decodeCandidates(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(in) {
		t.Fatalf("round trip length = %d, want %d", len(got), len(in))
	}
	for i := range in {
		if got[i].addr != in[i].addr {
			t.Fatalf("candidate %d = %s, want %s", i, got[i].addr, in[i].addr)
		}
	}

	legacy, err := decodeCandidates(encodeCandidates([]candidate{{addr: netip.MustParseAddrPort("1.2.3.4:5")}}))
	if err != nil || len(legacy) != 1 || legacy[0].addr.String() != "1.2.3.4:5" {
		t.Fatalf("legacy frame: %v %v", legacy, err)
	}
	if _, err := decodeCandidates([]byte{1, 7, 0, 0, 0, 0}); err == nil {
		t.Fatal("unknown candidate family accepted")
	}

	// A v4-mapped address is normalized to a real IPv4 (family 4) on encode, so
	// the family-4 branch of the codec is exercised end to end.
	mapped, err := decodeCandidates(encodeCandidates([]candidate{{addr: netip.MustParseAddrPort("[::ffff:192.0.2.1]:1234")}}))
	if err != nil {
		t.Fatalf("v4-mapped encode: %v", err)
	}
	if len(mapped) != 1 || mapped[0].addr != netip.MustParseAddrPort("192.0.2.1:1234") {
		t.Fatalf("v4-mapped normalize = %v, want [192.0.2.1:1234]", mapped)
	}
}

// TestV6Addrs covers the v6 filter that drives family selection.
func TestV6Addrs(t *testing.T) {
	cands := []candidate{
		{addr: netip.MustParseAddrPort("1.2.3.4:5")},
		{addr: netip.MustParseAddrPort("[2001:db8::1]:6")},
		{addr: netip.MustParseAddrPort("[::1]:7")},
	}
	got := v6Addrs(cands)
	want := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::1]:6"),
		netip.MustParseAddrPort("[::1]:7"),
	}
	if len(got) != len(want) {
		t.Fatalf("v6Addrs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("v6Addrs[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

// TestCapsBitfieldIdempotent: capability bits accumulate (OR), a repeated frame
// is a no-op, and an unknown bit does not disturb a known one.
func TestCapsBitfieldIdempotent(t *testing.T) {
	e := newTestEngine(t)
	peerPriv, peerPub, _ := derpclient.Generate()
	dc := e.directConn(peerPub)

	send := func(bits uint8) {
		t.Helper()
		sealed := peerPriv.SealTo(e.pub, []byte{bits})
		e.handleControl(peerPub, append([]byte{ctrlCaps}, sealed...))
	}

	send(capsIPv6)
	if !dc.supports(capsIPv6) {
		t.Fatal("capsIPv6 not recorded")
	}
	send(capsIPv6) // idempotent
	send(0x80)     // an unknown bit
	dc.mu.Lock()
	caps := dc.peerCaps
	dc.mu.Unlock()
	if caps != capsIPv6|0x80 {
		t.Fatalf("peerCaps = %#x, want %#x", caps, capsIPv6|0x80)
	}
}

// TestCapsUnknownKindIgnored pins backward compatibility: an unknown control
// kind and a malformed caps box leave the direct state untouched — exactly how
// an older host treats ctrlCaps.
func TestCapsUnknownKindIgnored(t *testing.T) {
	e := newTestEngine(t)
	_, peerPub, _ := derpclient.Generate()
	dc := e.directConn(peerPub)

	e.handleControl(peerPub, []byte{0x7f, 1, 2, 3})                          // unknown kind
	e.handleControl(peerPub, append([]byte{ctrlCaps}, []byte("garbage")...)) // bad box

	dc.mu.Lock()
	caps, state := dc.peerCaps, dc.state
	dc.mu.Unlock()
	if caps != 0 || state != directNone {
		t.Fatalf("state changed: caps=%#x state=%v", caps, state)
	}
}

// TestDirectDisabledNoPunch: the --direct master switch suppresses punching even
// when a STUN server and a v6 egress are configured.
func TestDirectDisabledNoPunch(t *testing.T) {
	e := newTestEngine(t)
	_, peer, _ := derpclient.Generate()
	e.direct = false
	e.stunAddr = "127.0.0.1:3478"
	e.v6Addr = loopbackV6()

	e.maybeStartDirect(peer)
	if dc := e.getDirect(peer); dc != nil {
		t.Fatal("punch started with direct disabled")
	}
}

// TestDirectV6NoSTUN: with a usable IPv6 egress and no STUN server at all, the
// pair still punches a direct path — v6 is independent of --stun. Both peers
// bind loopback, so v6 is reachable.
func TestDirectV6NoSTUN(t *testing.T) {
	if !v6LoopbackAvailable(t) {
		t.Skip("no IPv6 loopback")
	}
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.v6Addr, engineB.v6Addr = loopbackV6(), loopbackV6()
	defer engineA.Close()
	defer engineB.Close()

	engineA.Connect()
	engineB.Connect()

	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()

	waitFor(t, 5*time.Second, func() bool {
		return hasDirect(engineA, pubB) && hasDirect(engineB, engineA.pub)
	})
	assertDirectFamily(t, engineA, pubB, true)
	assertDirectFamily(t, engineB, engineA.pub, true)

	// Only a live direct path can carry this once relay data is cut.
	rs.setDropData(true)
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	roundTrip(t, s2, "v6")
}

// TestDirectV6FallbackToV4: both peers offer v6, but B advertises an
// unreachable v6. A dials that blackhole and never reaches B, while B's packets
// to A's real loopback are dropped by A's strict source filter (A's session is
// bound to the advertised blackhole). Both seeds fail, so both converge on v4
// in the same round instead of waiting out a whole backoff.
func TestDirectV6FallbackToV4(t *testing.T) {
	if !v6LoopbackAvailable(t) {
		t.Skip("no IPv6 loopback")
	}
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
	engineA.v6Addr, engineB.v6Addr = loopbackV6(), loopbackV6()
	engineB.v6Announce = func(port uint16) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), port)
	}
	defer engineA.Close()
	defer engineB.Close()

	engineA.Connect()
	engineB.Connect()

	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()

	waitFor(t, 10*time.Second, func() bool {
		return hasDirect(engineA, pubB) && hasDirect(engineB, engineA.pub)
	})
	assertDirectFamily(t, engineA, pubB, false)
	assertDirectFamily(t, engineB, engineA.pub, false)

	rs.setDropData(true)
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	roundTrip(t, s2, "v4 fallback")
}

// TestDirectNoCandidateSourceRelayOnly: with neither STUN nor a v6 egress,
// nothing is punched (no wasted attempt) and the relay serves traffic.
func TestDirectNoCandidateSourceRelayOnly(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()

	engineA.Connect()
	engineB.Connect()

	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "relay only")
	s.Close()

	if attempts, _, _, _ := engineA.stats.snapshot(); attempts != 0 {
		t.Fatalf("punchAttempts = %d, want 0 with no candidate source", attempts)
	}
	if hasDirect(engineA, pubB) {
		t.Fatal("direct up with no candidate source")
	}

	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	roundTrip(t, s2, "relay still works")
}

// TestV4OnlyPeerStillDirectV4 is the backward-compat guard: A advertises v4+v6,
// B (like an older host or one without a global v6) advertises v4 only. Both
// still establish v4 direct — A's extra v6 candidate does not break B.
func TestV4OnlyPeerStillDirectV4(t *testing.T) {
	if !v6LoopbackAvailable(t) {
		t.Skip("no IPv6 loopback")
	}
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
	engineA.v6Addr = loopbackV6() // B stays v4-only
	defer engineA.Close()
	defer engineB.Close()

	engineA.Connect()
	engineB.Connect()

	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()

	waitFor(t, 5*time.Second, func() bool {
		return hasDirect(engineA, pubB) && hasDirect(engineB, engineA.pub)
	})
	assertDirectFamily(t, engineA, pubB, false)
	assertDirectFamily(t, engineB, engineA.pub, false)

	rs.setDropData(true)
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	roundTrip(t, s2, "v4 only")
}

// TestV6ProbeAddrResolves guards a regression where the probe address was
// written without brackets ("2001:4860:4860::8888:53"), so ResolveUDPAddr
// always failed with "too many colons" and detectV6Egress returned nil even on
// hosts with a usable global IPv6 egress. The direct v6 tests substitute the
// v6Egress package var, so they could not catch this.
func TestV6ProbeAddrResolves(t *testing.T) {
	if _, err := net.ResolveUDPAddr("udp6", v6ProbeAddr); err != nil {
		t.Fatalf("v6ProbeAddr %q does not resolve: %v", v6ProbeAddr, err)
	}
}
