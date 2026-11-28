package host

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// sprayPublicV4 is a public documentation address used only as an unreachable
// candidate: no packet sent to it is expected to come back.
func sprayPublicV4(port uint16) []candidate {
	return []candidate{{addr: netip.MustParseAddrPort(netip.AddrPortFrom(netip.MustParseAddr("203.0.113.7"), port).String())}}
}

// sprayTestRound builds a connected engine whose STUN answer is a public
// candidate, arms its spray fallback, and queues that candidate as the peer's
// announcement. The relay is real; the peer itself is driven by the tests.
func sprayTestRound(t *testing.T, mode string, mapped string) (*directConn, derpclient.PublicKey) {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(url, "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)
	e.stunAddr = startFakeSTUN(t, mapped)
	e.v6Enabled = false
	e.punch = punchSettings{
		mode: mode, afterRounds: 1, sprayPorts: 2,
		sprayEvery: 50 * time.Millisecond, socketWindow: time.Second,
		seedGrace: 100 * time.Millisecond,
	}
	peer := derpclient.PublicKey{0x55}
	dc := e.directConn(peer)
	dc.addCaps(capsInfo{Bits: capsSpray})
	dc.noteNormalSeedFailure()
	if err := e.Connect(); err != nil {
		t.Fatal(err)
	}
	return dc, peer
}

// sprayTestEchoPeer echoes every seed probe back to its source, standing in for
// a peer whose only reachable port is inside the sprayed target set.
func sprayTestEchoPeer(t *testing.T) netip.AddrPort {
	t.Helper()
	peer := mustListenUDP(t)
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		peer.Close()
	})
	go func() {
		buf := make([]byte, 128)
		for {
			select {
			case <-done:
				return
			default:
			}
			if err := peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				return
			}
			n, src, err := peer.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if _, ok := planSeedToken(buf[:n]); ok {
				_, _ = peer.WriteToUDP(buf[:n], src)
			}
		}
	}()
	return udpAddrPort(t, peer)
}

// spraySetTargets replaces the random port generator with a controlled set and
// records the address it was asked to spray. The original is restored at cleanup.
func spraySetTargets(t *testing.T, ip *netip.Addr, n *int, targets []netip.AddrPort) {
	t.Helper()
	old := randomPortTargetsFn
	randomPortTargetsFn = func(gotIP netip.Addr, gotN int) []netip.AddrPort {
		*ip, *n = gotIP, gotN
		return targets
	}
	t.Cleanup(func() { randomPortTargetsFn = old })
}

// sprayTraceHas reports whether any punch-trace line contains want.
func sprayTraceHas(dc *directConn, want string) bool {
	for _, line := range dc.traceLines() {
		if strings.Contains(line, want) {
			return true
		}
	}
	return false
}

func TestRandomPortTargets(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	got := randomPortTargets(ip, 1000)
	if len(got) != 1000 {
		t.Fatalf("len = %d, want 1000", len(got))
	}
	seen := map[uint16]bool{}
	for _, ap := range got {
		if ap.Addr() != ip {
			t.Fatalf("address = %v, want %v", ap.Addr(), ip)
		}
		p := ap.Port()
		if p < 1024 || p > 65535 || seen[p] {
			t.Fatalf("port = %d, want a unique port in [1024, 65535]", p)
		}
		seen[p] = true
	}
}

func TestRandomPortTargetsClamps(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	if got := randomPortTargets(ip, 5000); len(got) != 2048 {
		t.Fatalf("len = %d, want the 2048 clamp", len(got))
	}
	if got := randomPortTargets(ip, 0); len(got) != 0 {
		t.Fatalf("len = %d for n=0, want 0", len(got))
	}
}

func TestPunchSprayHitsOneTarget(t *testing.T) {
	ours := mustListenUDP(t)
	defer ours.Close()
	peerAddr := sprayTestEchoPeer(t)

	dc := newFallbackTestConn(t, "spray", 1, capsSpray)
	dc.e.punch.sprayPorts = 3
	dc.e.punch.sprayEvery = 50 * time.Millisecond
	dc.e.punch.socketWindow = 2 * time.Second
	dc.e.punch.seedGrace = 100 * time.Millisecond
	var gotIP netip.Addr
	var gotN int
	spraySetTargets(t, &gotIP, &gotN, []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.9:1"), peerAddr,
	})

	// The announced endpoint is a dead public address: only the sprayed set can
	// reach the fake peer.
	announced := netip.MustParseAddrPort("203.0.113.7:40000")
	out, err := dc.punchSpray(ours, announced, announced.Addr())
	if err != nil {
		t.Fatalf("punchSpray = %v, want success", err)
	}
	if want := peerAddr; out.Answer != want {
		t.Fatalf("Answer = %v, want the sprayed peer %v", out.Answer, want)
	}
	if out.Token == [seedTokenLen]byte{} {
		t.Fatal("no token returned")
	}
	if want := announced.Addr(); gotIP != want {
		t.Fatalf("sprayed IP = %v, want %v", gotIP, want)
	}
	if gotN != 3 {
		t.Fatalf("sprayPorts = %d, want 3", gotN)
	}
}

// TestPunchSprayRoundInstallsAnswer proves the punch() fallback uses the v4
// family socket, aims at the public candidate's address, and skips the normal
// seed when a spray succeeds.
func TestPunchSprayRoundInstallsAnswer(t *testing.T) {
	mapped := "203.0.113.7:41000"
	dc, _ := sprayTestRound(t, "spray", mapped)
	peerAddr := sprayTestEchoPeer(t)
	var gotIP netip.Addr
	var gotN int
	spraySetTargets(t, &gotIP, &gotN, []netip.AddrPort{peerAddr})
	dc.cand <- sprayPublicV4(41000)

	if !dc.start() {
		t.Fatal("punch did not start")
	}
	waitFor(t, 4*time.Second, func() bool {
		return dc.isUp() || sprayTraceHas(dc, "spray failed")
	})

	if !dc.isUp() {
		t.Fatalf("spray did not install a direct path; trace = %v", dc.traceLines())
	}
	if want := netip.MustParseAddr("203.0.113.7"); gotIP != want {
		t.Fatalf("sprayed IP = %v, want the announced candidate's %v", gotIP, want)
	}
	if gotN != 2 {
		t.Fatalf("sprayPorts = %d, want 2", gotN)
	}
	if !sprayTraceHas(dc, "spray") {
		t.Fatalf("no spray trace line: %v", dc.traceLines())
	}
	for _, line := range dc.traceLines() {
		if strings.HasPrefix(line, "v4 seed ") {
			t.Fatalf("normal seed ran alongside the spray: %v", dc.traceLines())
		}
	}
	dc.mu.Lock()
	sock, installed := dc.sock, dc.peerAddr
	dc.mu.Unlock()
	if sock == nil {
		t.Fatal("no socket installed")
	}
	if installed != peerAddr {
		t.Fatalf("installed peer = %v, want the spray answer %v", installed, peerAddr)
	}
	if n := normalFailuresOf(dc); n != 0 {
		t.Fatalf("normalFailures = %d after a spray success, want 0", n)
	}
	if n := fallbackFailuresOf(dc); n != 0 {
		t.Fatalf("fallbackFailures = %d after a spray success, want 0", n)
	}
}

// TestPunchSprayRoundFailureBacksOff proves a failed spray counts as a fallback
// failure and does not run the normal seed in the same round.
func TestPunchSprayRoundFailureBacksOff(t *testing.T) {
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
		return fallbackFailuresOf(dc) == 1
	})

	if n := normalFailuresOf(dc); n != 1 {
		t.Fatalf("normalFailures = %d after a spray failure, want 1 (no new normal seed)", n)
	}
	if !sprayTraceHas(dc, "spray failed") {
		t.Fatalf("no spray failure trace: %v", dc.traceLines())
	}
	for _, line := range dc.traceLines() {
		if strings.HasPrefix(line, "v4 seed ") {
			t.Fatalf("normal seed ran alongside the spray: %v", dc.traceLines())
		}
	}
	if d := dc.nextPunchIn(); d <= 0 {
		t.Fatalf("no backoff armed after a spray failure")
	}
	if dc.isUp() {
		t.Fatal("a failed spray installed a direct path")
	}
}

// TestPunchSprayFailureReleasesSocket proves a failed spray closes the socket
// detached from the round's families: its local port must be bindable again.
func TestPunchSprayFailureReleasesSocket(t *testing.T) {
	dc, _ := sprayTestRound(t, "spray", "203.0.113.7:45000")
	dc.e.punch.socketWindow = 400 * time.Millisecond
	sink := mustListenUDP(t)
	defer sink.Close()
	source := make(chan netip.AddrPort, 1)
	go func() {
		buf := make([]byte, 128)
		for {
			_, src, err := sink.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case source <- src.AddrPort():
			default:
			}
		}
	}()
	var gotIP netip.Addr
	var gotN int
	spraySetTargets(t, &gotIP, &gotN, []netip.AddrPort{udpAddrPort(t, sink)})
	dc.cand <- sprayPublicV4(45000)

	if !dc.start() {
		t.Fatal("punch did not start")
	}
	waitFor(t, 4*time.Second, func() bool {
		return fallbackFailuresOf(dc) == 1
	})
	var addr netip.AddrPort
	select {
	case addr = <-source:
	case <-time.After(time.Second):
		t.Fatal("no spray probe reached the sink")
	}
	rebound, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Fatalf("spray socket %s is still bound after a failed spray: %v", addr, err)
	}
	rebound.Close()
}

// TestPunchSkipsSprayWithoutV4Family proves the fallback is skipped when the
// round could not collect a v4 socket, even with a public peer candidate armed.
func TestPunchSkipsSprayWithoutV4Family(t *testing.T) {
	dc, _ := sprayTestRound(t, "spray", "203.0.113.7:43000")
	dc.e.stunAddr = "192.0.2.1:9" // unanswerable: no v4 family this round
	var called sync.Once
	var sprayed bool
	old := randomPortTargetsFn
	randomPortTargetsFn = func(ip netip.Addr, n int) []netip.AddrPort {
		called.Do(func() { sprayed = true })
		return nil
	}
	t.Cleanup(func() { randomPortTargetsFn = old })
	dc.cand <- sprayPublicV4(43000)

	if !dc.start() {
		t.Fatal("punch did not start")
	}
	waitFor(t, 4*time.Second, func() bool {
		return sprayTraceHas(dc, "no local candidates")
	})

	if sprayed || sprayTraceHas(dc, "spray") {
		t.Fatalf("spray ran without a v4 socket: %v", dc.traceLines())
	}
	if n := fallbackFailuresOf(dc); n != 0 {
		t.Fatalf("fallbackFailures = %d with no spray attempt, want 0", n)
	}
}

// TestPunchOtherModesDoNotSpray proves mode "sockets" uses its own fallback and
// never the cone side's port spray.
func TestPunchOtherModesDoNotSpray(t *testing.T) {
	dc, _ := sprayTestRound(t, "sockets", "203.0.113.7:44000")
	var sprayed bool
	old := randomPortTargetsFn
	randomPortTargetsFn = func(ip netip.Addr, n int) []netip.AddrPort {
		sprayed = true
		return nil
	}
	t.Cleanup(func() { randomPortTargetsFn = old })
	dc.cand <- sprayPublicV4(44000)

	if !dc.start() {
		t.Fatal("punch did not start")
	}
	waitFor(t, 4*time.Second, func() bool {
		return fallbackFailuresOf(dc) == 1 || sprayTraceHas(dc, "spray")
	})

	if sprayed || sprayTraceHas(dc, "spray") {
		t.Fatalf("spray ran in sockets mode: %v", dc.traceLines())
	}
}
