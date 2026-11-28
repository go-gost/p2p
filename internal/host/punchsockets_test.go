package host

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// socketsTestConn builds a sockets-mode directConn whose extra sockets bind to
// loopback, so the fake peers in these tests are reachable from every socket.
func socketsTestConn(t *testing.T, sockets int, window time.Duration) *directConn {
	t.Helper()
	dc := newFallbackTestConn(t, "sockets", 1, capsSpray)
	dc.e.stunAddr = "127.0.0.1:9"
	dc.e.punch.sprayEvery = 20 * time.Millisecond
	dc.e.punch.sockets = sockets
	dc.e.punch.socketWindow = window
	dc.e.punch.seedGrace = 20 * time.Millisecond
	return dc
}

func socketsSetStartDelay(t *testing.T, d time.Duration) {
	t.Helper()
	old := socketStartDelay
	socketStartDelay = d
	t.Cleanup(func() { socketStartDelay = old })
}

type socketsProbe struct {
	src netip.AddrPort
	at  time.Time
}

// socketsProbePeer runs a fake peer that records every seed probe it receives.
// When echoFrom is valid it answers only that one local socket, and only after
// wantSources distinct sockets have sent, so all sockets are known to the test.
func socketsProbePeer(t *testing.T, echoFrom netip.AddrPort, wantSources int) (netip.AddrPort, <-chan socketsProbe) {
	t.Helper()
	addr, probes, _ := socketsProbePeerWith(t, echoFrom, 0, wantSources)
	return addr, probes
}

// socketsProbePeerWith also supports echoing the echoIndex-th distinct socket
// (1-based) without knowing its local port in advance, and reports which source
// it answered on. A zero echoIndex disables that selector.
func socketsProbePeerWith(t *testing.T, echoFrom netip.AddrPort, echoIndex, wantSources int) (netip.AddrPort, <-chan socketsProbe, <-chan netip.AddrPort) {
	t.Helper()
	peer := mustListenUDP(t)
	probes := make(chan socketsProbe, 64)
	answered := make(chan netip.AddrPort, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		peer.Close()
	})
	go func() {
		seen := map[netip.AddrPort]bool{}
		order := []netip.AddrPort{}
		echoed := false
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
			tok, ok := planSeedToken(buf[:n])
			if !ok {
				continue
			}
			ap := src.AddrPort()
			if !seen[ap] {
				seen[ap] = true
				order = append(order, ap)
			}
			select {
			case probes <- socketsProbe{src: ap, at: time.Now()}:
			default:
			}
			if echoed || len(order) < wantSources {
				continue
			}
			answerByIndex := echoIndex > 0 && len(order) >= echoIndex && order[echoIndex-1] == ap
			if (echoFrom.IsValid() && ap == echoFrom) || answerByIndex {
				_, _ = peer.WriteToUDP(planSeedPacket(tok), src)
				answered <- ap
				echoed = true
			}
		}
	}()
	return udpAddrPort(t, peer), probes, answered
}

func socketsCollectProbes(t *testing.T, probes <-chan socketsProbe, want int) []netip.AddrPort {
	t.Helper()
	seen := map[netip.AddrPort]bool{}
	for len(seen) < want {
		select {
		case p := <-probes:
			seen[p.src] = true
		case <-time.After(time.Second):
			t.Fatalf("saw %d distinct sockets, want %d", len(seen), want)
		}
	}
	out := make([]netip.AddrPort, 0, len(seen))
	for ap := range seen {
		out = append(out, ap)
	}
	return out
}

func socketsAssertClosed(t *testing.T, ap netip.AddrPort) {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(ap))
	if err != nil {
		t.Fatalf("socket %s is still bound: %v", ap, err)
	}
	c.Close()
}

// TestPunchSocketsStartDelay catches a sockets round that sends immediately:
// the spraying peer needs the capped head start before any local socket fires.
func TestPunchSocketsStartDelay(t *testing.T) {
	socketsSetStartDelay(t, 10*time.Millisecond)
	dc := socketsTestConn(t, 1, 100*time.Millisecond)
	dc.e.punch.sprayEvery = time.Second // the test seam, not the spray interval, caps the wait
	peerAddr, probes := socketsProbePeer(t, netip.AddrPort{}, 1)
	first := mustListenUDP(t)
	defer first.Close()

	start := time.Now()
	win, _, err := dc.punchSockets(first, peerAddr)
	planSkipEPERM(t, err)
	if win != nil || !errors.Is(err, errSeedTimeout) {
		t.Fatalf("punchSockets = (%v, %v), want (nil, errSeedTimeout)", win, err)
	}
	p := <-probes
	if elapsed := p.at.Sub(start); elapsed < 8*time.Millisecond {
		t.Fatalf("first send after %s, want at least the 10ms head start", elapsed)
	}
	if elapsed := p.at.Sub(start); elapsed > 500*time.Millisecond {
		t.Fatalf("first send after %s, want the capped delay, not sprayEvery", elapsed)
	}
}

// TestPunchSocketsWinner catches a round that returns a loser or leaks the
// sockets that did not answer. The fake peer answers only one of three sockets.
func TestPunchSocketsWinner(t *testing.T) {
	socketsSetStartDelay(t, 5*time.Millisecond)
	const count = 3
	dc := socketsTestConn(t, count, time.Second)
	first := mustListenUDP(t)
	defer first.Close()
	firstAddr := udpAddrPort(t, first)
	peerAddr, probes := socketsProbePeer(t, firstAddr, count)

	win, out, err := dc.punchSockets(first, peerAddr)
	planSkipEPERM(t, err)
	if err != nil {
		t.Fatalf("punchSockets = %v, want success", err)
	}
	if win != first {
		t.Fatalf("winner = %v, want the answering socket %v", win, firstAddr)
	}
	if want := peerAddr; out.Answer != want {
		t.Fatalf("Answer = %v, want the peer %v", out.Answer, want)
	}
	if out.Token == [seedTokenLen]byte{} {
		t.Fatal("no token returned")
	}

	seen := socketsCollectProbes(t, probes, count)
	found := false
	for _, ap := range seen {
		if ap == firstAddr {
			found = true
			continue
		}
		socketsAssertClosed(t, ap)
	}
	if !found {
		t.Fatalf("the answering socket never sent: %v", seen)
	}
}

// TestPunchSocketsWindow catches a round that keeps sockets bound after every
// handshake times out: each local port must be free to bind again.
func TestPunchSocketsWindow(t *testing.T) {
	socketsSetStartDelay(t, 10*time.Millisecond)
	const count = 3
	dc := socketsTestConn(t, count, 150*time.Millisecond)
	first := mustListenUDP(t)
	defer first.Close()
	peerAddr, probes := socketsProbePeer(t, netip.AddrPort{}, count)

	win, _, err := dc.punchSockets(first, peerAddr)
	planSkipEPERM(t, err)
	if win != nil || !errors.Is(err, errSeedTimeout) {
		t.Fatalf("punchSockets = (%v, %v), want (nil, errSeedTimeout)", win, err)
	}
	for _, ap := range socketsCollectProbes(t, probes, count) {
		socketsAssertClosed(t, ap)
	}
}

// TestPunchSocketsNilFirstReturnsSentinel makes the skip self-describing: a
// missing first socket is an explicit failure, not a success-shaped zero outcome.
func TestPunchSocketsNilFirstReturnsSentinel(t *testing.T) {
	dc := socketsTestConn(t, 1, 50*time.Millisecond)
	win, _, err := dc.punchSockets(nil, netip.MustParseAddrPort("203.0.113.7:41000"))
	if win != nil || !errors.Is(err, errNoSockets) {
		t.Fatalf("punchSockets(nil) = (%v, %v), want (nil, errNoSockets)", win, err)
	}
}

// TestPunchSocketsRoundTargetsPublicCandidateNotLast pins the branch's peer
// target: a public entry before a loopback one must win, not the list's tail.
func TestPunchSocketsRoundTargetsPublicCandidateNotLast(t *testing.T) {
	socketsSetStartDelay(t, 10*time.Millisecond)
	const public = "203.0.113.7:41000"
	dc, _ := sprayTestRound(t, "sockets", public)
	dc.e.punch.sockets = 2
	dc.e.punch.socketWindow = 100 * time.Millisecond
	dc.cand <- []candidate{
		{addr: netip.MustParseAddrPort(public)},
		{addr: netip.MustParseAddrPort("127.0.0.1:9")},
	}

	if !dc.start() {
		t.Fatal("punch did not start")
	}
	waitFor(t, 5*time.Second, func() bool {
		return fallbackDiagnostics(dc).FallbackError != ""
	})
	if !sprayTraceHas(dc, "sockets 2 "+public) {
		t.Fatalf("sockets did not target the public candidate: %v", dc.traceLines())
	}
	if sprayTraceHas(dc, "sockets 2 127.0.0.1:9") {
		t.Fatalf("sockets targeted the loopback tail: %v", dc.traceLines())
	}
	if d := fallbackDiagnostics(dc); d.FallbackRounds != 1 || d.FallbackWinner != "" {
		t.Fatalf("fallback outcome = (%q, %d rounds), want (empty, 1)", d.FallbackWinner, d.FallbackRounds)
	}
}

// TestPunchSocketsNonFirstWinnerUpdatesMine is the regression for a non-first
// socket winning: the winner must be installed and announced in dc.mine ahead of
// the preserved public mapping, while the other sockets are closed.
func TestPunchSocketsNonFirstWinnerUpdatesMine(t *testing.T) {
	socketsSetStartDelay(t, 10*time.Millisecond)
	const count = 3
	const public = "203.0.113.7:41000"
	dc, _ := sprayTestRound(t, "sockets", public)
	dc.e.punch.sockets = count
	dc.e.punch.socketWindow = 2 * time.Second
	peerAddr, probes, answered := socketsProbePeerWith(t, netip.AddrPort{}, 2, count)
	fallbackTreatAsPublic(t, peerAddr) // a loopback fake peer in the public slot
	dc.cand <- []candidate{{addr: peerAddr}}

	if !dc.start() {
		t.Fatal("punch did not start")
	}
	waitFor(t, 5*time.Second, func() bool {
		return fallbackDiagnostics(dc).FallbackWinner != ""
	})
	var echoed netip.AddrPort
	select {
	case echoed = <-answered:
	default:
		t.Fatal("the fake peer never answered a socket")
	}
	if !echoed.IsValid() {
		t.Fatal("answered by an invalid local socket")
	}
	for _, ap := range socketsCollectProbes(t, probes, count) {
		if ap != echoed {
			socketsAssertClosed(t, ap)
		}
	}

	dc.mu.Lock()
	sock, mine, installed := dc.sock, append([]candidate(nil), dc.mine...), dc.peerAddr
	dc.mu.Unlock()
	if sock == nil {
		t.Fatal("no socket installed")
	}
	la, ok := sock.LocalAddr().(*net.UDPAddr)
	if !ok || la.AddrPort() != echoed {
		t.Fatalf("installed socket = %v, want the non-first winner %v", sock.LocalAddr(), echoed)
	}
	if installed != peerAddr {
		t.Fatalf("installed peer = %v, want %v", installed, peerAddr)
	}
	if len(mine) < 2 || mine[0].addr != echoed {
		t.Fatalf("mine = %v, want the winner %v first", mine, echoed)
	}
	if want := netip.MustParseAddrPort(public); mine[len(mine)-1].addr != want {
		t.Fatalf("mine = %v, want the public mapping %v last", mine, want)
	}
}

// TestPunchSocketsRoundInstallsAnswer proves the punch() sockets branch runs
// the multi-socket handshake instead of the normal seed and installs its answer.
func TestPunchSocketsRoundInstallsAnswer(t *testing.T) {
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
		return dc.isUp() || sprayTraceHas(dc, "sockets failed")
	})
	if !dc.isUp() {
		t.Fatalf("sockets did not install a direct path; trace = %v", dc.traceLines())
	}
	if !sprayTraceHas(dc, "sockets 3") {
		t.Fatalf("no sockets trace line: %v", dc.traceLines())
	}
	for _, line := range dc.traceLines() {
		if strings.HasPrefix(line, "v4 seed ") {
			t.Fatalf("normal seed ran alongside the sockets fallback: %v", dc.traceLines())
		}
	}
	dc.mu.Lock()
	sock, installed := dc.sock, dc.peerAddr
	dc.mu.Unlock()
	if sock == nil {
		t.Fatal("no socket installed")
	}
	if installed != peerAddr {
		t.Fatalf("installed peer = %v, want the sockets answer %v", installed, peerAddr)
	}
	if n := normalFailuresOf(dc); n != 0 {
		t.Fatalf("normalFailures = %d after a sockets success, want 0", n)
	}
	if n := fallbackFailuresOf(dc); n != 0 {
		t.Fatalf("fallbackFailures = %d after a sockets success, want 0", n)
	}
}

// TestPunchSocketsRoundFailureBacksOff proves a failed sockets round counts as
// a fallback failure and does not run the normal seed in the same round.
func TestPunchSocketsRoundFailureBacksOff(t *testing.T) {
	socketsSetStartDelay(t, 10*time.Millisecond)
	dc, _ := sprayTestRound(t, "sockets", "203.0.113.7:42000")
	dc.e.punch.sockets = 3
	dc.e.punch.socketWindow = 100 * time.Millisecond
	dc.cand <- sprayPublicV4(42000)

	if !dc.start() {
		t.Fatal("punch did not start")
	}
	waitFor(t, 5*time.Second, func() bool {
		return fallbackFailuresOf(dc) == 1
	})
	if n := normalFailuresOf(dc); n != 1 {
		t.Fatalf("normalFailures = %d after a sockets failure, want 1 (no new normal seed)", n)
	}
	if !sprayTraceHas(dc, "sockets failed") {
		t.Fatalf("no sockets failure trace: %v", dc.traceLines())
	}
	for _, line := range dc.traceLines() {
		if strings.HasPrefix(line, "v4 seed ") {
			t.Fatalf("normal seed ran alongside the sockets fallback: %v", dc.traceLines())
		}
	}
	if d := dc.nextPunchIn(); d <= 0 {
		t.Fatal("no backoff armed after a sockets failure")
	}
	if dc.isUp() {
		t.Fatal("a failed sockets round installed a direct path")
	}
}

// TestPunchSkipsSocketsWithoutV4Family proves the fallback is skipped when the
// round collected no v4 socket, even with a public peer candidate armed.
func TestPunchSkipsSocketsWithoutV4Family(t *testing.T) {
	dc, _ := sprayTestRound(t, "sockets", "203.0.113.7:43000")
	dc.e.stunAddr = "192.0.2.1:9" // unanswerable: no v4 family this round
	dc.cand <- sprayPublicV4(43000)

	if !dc.start() {
		t.Fatal("punch did not start")
	}
	waitFor(t, 5*time.Second, func() bool {
		return sprayTraceHas(dc, "no local candidates")
	})
	if sprayTraceHas(dc, "sockets") {
		t.Fatalf("sockets ran without a v4 socket: %v", dc.traceLines())
	}
	if n := fallbackFailuresOf(dc); n != 0 {
		t.Fatalf("fallbackFailures = %d with no sockets attempt, want 0", n)
	}
}
