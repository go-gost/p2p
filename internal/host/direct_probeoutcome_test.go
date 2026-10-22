package host

// What the seed round saw of the peer's side.
//
// "the seed handshake timed out" reads the same whether nothing of the peer's
// ever reached us or its probe did reach us and the round still did not come
// together. The two are different faults with different fixes — one is blocked
// before us (our own NAT, or the path), the other is our side or the peer's
// filter dropping the echo — so a failed round has to report which one it was.
//
// The field case was a phone on a carrier NAT whose probe never arrived: the
// log said "seed failed: host: seed handshake timeout" for hours, and nothing
// in it said whether the phone's packets were reaching the hub at all.

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestSeedHandshakeReportsProbeSourceOnTimeout: a handshake that times out
// still has to report that the peer's probe arrived, and from where. The
// address is what tells "the peer's packet never reached us" apart from "it
// reached us from somewhere else".
func TestSeedHandshakeReportsProbeSourceOnTimeout(t *testing.T) {
	a := mustListenUDP(t)
	advertised := mustListenUDP(t) // the address we dial; never answers
	defer a.Close()
	defer advertised.Close()

	// The peer as it is really reachable: it probes us, but never echoes our
	// own token back, so the round cannot complete.
	peer := mustListenUDP(t)
	defer peer.Close()

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		var tok [seedTokenLen]byte
		tok[0] = 0xC3
		probe := append(append([]byte(nil), seedProbeMagic[:]...), tok[:]...)
		for time.Now().Before(deadline) {
			_, _ = peer.WriteToUDP(probe, a.LocalAddr().(*net.UDPAddr))
			time.Sleep(100 * time.Millisecond)
		}
	}()

	out, err := seedHandshakeUDPToken(a, udpAddrPort(t, advertised), 700*time.Millisecond)
	if err == nil {
		t.Fatal("seedHandshakeUDPToken succeeded, want a timeout")
	}
	if want := udpAddrPort(t, peer); out.ProbeFrom != want {
		t.Fatalf("probe source = %v, want the peer's own source %v", out.ProbeFrom, want)
	}
}

// TestNoteSeedFailureRecordsNoProbeArrived: a round in which nothing of the
// peer's reached us must say so. The fault is before us — our NAT, the path,
// or the peer's network — and none of those is fixed by anything that happens
// after the packet would have arrived.
func TestNoteSeedFailureRecordsNoProbeArrived(t *testing.T) {
	dc := &directConn{}

	dc.noteSeedFailure("v4", errors.New("host: seed handshake timeout"), netip.AddrPort{})

	if got := dc.lastErrOf(); !strings.Contains(got, "no peer probe arrived") {
		t.Fatalf("lastErr = %q, want it to say that no peer probe arrived", got)
	}
	if !traceHas(dc, "no peer probe arrived") {
		t.Fatalf("trace = %v, want a line saying that no peer probe arrived", dc.traceLines())
	}
}

// TestNoteSeedFailureRecordsProbeArrived: a round in which the peer's probe
// did reach us must say so, and from where — that is the round where the rest
// of the path is the suspect, not the arrival.
func TestNoteSeedFailureRecordsProbeArrived(t *testing.T) {
	dc := &directConn{}
	from := netip.MustParseAddrPort("203.0.113.9:51000")

	dc.noteSeedFailure("v4", errors.New("host: seed handshake timeout"), from)

	if got := dc.lastErrOf(); !strings.Contains(got, "peer probe arrived from 203.0.113.9:51000") {
		t.Fatalf("lastErr = %q, want it to name the probe source", got)
	}
	if !traceHas(dc, "peer probe arrived from 203.0.113.9:51000") {
		t.Fatalf("trace = %v, want a line naming the probe source", dc.traceLines())
	}
}

// traceHas reports whether the trace holds a line containing s.
func traceHas(dc *directConn, s string) bool {
	for _, line := range dc.traceLines() {
		if strings.Contains(line, s) {
			return true
		}
	}
	return false
}

// TestPunchFailureLogsThePeerProbeSource: a failed punch round must say in
// the log whether the peer's probe arrived, and from where.
//
// This is the field case the change exists for: a phone on a carrier NAT
// whose probe never reached the hub, and a log that said only "the seed
// handshake timed out" for hours — with nothing in it to say whether the
// phone's packets were arriving at all, which is the difference between a
// path blocked before us and one that broke after the arrival.
func TestPunchFailureLogsThePeerProbeSource(t *testing.T) {
	// The peer as it is really reachable: it probes us, but never echoes our
	// token, so the round cannot complete.
	responder := mustListenUDP(t)
	defer responder.Close()
	go func() {
		buf := make([]byte, 64)
		var tok [seedTokenLen]byte
		tok[0] = 0xC3
		probe := append(append([]byte(nil), seedProbeMagic[:]...), tok[:]...)
		for {
			n, src, err := responder.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < len(seedProbeMagic) {
				continue
			}
			_, _ = responder.WriteToUDP(probe, src)
		}
	}()

	got := runFailingPunch(t, responder.LocalAddr().String())

	if !strings.Contains(got, "probe_from="+responder.LocalAddr().String()) {
		t.Fatalf("the log does not name the probe source:\n%s", got)
	}
}

// TestPunchFailureLogsThatNoPeerProbeArrived: the other half of the same
// distinction — a round in which nothing of the peer's reached us must say so
// in the log, so a reader does not have to guess which of the two faults it
// was.
func TestPunchFailureLogsThatNoPeerProbeArrived(t *testing.T) {
	// A socket that listens and never answers: our probe arrives, and
	// nothing ever comes back, so no peer probe is ever seen.
	silent := mustListenUDP(t)
	defer silent.Close()

	got := runFailingPunch(t, silent.LocalAddr().String())

	if !strings.Contains(got, "probe_from=(none)") {
		t.Fatalf("the log does not say that no peer probe arrived:\n%s", got)
	}
}

// runFailingPunch runs a punch round that cannot complete — the peer's public
// endpoint is peerAddr, and the round is over by the time it returns — and
// returns the engine's log.
//
// Our own STUN reports a blackhole under a different address, so the peer
// never probes us and the round under test is the only one that happens.
func runFailingPunch(t *testing.T, peerAddr string) string {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)
	peerStun := startFakeSTUN(t, peerAddr)
	ourStun := startFakeSTUN(t, "192.0.2.1:9")

	// The seed timeout stays at its production value: it is a package var the
	// engine's punch goroutine reads, so a test that shortened it would race
	// with that goroutine on the way out.

	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	logs := &safeBuffer{}
	engineA := newEngine(url, "", privA, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(engineA.Close)
	engineB := newEngine(url, echo, privB, slog.Default())
	t.Cleanup(engineB.Close)
	engineA.stunAddr, engineB.stunAddr = ourStun, peerStun

	engineA.Connect()
	engineB.Connect()

	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()

	waitFor(t, 10*time.Second, func() bool {
		return strings.Contains(logs.String(), "seed failed")
	})
	return logs.String()
}

// safeBuffer is a log sink the test can read while the engine writes to it.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
