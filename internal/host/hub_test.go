package host

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

// startHubStub returns a throwaway UDP socket standing in for the hub's tun
// server, plus its "udp://" target spec.
func startHubStub(t *testing.T) (*net.UDPConn, string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, "udp://" + conn.LocalAddr().String()
}

// TestSpokeReachesTargetOutlet: a spoke's udp dial reaches a peer holding a udp
// target, whatever the key order — the dialing side presents its own edge, so
// no notice and no key-order opener is involved. This is the shape a wisper
// entrypoint uses against a host with --target.
func TestSpokeReachesTargetOutlet(t *testing.T) {
	for _, spokeSmaller := range []bool{true, false} {
		name := "spoke-larger"
		if spokeSmaller {
			name = "spoke-smaller"
		}
		t.Run(name, func(t *testing.T) {
			rs := &relayServer{}
			url := rs.start(t)

			var privH, privS derpclient.PrivateKey
			var pubH, pubS derpclient.PublicKey
			for {
				privH, pubH, _ = derpclient.Generate()
				privS, pubS, _ = derpclient.Generate()
				if (bytes.Compare(pubS[:], pubH[:]) < 0) == spokeSmaller {
					break
				}
			}

			hub := newEngine(url, "", privH, slog.Default())
			spoke := newEngine(url, "", privS, slog.Default())
			defer hub.Close()
			defer spoke.Close()
			if err := hub.Connect(); err != nil {
				t.Fatal(err)
			}
			if err := spoke.Connect(); err != nil {
				t.Fatal(err)
			}
			stub, spec := startHubStub(t)
			if err := hub.addTargets([]string{spec}); err != nil {
				t.Fatal(err)
			}

			l := newLink(spoke, pubH, false)
			spoke.addLink(l)
			defer func() {
				spoke.removeLink(l)
				l.close()
			}()
			local := attachLocal(t, l)

			go local.Write(appendFrame(nil, []byte("hello")))
			got, err := recvDatagram(t, stub)
			if err != nil || string(got) != "hello" {
				t.Fatalf("target got %q, %v; want hello", got, err)
			}
		})
	}
}

// linkToHubStub builds a spoke -> hub pair over the test relay, the hub holding
// a udp target stub and the spoke holding one link to the hub (scoped or
// transparent) attached to a local edge, with the edge already established by
// one datagram. Shared by the fault-injection tests below.
func linkToHubStub(t *testing.T, scoped bool) (l *link, hub, spoke *engine) {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)

	var privH, privS derpclient.PrivateKey
	var pubH, pubS derpclient.PublicKey
	for {
		privH, pubH, _ = derpclient.Generate()
		privS, pubS, _ = derpclient.Generate()
		if bytes.Compare(pubS[:], pubH[:]) < 0 {
			break
		}
	}
	hub = newEngine(url, "", privH, slog.Default())
	spoke = newEngine(url, "", privS, slog.Default())
	t.Cleanup(func() { hub.Close(); spoke.Close() })
	if err := hub.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := spoke.Connect(); err != nil {
		t.Fatal(err)
	}
	stub, spec := startHubStub(t)
	if err := hub.addTargets([]string{spec}); err != nil {
		t.Fatal(err)
	}
	l = newLink(spoke, pubH, scoped)
	spoke.addLink(l)
	t.Cleanup(func() { spoke.removeLink(l); l.close() })
	local := attachLocal(t, l)

	// Establish the edge: one datagram through to the hub's target.
	go local.Write(appendFrame(nil, []byte("hello")))
	if _, err := recvDatagram(t, stub); err != nil {
		t.Fatalf("establish edge: %v", err)
	}
	waitFor(t, 10*time.Second, l.hasEdge)
	return l, hub, spoke
}

// TestScopedLinkEndsUnderBlackhole pins the tun fix's liveness bound: a
// session-scoped link ends when the peer path goes dead in both directions —
// the "network switch / blackhole" shape, where no frame gets through and the
// smux keepalive is dropped too — because the session's own liveness gives up.
// That end is what makes the tun consumer re-dial and re-register. The
// transparent link does the opposite: it re-presents and stays up, which is why
// it lost the registration. The bound logged here is the smux keepalive timeout.
func TestScopedLinkEndsUnderBlackhole(t *testing.T) {
	l, hub, spoke := linkToHubStub(t, true)

	// Blackhole both directions: no data frame either way, smux keepalives
	// included. This is the shape a network switch (or a silent path) leaves
	// behind, and what the relay's own watchdog cannot see.
	hub.faults.Store(newFaults(&p2p.FaultsConfig{DropData: true}))
	spoke.faults.Store(newFaults(&p2p.FaultsConfig{DropData: true}))

	start := time.Now()
	select {
	case <-l.done:
		t.Logf("session-scoped link ended %s after the path went dead (the smux keepalive bound)",
			time.Since(start).Round(time.Second))
	case <-time.After(90 * time.Second):
		t.Fatal("a session-scoped link never ended under a blackhole — the tun would not re-register")
	}
}

// TestScopedLinkSurvivesPacketLoss: under a lossy path that still carries the
// session's own keepalive, a session-scoped link does NOT end — the tun keeps
// its established session and its (still-valid) registration rather than
// flapping. The fault drops one in every two relay data frames (50% loss); the
// smux keepalive, sent every few seconds, still gets through, so the session
// survives and the link stays up.
func TestScopedLinkSurvivesPacketLoss(t *testing.T) {
	l, hub, spoke := linkToHubStub(t, true)

	hub.faults.Store(newFaults(&p2p.FaultsConfig{DropDataRate: 0.5}))
	spoke.faults.Store(newFaults(&p2p.FaultsConfig{DropDataRate: 0.5}))

	select {
	case <-l.done:
		t.Fatal("a session-scoped link ended under 50% frame loss — the tun would flap on a lossy path")
	case <-time.After(30 * time.Second):
		// survived: the session rode through the loss.
	}
}

// engineLink returns e's first link to peer; the tests that use it dial once.
func engineLink(t *testing.T, e *engine, peer derpclient.PublicKey) *link {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	ls := e.links[peer]
	if len(ls) == 0 {
		t.Fatalf("engine has no link to %s", keyName(peer))
	}
	return ls[0]
}

// waitRendezvous waits until the larger key has adopted the smaller key's
// presentation, so both links ride one shared edge. Until it settles, a datagram
// written on the larger side may ride its own provisional edge — which the
// smaller side discards — exactly like the old model's build window.
func waitRendezvous(t *testing.T, larger *link) {
	t.Helper()
	waitFor(t, 10*time.Second, func() bool { return !larger.adoptable() })
}

// tunToTunRoundTrip models tun-to-tun: both sides hold a GOST udp dial (a link
// with a local edge) and neither holds a udp --target. The larger key adopts the
// smaller's presentation — one shared edge — and the gost edges pass bytes both
// ways. smallerA forces which public key wins, so both key orders run.
func tunToTunRoundTrip(t *testing.T, smallerA bool) {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)

	var privA, privB derpclient.PrivateKey
	var pubA, pubB derpclient.PublicKey
	for {
		privA, pubA, _ = derpclient.Generate()
		privB, pubB, _ = derpclient.Generate()
		if (bytes.Compare(pubA[:], pubB[:]) < 0) == smallerA {
			break
		}
	}

	engineA := newEngine(url, "", privA, slog.Default()) // no --target
	engineB := newEngine(url, "", privB, slog.Default()) // no --target
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	la := newLink(engineA, pubB, false)
	engineA.addLink(la)
	defer func() {
		engineA.removeLink(la)
		la.close()
	}()
	lb := newLink(engineB, pubA, false)
	engineB.addLink(lb)
	defer func() {
		engineB.removeLink(lb)
		lb.close()
	}()
	localA := attachLocal(t, la)
	localB := attachLocal(t, lb)

	larger := lb
	if !smallerA {
		larger = la
	}
	waitRendezvous(t, larger)

	go localA.Write([]byte("one"))
	if got := string(readN(t, localB, 3)); got != "one" {
		t.Fatalf("A->B = %q, want one", got)
	}
	go localB.Write([]byte("two"))
	if got := string(readN(t, localA, 3)); got != "two" {
		t.Fatalf("B->A = %q, want two", got)
	}
}

// TestTunToTunBothKeyOrders: tun-to-tun with no udp target on either side must
// still work through the rendezvous (the larger key adopts the smaller's
// presentation), for both public-key orders.
func TestTunToTunBothKeyOrders(t *testing.T) {
	t.Run("a-opener", func(t *testing.T) { tunToTunRoundTrip(t, true) })
	t.Run("b-opener", func(t *testing.T) { tunToTunRoundTrip(t, false) })
}
