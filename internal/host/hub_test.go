package host

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
	"time"

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

			l := newLink(spoke, pubH)
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

	la := newLink(engineA, pubB)
	engineA.addLink(la)
	defer func() {
		engineA.removeLink(la)
		la.close()
	}()
	lb := newLink(engineB, pubA)
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
