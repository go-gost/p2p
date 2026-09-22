package host

import (
	"bytes"
	"log/slog"
	"net"
	"testing"

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

// TestDatagramDialNoticeOpensWhenOpener: the dial notice makes a udp-target
// holder open a datagram stream to the notifier, but only when it owns the
// smaller key (the key-order opener). No allowlist is consulted.
func TestDatagramDialNoticeOpensWhenOpener(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	var privH, privS derpclient.PrivateKey
	var pubH, pubS derpclient.PublicKey
	for { // hub owns the smaller key, so the hub is the opener
		privH, pubH, _ = derpclient.Generate()
		privS, pubS, _ = derpclient.Generate()
		if bytes.Compare(pubH[:], pubS[:]) < 0 {
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

	chS := spoke.openChannel(pubH)
	defer chS.release()
	spokeLocal := attachLocal(t, chS) // the GOST-side edge (test's end of the pipe)

	if err := spoke.sendDialUDP(pubH); err != nil {
		t.Fatal(err)
	}
	waitStream(t, chS) // the hub opened the peer edge

	go spokeLocal.Write(appendFrame(nil, []byte("hello")))
	got, err := recvDatagram(t, stub)
	if err != nil || string(got) != "hello" {
		t.Fatalf("target got %q, %v; want hello", got, err)
	}
}

// TestDatagramDialNoticeIgnoredWhenResponder: with the target holder owning the
// larger key it is the responder, so the notice must not make it open; the
// notifier (the opener) opens and the holder serves it per stream.
func TestDatagramDialNoticeIgnoredWhenResponder(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	var privH, privS derpclient.PrivateKey
	var pubH, pubS derpclient.PublicKey
	for { // spoke owns the smaller key, so the spoke is the opener
		privH, pubH, _ = derpclient.Generate()
		privS, pubS, _ = derpclient.Generate()
		if bytes.Compare(pubS[:], pubH[:]) < 0 {
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

	chS := spoke.openChannel(pubH) // the spoke is the opener: its loop opens
	defer chS.release()
	local := attachLocal(t, chS)
	if err := spoke.sendDialUDP(pubH); err != nil {
		t.Fatal(err)
	}
	waitStream(t, chS)

	go local.Write(appendFrame(nil, []byte("hello")))
	if got, err := recvDatagram(t, stub); err != nil || string(got) != "hello" {
		t.Fatalf("target got %q, %v; want hello", got, err)
	}
}

// tunToTunRoundTrip models tun-to-tun: both sides hold a GOST udp dial (a
// channel with a local edge) and neither holds a udp --target. The opener's
// ch.loop stream must be served by the responder through the channel branch --
// the absent --target must NOT refuse it -- and the gost edges must pass bytes
// both ways. smallerA forces which public key wins, so both key orders run.
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

	chA := engineA.openChannel(pubB)
	defer chA.release()
	chB := engineB.openChannel(pubA)
	defer chB.release()
	localA := attachLocal(t, chA)
	localB := attachLocal(t, chB)

	// Only the smaller key's loop opens; the larger side serves it. If the
	// responder refused tagged streams when it has no udp target, the stream
	// would never come up and this would time out.
	waitStream(t, chA)
	waitStream(t, chB)

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
// still work through the channel branch, for both public-key orders (running
// only one order would miss a broken "channel present -> no dialer" guard).
func TestTunToTunBothKeyOrders(t *testing.T) {
	t.Run("a-opener", func(t *testing.T) { tunToTunRoundTrip(t, true) })
	t.Run("b-opener", func(t *testing.T) { tunToTunRoundTrip(t, false) })
}
