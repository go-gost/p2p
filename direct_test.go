package main

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestMain shortens the direct punch timing for the whole package. It is set
// once here, never mutated per-test, so no test writes these globals while a
// background punch/backoff goroutine reads them. The relay-only tests never
// trigger punching, so they are unaffected.
func TestMain(m *testing.M) {
	punchTimeout = 2 * time.Second
	backoffPeriod = 500 * time.Millisecond
	stunTimeout = 500 * time.Millisecond
	os.Exit(m.Run())
}

// startFakeSTUN runs an in-process STUN server. When mapped is non-empty it
// returns that fixed address as the XOR-MAPPED-ADDRESS (e.g. an unreachable
// blackhole for the timeout path); otherwise it reflects the sender's source
// address (loopback for the in-process tests).
func startFakeSTUN(t *testing.T, mapped string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := buf[:n]
			if n < 20 || binary.BigEndian.Uint16(req[0:2]) != 0x0001 {
				continue
			}
			conn.WriteToUDP(mappedResponse(req, addr, mapped), addr)
		}
	}()
	return conn.LocalAddr().String()
}

func mappedResponse(req []byte, addr *net.UDPAddr, mapped string) []byte {
	ip := addr.IP.To4()
	port := uint16(addr.Port)
	if mapped != "" {
		u, err := net.ResolveUDPAddr("udp4", mapped)
		if err != nil {
			return nil
		}
		ip, port = u.IP.To4(), uint16(u.Port)
	}
	resp := make([]byte, 0, 32)
	resp = append(resp, 0x01, 0x01)   // binding success
	resp = append(resp, 0x00, 0x0c)   // length
	resp = append(resp, req[4:20]...) // cookie + transaction ID
	resp = append(resp, 0x00, 0x20)   // XOR-MAPPED-ADDRESS
	resp = append(resp, 0x00, 0x08)   // attribute length
	resp = append(resp, 0x00, 0x01)   // reserved + family IPv4
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port^uint16(0x2112A442>>16))
	resp = append(resp, pb[:]...)
	var xaddr [4]byte
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], 0x2112A442)
	for i := 0; i < 4; i++ {
		xaddr[i] = ip[i] ^ cookie[i]
	}
	resp = append(resp, xaddr[:]...)
	return resp
}

// hasDirect reports whether an engine has an established direct session to peer.
func hasDirect(e *Engine, peer derpclient.PublicKey) bool {
	dc := e.getDirect(peer)
	return dc != nil && dc.session() != nil
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func roundTrip(t *testing.T, c net.Conn, payload string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != payload {
		t.Fatalf("round trip = %q, want %q", buf, payload)
	}
}

// TestDirectPunchRoundTrip proves that once a hole is punched, traffic flows
// over the direct path even after the relay stops forwarding data frames.
func TestDirectPunchRoundTrip(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
	defer engineA.Close()
	defer engineB.Close()

	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// Establish the relay session (triggers hole punching on both sides).
	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()

	waitFor(t, 5*time.Second, func() bool {
		return hasDirect(engineA, pubB) && hasDirect(engineB, engineA.pub)
	})

	// Cut relay data frames; control frames still flow. The direct path must
	// now carry the traffic.
	rs.setDropData(true)

	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	roundTrip(t, s2, "ping!")
}

// TestDirectSurvivesPunchTimeout proves the direct session outlives the
// priming deadline. The deadline set during the KCP priming round-trip must be
// cleared, or the first smux read after it expires kills the session (a
// ~10s-flap in production). Traffic must still flow over the direct path after
// sleeping past the (test-shortened) punchTimeout.
func TestDirectSurvivesPunchTimeout(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
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

	// Sleep past punchTimeout (2s in tests). With the deadline left set, the
	// session dies here; with it cleared, smux keepalive holds it up.
	time.Sleep(3 * time.Second)

	// Cut relay data; only a still-alive direct path can carry this.
	rs.setDropData(true)
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatalf("open after punchTimeout: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "still alive")
}

// TestDirectFallbackToRelay proves that after the direct session is torn down,
// new streams fall back to the relay path.
func TestDirectFallbackToRelay(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
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

	// Tear down A's direct session; a new stream must fall back to relay.
	engineA.directConn(pubB).teardown()

	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	roundTrip(t, s2, "still works")
}

// TestDirectLocalCandidateSameNetwork proves that peers on the same network
// still punch directly even when the STUN-mapped public address is a blackhole
// (TEST-NET-1): the local candidate is reached first.
func TestDirectLocalCandidateSameNetwork(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "192.0.2.1:9") // public candidate is unreachable
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
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
}

// TestDirectStunUnreachableStaysOnRelay proves a punch that cannot even query
// STUN leaves the relay path serving and never brings direct up.
func TestDirectStunUnreachableStaysOnRelay(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	// No STUN listener here: Lookup times out and the punch aborts.
	engineA.stunAddr, engineB.stunAddr = "192.0.2.1:9", "192.0.2.1:9"
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

	// Give the (failing) punch time to run.
	time.Sleep(2 * time.Second)

	if hasDirect(engineA, pubB) || hasDirect(engineB, engineA.pub) {
		t.Fatal("direct unexpectedly up with unreachable STUN")
	}

	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	roundTrip(t, s2, "relay only")
}

// TestRelaySessionRecoversAfterAdapterClosed reproduces the stuck state where a
// peer's relay adapter is closed (the peer process died) but stays cached: the
// next OpenStream must drop it and rebuild a fresh session instead of failing
// with "peer session closed" forever.
func TestRelaySessionRecoversAfterAdapterClosed(t *testing.T) {
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
	roundTrip(t, s, "hi")
	s.Close()

	// Simulate the peer process dying: the peer's relay adapter on A is closed
	// (marked closed but left cached), and B's DERP connection drops.
	engineA.mu.Lock()
	pc := engineA.peers[pubB]
	engineA.mu.Unlock()
	if pc == nil {
		t.Fatal("no relay adapter to peer")
	}
	pc.Close()
	engineB.Close()

	// The peer "restarts" with the same key.
	engineB2 := newEngine(url, echo, privB, slog.Default())
	defer engineB2.Close()
	engineB2.Connect()

	// The next open must rebuild A's adapter/session and reach the restarted
	// peer instead of failing with "peer session closed".
	s2, err := engineA.OpenStream(keyName(pubB))
	if err != nil {
		t.Fatalf("reopen after peer restart: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "recovered")
}

// TestPeerGoneFastFail proves that once a peer's DERP connection drops, a
// request to the (still down) peer fails fast once the relay reports it gone,
// instead of hanging until the smux keepalive timeout (~30s).
func TestPeerGoneFastFail(t *testing.T) {
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
	roundTrip(t, s, "hi")
	s.Close()

	// The peer's DERP connection drops; B is unregistered at the relay (which
	// notifies A), then stays down. A must learn the peer is gone.
	engineB.Close()
	waitFor(t, 5*time.Second, func() bool {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		_, ok := rs.clients[pubB]
		return !ok
	})
	waitFor(t, 5*time.Second, func() bool { return engineA.isGone(pubB) })

	// smux open is async (SYN is fire-and-forget), so the failure surfaces on
	// the stream. derper notifies PeerGone only once, so the gone probe must
	// tear the session down after goneProbeTimeout instead of letting the
	// request hang until the smux keepalive (~30s).
	start := time.Now()
	s2, err := engineA.OpenStream(keyName(pubB))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	type readRes struct{ err error }
	done := make(chan readRes, 1)
	go func() {
		if _, werr := s2.Write([]byte("ping")); werr != nil {
			done <- readRes{werr}
			return
		}
		_, rerr := io.ReadFull(s2, make([]byte, 4))
		done <- readRes{rerr}
	}()
	select {
	case r := <-done:
		if r.err == nil {
			t.Fatal("request to down peer unexpectedly succeeded")
		}
	case <-time.After(7 * time.Second):
		t.Fatal("request to down peer did not fail fast")
	}
	if elapsed := time.Since(start); elapsed > 7*time.Second {
		t.Fatalf("request to down peer took %v, want fast fail (~%v)", elapsed, goneProbeTimeout)
	}
}
