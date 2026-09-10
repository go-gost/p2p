package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestMain shortens the direct punch timing for the whole package. It is set
// once here, never mutated per-test, so no test writes these globals while a
// background punch/backoff goroutine reads them. The relay-only tests never
// trigger punching, so they are unaffected.
func TestMain(m *testing.M) {
	punchTimeout = 2 * time.Second
	punchWaitTimeout = 2 * time.Second
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

// scriptConn is a net.Conn fed by a fixed reader; writes are discarded.
type scriptConn struct{ io.Reader }

func (scriptConn) Write(p []byte) (int, error)      { return len(p), nil }
func (scriptConn) Close() error                     { return nil }
func (scriptConn) LocalAddr() net.Addr              { return nil }
func (scriptConn) RemoteAddr() net.Addr             { return nil }
func (scriptConn) SetDeadline(time.Time) error      { return nil }
func (scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (scriptConn) SetWriteDeadline(time.Time) error { return nil }

// TestSeedHandshake covers the symmetric echo handshake: two peer ends
// complete when both directions flow; a half-open path (the peer's token
// arrives but our own echo never comes back) must fail — the false-direct
// regression this handshake exists to prevent.
func TestSeedHandshake(t *testing.T) {
	// success over a real KCP pair: both sides write first, which only works
	// because KCP buffers writes in its send window (an unbuffered transport
	// like net.Pipe would deadlock).
	sockA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sockA.Close()
	sockB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sockB.Close()
	a, err := kcp.NewConn3(0x5eed, sockB.LocalAddr(), nil, 0, 0, sockA)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := kcp.NewConn3(0x5eed, sockA.LocalAddr(), nil, 0, 0, sockB)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	errs := make(chan error, 2)
	go func() { errs <- seedHandshake(a, 5*time.Second) }()
	go func() { errs <- seedHandshake(b, 5*time.Second) }()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("seedHandshake: %v", err)
		}
	}

	// half-open: peer token arrives (1 byte), then EOF — own echo never comes
	if err := seedHandshake(scriptConn{Reader: bytes.NewReader([]byte{42})}, time.Second); err == nil {
		t.Fatal("half-open seed unexpectedly succeeded")
	}
}

// TestMutualNewConn3Merge: two kcp.NewConn3 endpoints dialing each other's
// address with the same conv merge into one working bidirectional session
// without any listener — the transport-level property the mutual punch
// relies on.
func TestMutualNewConn3Merge(t *testing.T) {
	conv := uint32(0x12345678)
	sockA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sockA.Close()
	sockB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sockB.Close()

	a, err := kcp.NewConn3(conv, sockB.LocalAddr(), nil, 0, 0, sockA)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := kcp.NewConn3(conv, sockA.LocalAddr(), nil, 0, 0, sockB)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { // A writes, then reads B's reply
		defer wg.Done()
		a.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := a.Write([]byte("hello-from-A")); err != nil {
			errs <- err
			return
		}
		buf := make([]byte, 64)
		n, err := a.Read(buf)
		if err != nil {
			errs <- err
			return
		}
		if string(buf[:n]) != "hello-from-B" {
			errs <- fmt.Errorf("A got %q", buf[:n])
		}
	}()
	go func() { // B reads, then writes
		defer wg.Done()
		b.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		n, err := b.Read(buf)
		if err != nil {
			errs <- err
			return
		}
		if string(buf[:n]) != "hello-from-A" {
			errs <- fmt.Errorf("B got %q", buf[:n])
			return
		}
		if _, err := b.Write([]byte("hello-from-B")); err != nil {
			errs <- err
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestMutualKCPWithSmux: smux over a mutual KCP pair, roles by key order
// (external to who dialed), streams in both directions.
func TestMutualKCPWithSmux(t *testing.T) {
	conv := uint32(0x9abcdef0)
	sockA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sockA.Close()
	sockB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sockB.Close()

	a, err := kcp.NewConn3(conv, sockB.LocalAddr(), nil, 0, 0, sockA)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := kcp.NewConn3(conv, sockA.LocalAddr(), nil, 0, 0, sockB)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	seeds := make(chan error, 2)
	go func() { seeds <- seedHandshake(a, 3*time.Second) }()
	go func() { seeds <- seedHandshake(b, 3*time.Second) }()
	for i := 0; i < 2; i++ {
		if err := <-seeds; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	cfg := smux.DefaultConfig()
	sessA, err := smux.Client(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sessA.Close()
	sessB, err := smux.Server(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sessB.Close()

	accepted := make(chan *smux.Stream, 1)
	go func() {
		s, err := sessB.AcceptStream()
		if err != nil {
			t.Errorf("B accept: %v", err)
			return
		}
		accepted <- s
	}()
	s1, err := sessA.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	bs := <-accepted
	defer bs.Close()

	s1.SetDeadline(time.Now().Add(5 * time.Second))
	bs.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := s1.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(bs, buf); err != nil {
		t.Fatalf("B read: %v", err)
	}
	if _, err := bs.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(s1, buf); err != nil {
		t.Fatalf("A read: %v", err)
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

// TestDirectRepunchAfterSessionDeath proves that once a direct session dies on
// both sides (as it does after an idle keepalive timeout), the pair can
// re-punch: the accepting side must reset its state when its accept loop ends,
// or it never answers the re-punch candidates and the direct path is lost for
// good. This is the bug behind "punch succeeded but the forward re-punched".
func TestDirectRepunchAfterSessionDeath(t *testing.T) {
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

	// Simulate the idle-keepalive death: close the smux session on both sides.
	// Each side's accept loop ends and markDead must reset the state.
	for _, e := range []*Engine{engineA, engineB} {
		peer := pubB
		if e == engineB {
			peer = engineA.pub
		}
		dc := e.directConn(peer)
		dc.mu.Lock()
		sess := dc.sess
		dc.mu.Unlock()
		if sess != nil {
			sess.Close()
		}
	}
	waitFor(t, 5*time.Second, func() bool {
		dcA := engineA.directConn(pubB)
		dcA.mu.Lock()
		a := dcA.state
		dcA.mu.Unlock()
		dcB := engineB.directConn(engineA.pub)
		dcB.mu.Lock()
		b := dcB.state
		dcB.mu.Unlock()
		return a == directNone && b == directNone
	})

	// Cut relay data; only a re-punched direct path can carry this.
	rs.setDropData(true)
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatalf("open after session death: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "re-punched")
}

// TestDirectRepunchAfterMissedPeerGone proves that when a peer restarts and
// its PeerGone is missed (the other side still holds a stale directUp
// session), the re-punch still succeeds: the stale side must reset on fresh
// candidates instead of ignoring them.
func TestDirectRepunchAfterMissedPeerGone(t *testing.T) {
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

	// Simulate a missed PeerGone: A's direct session is torn down (the peer
	// "restarted"), but B still holds its stale directUp session.
	engineA.directConn(pubB).teardown()

	// Cut relay data; only a re-punched direct path can carry this. B must
	// reset its stale session on A's fresh candidates.
	rs.setDropData(true)
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatalf("open after missed peer gone: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "re-punched after missed peer gone")
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

// TestSameCandidates covers the de-duplication that keeps a re-announced
// candidate list from being mistaken for a fresh punch (and from ping-ponging).
func TestSameCandidates(t *testing.T) {
	a := []candidate{
		{addr: netip.MustParseAddrPort("10.0.0.1:1")},
		{addr: netip.MustParseAddrPort("1.2.3.4:5")},
	}
	same := []candidate{
		{addr: netip.MustParseAddrPort("10.0.0.1:1")},
		{addr: netip.MustParseAddrPort("1.2.3.4:5")},
	}
	if !sameCandidates(a, same) {
		t.Fatal("identical lists compared unequal")
	}
	if sameCandidates(a, a[:1]) || sameCandidates(a, nil) || sameCandidates(nil, nil) {
		t.Fatal("shorter or empty list compared equal")
	}
	diff := []candidate{
		{addr: netip.MustParseAddrPort("10.0.0.1:2")},
		{addr: netip.MustParseAddrPort("1.2.3.4:5")},
	}
	if sameCandidates(a, diff) {
		t.Fatal("different endpoints compared equal")
	}
}

// TestDirectPunchStaggeredStart covers the late-start case: A punches while B
// is down, then B starts and punches. A must end up with B's candidates and B
// with A's so both dial. The in-process relay sends A a PeerGone when it first
// broadcasts to the absent B, which makes A fail fast and re-punch once B is up
// — so this converges here regardless of whether onCandidates answers; the
// answer (see onCandidates) removes the wasted round that the real deployment
// shows (a late peer waiting out punchTimeout). This test is the scenario
// guard, not a strict guard on the answer.
func TestDirectPunchStaggeredStart(t *testing.T) {
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
	// A punches alone: nothing answers, so it sits in its candidate wait.
	engineA.maybeStartDirect(pubB)
	time.Sleep(300 * time.Millisecond)

	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}
	// B starts late; its candidates reach A mid-wait, and A must answer.
	engineB.maybeStartDirect(engineA.pub)

	waitFor(t, 5*time.Second, func() bool {
		return hasDirect(engineA, pubB) && hasDirect(engineB, engineA.pub)
	})

	// Cut relay data; only the (re-punched) direct path can carry this.
	rs.setDropData(true)
	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatalf("open on direct after staggered start: %v", err)
	}
	defer s.Close()
	roundTrip(t, s, "staggered-direct")
}
