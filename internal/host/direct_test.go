package host

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestMain shortens the timing globals for the whole package — direct punch and
// the relay keepalive probe alike. It is set once here, never mutated per-test,
// so no test writes these globals while a background punch/backoff/keepalive
// goroutine reads them. The relay-only tests never trigger punching, so they are
// unaffected.
func TestMain(m *testing.M) {
	punchTimeout = 2 * time.Second
	punchWaitTimeout = 2 * time.Second
	backoffPeriod = 500 * time.Millisecond
	stunTimeout = 500 * time.Millisecond
	// The direct session's keepalive is the thing TestDirectSilentPeerIsNoticed
	// measures, so it runs at test speed here (production is 2s/6s).
	directSmuxKeepAliveInterval = 500 * time.Millisecond
	directSmuxKeepAliveTimeout = 2 * time.Second
	// The relay keepalive probe, shortened together so a relay that stops
	// answering is noticed at test speed. The ceiling stays several intervals
	// above the tick, as production has it (30s/45s), so an answering relay is
	// never mistaken for a silent one.
	keepAlivePeriod = 100 * time.Millisecond
	relayDeadPeriod = 400 * time.Millisecond
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
func hasDirect(e *engine, peer derpclient.PublicKey) bool {
	dc := e.getDirect(peer)
	return dc != nil && dc.session() != nil
}

// directSecureForTest reports whether an engine's direct session to peer is
// encrypted. It reads the direct session under the engine lock, then its keys
// under the session's own lock — never the session's lock while holding e.mu.
func directSecureForTest(e *engine, peer derpclient.PublicKey) bool {
	e.mu.Lock()
	dc := e.directs[peer]
	e.mu.Unlock()
	if dc == nil {
		return false
	}
	_, _, ok := dc.secure.keys()
	return ok
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

	// The direct session's tighter keepalive is negotiated, and both ends of a
	// punch run this version, so each must have seen the other's bit. The caps
	// frame rides the control channel, so it can land just after the session.
	for _, e := range []*engine{engineA, engineB} {
		peer := pubB
		if e == engineB {
			peer = engineA.pub
		}
		waitFor(t, 5*time.Second, func() bool {
			dc := e.getDirect(peer)
			return dc != nil && dc.supports(capsTightKeepalive)
		})
	}

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

// TestDirectSessionEncrypted proves the hole-punched direct path is
// end-to-end encrypted: after a direct session is up, a stream round-trips
// over it and both ends report the direct session as settled encrypted (the
// handshake ran, not just a plaintext round trip).
func TestDirectSessionEncrypted(t *testing.T) {
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

	// Bring the relay session up, which triggers the mutual punch.
	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()

	waitFor(t, 5*time.Second, func() bool {
		return hasDirect(engineA, pubB) && hasDirect(engineB, engineA.pub)
	})

	// Cut relay data; only the direct path can carry this. Its payload is sealed
	// end to end, so a successful round trip proves the ciphered transport works.
	rs.setDropData(true)
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatalf("open on direct: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "encrypted-direct")

	// A direct session is built only after its own side settled the handshake,
	// so both ends must report it encrypted once the sessions are up.
	if !directSecureForTest(engineA, pubB) {
		t.Fatal("A's direct session did not settle encrypted")
	}
	if !directSecureForTest(engineB, engineA.pub) {
		t.Fatal("B's direct session did not settle encrypted")
	}
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
	// Nothing dials afterwards — the death itself must bring the path back.
	// That is the phone's Wi-Fi ↔ cellular switch: the session dies with the
	// old interface, and without the re-punch the pair sits on the relay until
	// something dials.
	for _, e := range []*engine{engineA, engineB} {
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
	waitFor(t, 10*time.Second, func() bool {
		return directUpNow(engineA, pubB) && directUpNow(engineB, engineA.pub)
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
//
// Known flake (pre-existing, not a regression): the final roundTrip fails
// intermittently with "direct_test.go:671: timeout". Measured ~30% at main
// HEAD without -race (9 failures in 30 runs) and ~17% at d2eff96 (5 in 30, the
// last commit before the relay KCP reliability work) — so it predates both the
// relay work and the shared cryptoConn nonce draw-under-lock change in
// secure.go. It never reproduces under -race, which is why the -race gate and
// CI stay green while a plain non-race run fails roughly one time in five. Two
// contributors: (1) environmental — this sandbox intermittently denies the
// sendmmsg syscall (EPERM) under load, breaking the seed handshake; absent in
// CI/normal environments and irrelevant there. (2) A genuine pre-existing race
// in the direct plane's re-punch path: a stale-candidate dial can burn the 5s
// seedTimeout, and a peerLive false-negative on the accepting side re-arms
// instead of re-punching, so the re-punch exceeds the 2s punchWaitTimeout and
// OpenStream falls back to the relay — whose data frames this test has just
// cut. The exact interleaving of (2) is still uncharacterized; instrumentation
// shifted the timing and made it rarer. Hitting this failure: it is not your
// change, and -race hides it.
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

// TestDirectSmuxConfig: the tighter direct keepalive applies only to a peer
// that advertised it. smux answers a NOP with nothing, so a session is kept
// alive by the frames the peer sends — a peer pinging every 10s cannot keep a
// 6s timeout alive, and every direct session to it would be torn down and
// re-punched on a loop. A peer that does not set the bit gets the relay's pair,
// which is what every peer had before the tighter one existed.
func TestDirectSmuxConfig(t *testing.T) {
	tight := directSmuxConfig(true)
	if tight.KeepAliveInterval != directSmuxKeepAliveInterval || tight.KeepAliveTimeout != directSmuxKeepAliveTimeout {
		t.Fatalf("an advertising peer got %v/%v, want the direct pair %v/%v",
			tight.KeepAliveInterval, tight.KeepAliveTimeout,
			directSmuxKeepAliveInterval, directSmuxKeepAliveTimeout)
	}
	loose := directSmuxConfig(false)
	if loose.KeepAliveInterval != smuxKeepAliveInterval || loose.KeepAliveTimeout != smuxKeepAliveTimeout {
		t.Fatalf("a peer that did not advertise got %v/%v, want the relay pair %v/%v",
			loose.KeepAliveInterval, loose.KeepAliveTimeout,
			smuxKeepAliveInterval, smuxKeepAliveTimeout)
	}
}

// TestDirectSilentPeerIsNoticed: a direct session whose path goes silent must
// be given up on its own keepalive, not left looking live. The relay only
// reports a peer gone when the peer leaves the relay, which is not what a dead
// direct path is — a NAT rebinding or a route change leaves the peer present
// and the path black. Until the session is closed the peer reads as "direct"
// and a new stream is handed to the dead path instead of the relay, so the
// window is the whole point of the direct session's own (tighter) keepalive.
func TestDirectSilentPeerIsNoticed(t *testing.T) {
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

	dcA := engineA.directConn(pubB)
	dcA.mu.Lock()
	sessA := dcA.sess
	dcA.mu.Unlock()
	if sessA == nil {
		t.Fatal("A has no direct session to watch")
	}

	// B's punch socket goes away without the relay being told: from A's side
	// this is a black path, which is the case the keepalive has to cover.
	dcB := engineB.directConn(engineA.pub)
	dcB.mu.Lock()
	sockB := dcB.socket
	dcB.mu.Unlock()
	if sockB == nil {
		t.Fatal("B has no punch socket to close")
	}
	sockB.Close()

	// 1-2x the direct timeout (2s in TestMain). The relay keepalive this
	// replaced would take 30-60s, so the bound proves which one is in play.
	closed := time.Now()
	waitFor(t, 8*time.Second, func() bool { return sessA.IsClosed() })
	t.Logf("silent direct path noticed after %v (keepalive %v/%v)",
		time.Since(closed).Round(time.Millisecond), directSmuxKeepAliveInterval, directSmuxKeepAliveTimeout)
}

// TestPeerGoneKeepsLiveDirectSession: a PeerGone is a notice about the peer's
// *relay* connection, and it says nothing about the hole-punched path, which
// does not run through the relay at all. It used to tear the direct session
// down, so every blip on the peer's relay link cost a working path and a
// re-punch. The direct session answers for itself through its own keepalive.
func TestPeerGoneKeepsLiveDirectSession(t *testing.T) {
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

	dcA := engineA.directConn(pubB)
	dcA.mu.Lock()
	sessA := dcA.sess
	dcA.mu.Unlock()
	if sessA == nil {
		t.Fatal("A has no direct session to watch")
	}

	// B's relay connection goes away, so the relay reports it gone to A. B's
	// process — and with it the punch socket — stays up, which is the case the
	// direct session must survive.
	engineB.mu.Lock()
	clientB := engineB.client
	engineB.mu.Unlock()
	if clientB == nil {
		t.Fatal("B has no relay connection to drop")
	}
	clientB.Close()

	waitFor(t, 5*time.Second, func() bool { return engineA.isGone(pubB) })

	// Longer than the direct keepalive's own detection window (2x the 2s
	// timeout here): a session that survives this is genuinely alive, not just
	// unexamined.
	time.Sleep(3 * directSmuxKeepAliveTimeout)
	if sessA.IsClosed() {
		t.Fatal("a PeerGone tore down the live direct session")
	}
	if !hasDirect(engineA, pubB) {
		t.Fatal("A no longer holds the direct session")
	}

	// And it still carries traffic, with the relay out of the picture.
	rs.setDropData(true)
	s2, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatalf("open after PeerGone: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "still direct")
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

// TestPunchAndWaitDoesNotStallWhenPunchCannotStart: the punch wait is charged
// to the call that starts the punch. A peer that already failed to punch (in
// backoff) or has one in flight is not affected by a blocking wait, so waiting
// there would stall every stream open by the full punchWaitTimeout — on a
// symmetric-NAT peer, every connection over a permanent relay path.
func TestPunchAndWaitDoesNotStallWhenPunchCannotStart(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	privA, _, _ := derpclient.Generate()
	_, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineA.stunAddr = "192.0.2.1:9" // candidate source exists; the punch itself fails
	defer engineA.Close()

	engineA.Connect()

	dc := engineA.directConn(pubB)
	for _, state := range []directState{directBackoff, directUp} {
		dc.mu.Lock()
		dc.state = state
		dc.mu.Unlock()

		start := time.Now()
		if sess := engineA.punchAndWait(pubB); sess != nil {
			t.Fatalf("punchAndWait returned a session in state %d", state)
		}
		if d := time.Since(start); d > punchWaitTimeout/4 {
			t.Fatalf("punchAndWait waited %v in state %d; want an immediate nil", d, state)
		}
	}

	// An idle connection still owns the wait: that is the case the wait is for.
	dc.mu.Lock()
	dc.state = directNone
	dc.failed = false
	dc.mu.Unlock()
	if sess := engineA.punchAndWait(pubB); sess != nil {
		t.Fatal("punchAndWait returned a session for an unreachable peer")
	}
	dc.mu.Lock()
	state := dc.state
	dc.mu.Unlock()
	if state == directNone {
		t.Fatal("punchAndWait did not start a punch from directNone")
	}

	// A peer whose punch already failed does not make a later caller wait:
	// the round is started again for the background, and the caller goes on.
	dc.mu.Lock()
	dc.state = directNone
	dc.failed = true
	dc.mu.Unlock()
	start := time.Now()
	if sess := engineA.punchAndWait(pubB); sess != nil {
		t.Fatal("punchAndWait returned a session after a failed round")
	}
	if d := time.Since(start); d > punchWaitTimeout/4 {
		t.Fatalf("punchAndWait waited %v after a failed round; want an immediate nil", d)
	}
}

// TestWarmConnectsWithoutStream: warming a peer brings up its relay session
// with no tunnel stream and no punch — the answering side's case, where the
// peer must be visible in the status but nothing should be attempted on its
// behalf yet.
func TestWarmConnectsWithoutStream(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, "", privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
	defer engineA.Close()
	defer engineB.Close()

	engineA.Connect()
	engineB.Connect()

	if err := engineA.warm(pubB, false); err != nil {
		t.Fatalf("warm: %v", err)
	}

	// The peer counts as connected before any traffic: it has a path in the
	// per-peer transports, which is what a caller renders.
	if got := engineA.peerTransports()[keyName(pubB)]; got == "" {
		t.Fatalf("peerTransports = %v, want an entry for the warmed peer", engineA.peerTransports())
	}
	// Nothing was attempted for it.
	time.Sleep(200 * time.Millisecond)
	if attempts, _, _, _ := engineA.stats.snapshot(); attempts != 0 {
		t.Fatalf("punch attempts after a presence-only warm = %d, want 0", attempts)
	}
}

// TestPunchStartsWithoutStream: Punch is the dialing side's warm-up — the
// punch starts (and is mutual) with no stream ever opened.
func TestPunchStartsWithoutStream(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, "", privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
	defer engineA.Close()
	defer engineB.Close()

	engineA.Connect()
	engineB.Connect()

	if err := engineA.warm(pubB, true); err != nil {
		t.Fatalf("punch: %v", err)
	}

	// The peer answers our candidates: both sides come up, no stream opened.
	waitFor(t, 5*time.Second, func() bool {
		return hasDirect(engineA, pubB) && hasDirect(engineB, engineA.pub)
	})
}

// TestCandidatesKeepLiveSession: an announcement from a peer whose rounds keep
// failing must not tear down the session that is already carrying traffic.
// Tearing it down is what makes a pair that can punch look like a pair that
// cannot: every retry announcement kills the working path, and the round that
// replaces it fails. A round may still start — that is how a genuinely stale
// session gets repaired — but the live one keeps serving until a new punch
// succeeds and markUp replaces it.
func TestCandidatesKeepLiveSession(t *testing.T) {
	newEngine := func(state directState) (*engine, *directConn, *smux.Session) {
		e := &engine{
			direct:   true,
			stunAddr: "127.0.0.1:3478",
			log:      slog.Default(),
			stop:     make(chan struct{}),
			directs:  make(map[derpclient.PublicKey]*directConn),
			peers:    make(map[derpclient.PublicKey]*peerConn),
		}
		peer := derpclient.PublicKey{9}
		sess := newTestSess(t)
		dc := &directConn{e: e, peer: peer, sess: sess, state: state, cand: make(chan []candidate, 1)}
		e.directs[peer] = dc
		return e, dc, sess
	}
	cands := []candidate{{addr: netip.MustParseAddrPort("203.0.113.7:1234")}}

	// A live session stays live, and is still what a stream would use.
	for _, state := range []directState{directUp, directBackoff} {
		_, dc, sess := newEngine(state)
		dc.onCandidates(cands)
		if !dc.live() {
			t.Errorf("state %v: after candidates live = false, want the session untouched", state)
		}
		if sess.IsClosed() {
			t.Errorf("state %v: the live direct session was closed by an announcement", state)
		}
		if got := dc.session(); got == nil {
			t.Errorf("state %v: session() = nil, want the live session served whatever the punch state", state)
		}
	}

	// Either way a round runs: the peer is punching now, and a round is what
	// repairs a session that really is stale.
	_, dc, _ := newEngine(directBackoff)
	dc.failed = true
	dc.onCandidates(cands)
	if got := dc.stateOf(); got != directAttempting {
		t.Errorf("after candidates while backing off: state = %v, want a round started", got)
	}
}

// TestCandidatesIgnoredWhenDirectOff: the direct switch is a master gate, and
// it must hold on the inbound path too. A peer that still punches announces its
// candidates over the relay; a host with the direct path off must not start a
// round for it, or the pair ends up on a hole-punched session the switch was
// turned off to prevent.
func TestCandidatesIgnoredWhenDirectOff(t *testing.T) {
	e := &engine{
		direct:   false,
		stunAddr: "127.0.0.1:3478", // a candidate source exists; the switch, not the source, is what is off
		log:      slog.Default(),
		stop:     make(chan struct{}),
		directs:  make(map[derpclient.PublicKey]*directConn),
		peers:    make(map[derpclient.PublicKey]*peerConn),
	}
	peer := derpclient.PublicKey{9}
	dc := &directConn{e: e, peer: peer, cand: make(chan []candidate, 1)}
	e.directs[peer] = dc

	dc.onCandidates([]candidate{{addr: netip.MustParseAddrPort("203.0.113.7:1234")}})

	if got := dc.stateOf(); got != directNone {
		t.Errorf("state = %v, want directNone: the direct path is off", got)
	}
	if dc.session() != nil {
		t.Error("session() = a live session, want nil with the direct path off")
	}
	if got := dc.start(); got {
		t.Error("start() = true, want false: no round may start with the direct path off")
	}
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

// TestInboundRecoversAfterAdapterClosed: a killed adapter that stays cached must
// not leave the peer without an inbound path. The pump used to read e.peers
// directly, so it kept handing packets to the closed adapter and only an
// outbound open replaced it; a host that only receives (a reverse tunnel) then
// served nothing until it happened to dial. peerConn drops the closed adapter,
// so the peer's next inbound stream is served.
func TestInboundRecoversAfterAdapterClosed(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, echo, privA, slog.Default()) // A answers inbound
	engineB := newEngine(url, "", privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()

	engineA.Connect()
	engineB.Connect()

	// First inbound stream: A builds its adapter from the packet pump alone.
	s, err := engineB.OpenStream(keyName(pubA))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()
	waitFor(t, 5*time.Second, func() bool {
		engineA.mu.Lock()
		_, ok := engineA.peers[pubB]
		engineA.mu.Unlock()
		return ok
	})

	// Simulate the adapter dying (queue overflow, or a peer restart A was not
	// told about): closed, but left cached in e.peers.
	engineA.mu.Lock()
	pc := engineA.peers[pubB]
	engineA.mu.Unlock()
	if pc == nil {
		t.Fatal("no inbound adapter to peer")
	}
	pc.Close()

	// The peer's next inbound stream must still be served.
	s2, err := engineB.OpenStream(keyName(pubA))
	if err != nil {
		t.Fatalf("inbound open after adapter kill: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "recovered")
}

// TestPeerGoneFastFail proves that once a peer's DERP connection drops, a
// request to the (still down) peer fails fast once the relay reports it gone,
// instead of hanging until the smux keepalive timeout (~30s). With forced
// encryption the open itself is refused — the down peer cannot re-negotiate,
// and there is no plaintext fallback to serve it.
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

	// The peer is down, so its security session cannot be re-negotiated and the
	// open must be refused quickly (bounded by goneHandshakeTimeout once the
	// relay reports it gone) instead of hanging until the smux keepalive (~30s).
	start := time.Now()
	if _, err := engineA.OpenStream(keyName(pubB)); err == nil {
		t.Fatal("open to a down peer succeeded, want a fast refusal")
	} else if !errors.Is(err, errEncryptionRequired) {
		t.Fatalf("open to a down peer: %v, want errEncryptionRequired", err)
	}
	if elapsed := time.Since(start); elapsed > 7*time.Second {
		t.Fatalf("open to a down peer took %v, want a fast refusal (~%v)", elapsed, goneHandshakeTimeout)
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

// newSlotConn builds a bare directConn with an engine whose punch cannot start
// (no STUN answers), for tests that only exercise the candidate exchange.
func newSlotConn(t *testing.T) *directConn {
	t.Helper()
	peer := derpclient.PublicKey{7}
	e := &engine{
		direct:   true,
		stunAddr: "127.0.0.1:3478",
		log:      slog.Default(),
		stop:     make(chan struct{}),
		directs:  make(map[derpclient.PublicKey]*directConn),
		peers:    make(map[derpclient.PublicKey]*peerConn),
	}
	dc := &directConn{e: e, peer: peer, cand: make(chan []candidate, 1)}
	e.directs[peer] = dc
	return dc
}

// TestCandidateSlotLatestWins: the slot holds one list and a round takes
// whatever is in it, so a newer announcement must displace an older one the
// round has not picked up yet. The older list names a port the peer has already
// left, and dialing it is what burns a round.
func TestCandidateSlotLatestWins(t *testing.T) {
	dc := newSlotConn(t)
	older := []candidate{{addr: netip.MustParseAddrPort("203.0.113.7:1111")}}
	newer := []candidate{{addr: netip.MustParseAddrPort("203.0.113.7:2222")}}

	dc.onCandidates(older)
	dc.onCandidates(newer)

	select {
	case got := <-dc.cand:
		if got[0].addr != newer[0].addr {
			t.Fatalf("slot holds %v, want the newest %v", candAddrs(got), candAddrs(newer))
		}
	default:
		t.Fatal("slot is empty, want the newest list in it")
	}
}

// TestFresherCandidates: a round holds briefly for a list that supersedes the
// one it took, and does not report one when the grace passes without any.
func TestFresherCandidates(t *testing.T) {
	dc := newSlotConn(t)
	newer := []candidate{{addr: netip.MustParseAddrPort("203.0.113.7:2222")}}

	go func() {
		time.Sleep(20 * time.Millisecond)
		dc.onCandidates(newer)
	}()
	if got, ok := dc.fresherCandidates(500 * time.Millisecond); !ok {
		t.Fatal("a list arriving inside the grace was not reported")
	} else if got[0].addr != newer[0].addr {
		t.Fatalf("superseding list = %v, want %v", candAddrs(got), candAddrs(newer))
	}

	start := time.Now()
	if _, ok := dc.fresherCandidates(50 * time.Millisecond); ok {
		t.Fatal("a list was reported when none arrived")
	}
	if d := time.Since(start); d < 40*time.Millisecond {
		t.Fatalf("returned after %v, want the grace to be waited out", d)
	}
}

// TestBackoffDropsOwnCandidates: onCandidates answers a peer's announcement with
// dc.mine, so a failed round must not leave its own list behind — those sockets
// are closed, and an echo of them races the peer's fresh list into its slot.
func TestBackoffDropsOwnCandidates(t *testing.T) {
	dc := newSlotConn(t)
	dc.mu.Lock()
	dc.mine = []candidate{{addr: netip.MustParseAddrPort("203.0.113.7:1111")}}
	dc.state = directAttempting
	dc.mu.Unlock()

	dc.backoff()

	dc.mu.Lock()
	mine := dc.mine
	dc.mu.Unlock()
	if mine != nil {
		t.Fatalf("mine = %v after a failed round, want it cleared", candAddrs(mine))
	}
}

// TestBackoffSkipsRoundsForAGonePeer: a failed round schedules a retry, but a
// peer with no live data path cannot answer one — the candidate exchange rides
// the relay's control channel to the peer. Running a round for it anyway burns
// a STUN lookup, a broadcast and a timeout every backoff period, forever: the
// field case is a killed phone re-punched for over an hour (197 rounds).
//
// The retry must stay armed, though. A skipped round that stopped the timer
// would leave the state in directBackoff, which start() refuses to run from — a
// one-way door, and also a field case: a phone that reconnected sat on the
// relay for good because nothing could punch it again.
func TestBackoffSkipsRoundsForAGonePeer(t *testing.T) {
	dc := newSlotConn(t)
	dc.e.client = &derpclient.Client{} // relay up, so a round would reach its STUN lookup
	dead := newTestSess(t)
	dead.Close()
	pc := &peerConn{peer: dc.peer, sess: dead}
	dc.e.peers[dc.peer] = pc

	dc.retry(50*time.Millisecond, true)
	time.Sleep(200 * time.Millisecond)
	if a, _, _ := dc.punchCounters(); a != 0 {
		t.Fatalf("attempts = %d, want 0 — a round ran for a peer with no live path", a)
	}

	// The peer comes back: the punch has to recover on its own, within a backoff
	// period of the return.
	pc.mu.Lock()
	pc.sess = newTestSess(t)
	pc.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a, _, _ := dc.punchCounters(); a > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no round ran after the peer came back: the skipped retry left the punch stuck")
}

// TestBackoffContinuesForALivePeer: the gate is "the peer is gone", not "the
// round failed". A connected peer keeps retrying — a symmetric-NAT peer, and one
// whose relay session is briefly down, must not be given up on.
// TestPeerDirectOffSkipsTheRound: the asymmetry that makes this bit worth
// having — this host has direct on, the peer has it off. A round cannot be
// answered, so starting one is what produced the endless "punch failed (often a
// symmetric NAT)": the word names a NAT problem that is not there, and the
// STUN lookup and broadcast go out every backoff period for a peer that will
// never send candidates back.
//
// The bit is revoked by the peer's next candidate broadcast, so turning the
// switch back on is not a restart: the round resumes on the announcement.
func TestPeerDirectOffSkipsTheRound(t *testing.T) {
	dc := newSlotConn(t)
	eng := dc.e
	eng.direct, eng.stunAddr = true, "127.0.0.1:3478"
	eng.client = &derpclient.Client{} // relay up, so a round would reach its STUN lookup

	// The peer says it will not punch.
	dc.addCaps(capsNoDirect)
	eng.maybeStartDirect(dc.peer)
	// The decision is read from the trace, not from a counter: a skipped round
	// is a synchronous decision, while "attempts == 0" is a race — a round that
	// did start is counted by a goroutine, and a retry re-armed by an earlier
	// case can fire after the assertion. The trace line is what the skip leaves.
	skip := func() bool {
		for _, l := range dc.traceLines() {
			if strings.Contains(l, "peer has the direct path off") {
				return true
			}
		}
		return false
	}
	if !skip() {
		t.Fatal("no round was skipped for a peer that advertised the direct path off")
	}
	// punchAndWait must not block for the full wait on the same peer either.
	if sess := eng.punchAndWait(dc.peer); sess != nil {
		t.Error("punchAndWait returned a session for a peer with direct off")
	}

	// The peer turns punching back on: the announcement revokes the bit and the
	// next trigger starts a round again.
	dc.onCandidates([]candidate{{addr: netip.MustParseAddrPort("203.0.113.7:1234")}})
	if dc.peerDirectOff() {
		t.Fatal("a candidate broadcast did not revoke capsNoDirect")
	}
	eng.maybeStartDirect(dc.peer)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a, _, _ := dc.punchCounters(); a > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("no round ran after the peer resumed punching")
}

func TestBackoffContinuesForALivePeer(t *testing.T) {
	dc := newSlotConn(t)
	dc.e.client = &derpclient.Client{}
	dc.e.peers[dc.peer] = &peerConn{peer: dc.peer, sess: newTestSess(t)}

	dc.retry(50*time.Millisecond, true)
	time.Sleep(300 * time.Millisecond)

	if a, _, _ := dc.punchCounters(); a == 0 {
		t.Error("attempts = 0, want a retry to have run for a peer that can answer")
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

// TestUDPDialStartsPunch: dialling a udp tunnel starts hole punching even when
// this side will not open the channel stream -- otherwise, in the half of the
// key orders where the peer is the opener, neither side ever sends candidates
// and the direct path never gets a chance.
func TestUDPDialStartsPunch(t *testing.T) {
	e := newTestEngine(t)
	e.stunAddr = "127.0.0.1:3478" // non-empty only: the punch itself fails fast
	_, peer, _ := derpclient.Generate()

	s := newServer(e)
	if _, err := s.allocateTunnel("udp", keyName(peer), false); err != nil {
		t.Fatal(err)
	}

	dc := e.getDirect(peer)
	if dc == nil {
		t.Fatal("udp dial did not start a punch")
	}
	dc.mu.Lock()
	state := dc.state
	dc.mu.Unlock()
	if state == directNone {
		t.Fatal("udp dial left the punch unstarted")
	}
}

// directUpNow reports the punch state without going through session(): that
// call is itself a re-punch trigger, and the point of the test below is the
// death being one.
func directUpNow(e *engine, peer derpclient.PublicKey) bool {
	dc := e.directConn(peer)
	if dc == nil {
		return false
	}
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.state == directUp
}

// TestPunchWaitsForRelay: with the relay down a punch round must wait, not
// fail. Candidates are exchanged over the relay, so there is nothing to do
// until it is back — and counting the round as a failure backs the peer off for
// 30s over what is usually a few seconds of network change (a phone switching
// Wi-Fi ↔ cellular, which is when this happens).
func TestPunchWaitsForRelay(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, "", privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
	defer engineA.Close()
	defer engineB.Close()
	engineA.Connect()
	engineB.Connect()

	// Take the relay away, the way a network change does.
	engineA.mu.Lock()
	c := engineA.client
	engineA.client = nil
	engineA.mu.Unlock()
	if c != nil {
		c.Close()
	}

	dc := engineA.directConn(pubB)
	if !dc.start() {
		t.Fatal("punch did not start")
	}
	waitFor(t, 5*time.Second, func() bool {
		dc.mu.Lock()
		defer dc.mu.Unlock()
		return dc.state == directBackoff
	})
	if dc.hasFailed() {
		t.Fatal("a round without the relay marked the peer as failed; it should wait instead")
	}
}

// A live direct session ending must be counted once, and only when the session
// actually owned the state: a round already rebuilding is not a new drop.
func TestDetachSessionCountsDropOnce(t *testing.T) {
	e := &engine{directs: make(map[derpclient.PublicKey]*directConn)}
	// A punch session owns the socket kcp closes with it (ownConn=true), so a
	// session that owned directUp must hand that socket back for closing.
	uconn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uconn.Close()
	dc := &directConn{e: e, peer: derpclient.PublicKey{1}, sess: newTestSess(t), socket: uconn, state: directUp}

	sock, repunch := dc.detachSessionLocked(dc.sess)
	if !repunch {
		t.Fatal("repunch = false, want true for a session that owned directUp")
	}
	if sock == nil {
		t.Error("socket = nil, want the session's socket")
	}
	if got := dc.drops.Load(); got != 1 {
		t.Errorf("drops = %d, want 1", got)
	}

	// A second detach has nothing to detach: no second drop.
	if _, repunch := dc.detachSessionLocked(dc.sess); repunch {
		t.Error("a second detach reported a re-punch")
	}
	if got := dc.drops.Load(); got != 1 {
		t.Errorf("drops = %d after a no-op detach, want 1", got)
	}
}

// TestDirectSessionAgeZeroedAfterEnd: SessionAge is the age of the *live*
// session, so a peer whose direct session has ended (state none/backoff, path
// no longer direct) must report 0 — never a phantom age that keeps growing
// while the same row's state/path say the session is gone. Both detach paths
// (teardown, and the detachSessionLocked that markDead uses) zero it.
func TestDirectSessionAgeZeroedAfterEnd(t *testing.T) {
	e := &engine{
		direct:   true,
		stunAddr: "127.0.0.1:3478", // a candidate source: directReason() is empty
		directs:  make(map[derpclient.PublicKey]*directConn),
		peers:    make(map[derpclient.PublicKey]*peerConn),
	}
	peer := derpclient.PublicKey{7}
	e.peers[peer] = &peerConn{peer: peer}
	dc := &directConn{e: e, peer: peer}
	e.directs[peer] = dc

	dc.markUp(newTestSess(t), nil, netip.AddrPort{})
	if d := e.peerDiagnostics(e.peerTransports())[keyName(peer)]; d.Path != transportDirect || d.SessionAge <= 0 {
		t.Fatalf("live session: path=%q age=%v, want direct with age > 0", d.Path, d.SessionAge)
	}

	// markDead's path.
	dc.markUp(newTestSess(t), nil, netip.AddrPort{})
	if sock, _ := dc.detachSessionLocked(dc.sess); sock != nil {
		sock.Close()
	}
	if at := dc.sessAtOf(); !at.IsZero() {
		t.Errorf("sessAt = %v after detach, want zero", at)
	}
	if d := e.peerDiagnostics(e.peerTransports())[keyName(peer)]; d.SessionAge != 0 {
		t.Errorf("SessionAge = %v after the session ended, want 0", d.SessionAge)
	}

	// teardown's path.
	dc.markUp(newTestSess(t), nil, netip.AddrPort{})
	dc.teardown()
	if at := dc.sessAtOf(); !at.IsZero() {
		t.Errorf("sessAt = %v after teardown, want zero", at)
	}
	if d := e.peerDiagnostics(e.peerTransports())[keyName(peer)]; d.SessionAge != 0 {
		t.Errorf("SessionAge = %v after teardown, want 0", d.SessionAge)
	}
}

// A session that did not own the state (a round is already rebuilding) is not
// this side's drop to count: it returns repunch=false.
func TestDetachSessionIgnoresNonOwningState(t *testing.T) {
	e := &engine{directs: make(map[derpclient.PublicKey]*directConn)}
	sess := newTestSess(t)
	dc := &directConn{e: e, peer: derpclient.PublicKey{1}, sess: sess, state: directAttempting}

	if _, repunch := dc.detachSessionLocked(sess); repunch {
		t.Error("repunch = true for a session that did not own directUp")
	}
	if got := dc.drops.Load(); got != 0 {
		t.Errorf("drops = %d, want 0", got)
	}
}

// A session coming up counts as an up.
func TestMarkUpCountsUps(t *testing.T) {
	e := &engine{directs: make(map[derpclient.PublicKey]*directConn)}
	dc := &directConn{e: e, peer: derpclient.PublicKey{1}}

	dc.markUp(newTestSess(t), nil, netip.AddrPort{})

	if got := dc.ups.Load(); got != 1 {
		t.Errorf("ups = %d, want 1", got)
	}
	if dc.stateOf() != directUp {
		t.Errorf("state = %v, want directUp", dc.stateOf())
	}
}

// TestDirectConnRecordsLastError: a punch failure records its reason so a status
// reader sees why a peer is stuck, and a success clears it.
func TestDirectConnRecordsLastError(t *testing.T) {
	dc := &directConn{}
	dc.noteErr("seed timeout")
	if got := dc.lastErrOf(); got != "seed timeout" {
		t.Fatalf("lastErr = %q, want %q", got, "seed timeout")
	}
	dc.mu.Lock()
	dc.lastErr = ""
	dc.mu.Unlock()
	if got := dc.lastErrOf(); got != "" {
		t.Fatalf("lastErr = %q, want empty", got)
	}
}

// TestPunchGatesBeforeDial: the encryption gate sits before the dial/seed, so a
// peer that cannot negotiate the direct cipher is never dialed — it gets no seed
// echo, so its own punch fails and it backs off instead of falsely reporting a
// direct path. The round must end in backoff with no direct session.
//
// The relay's dropCtrl cannot target only the direct transport (the transport
// byte is inside the seal), so this drives the punch path directly against a
// peer that is not registered at the relay: no direct half ever arrives, so the
// gate cannot settle.
//
// It deliberately does NOT shorten handshakeTimeout/resendInterval: another
// test's lingering background punch/udp-link goroutine can be reading them, and
// writing a package timing global races with it (see TestMain's note). The gate
// therefore runs at the default handshakeTimeout.
func TestPunchGatesBeforeDial(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")

	priv, _, _ := derpclient.Generate()
	e := newEngine(url, "", priv, slog.Default())
	e.stunAddr = stun
	t.Cleanup(e.Close)
	if err := e.Connect(); err != nil {
		t.Fatal(err)
	}

	peer := derpclient.PublicKey{9}
	dc := e.directConn(peer)
	// A peer candidate list, so the round gets past the candidate exchange to the
	// gate (otherwise it would back off for "no shared family" instead).
	dc.cand <- []candidate{{addr: netip.MustParseAddrPort("127.0.0.1:9")}}

	start := time.Now()
	dc.punch()
	elapsed := time.Since(start)

	if dc.secure.settled() {
		t.Fatal("direct session settled without a peer half")
	}
	if hasDirect(e, peer) {
		t.Fatal("a peer that cannot encrypt was marked direct")
	}
	if sess := dc.session(); sess != nil {
		t.Fatal("a direct smux session was built without the cipher")
	}
	if got := dc.stateOf(); got != directBackoff {
		t.Fatalf("punch state = %v, want directBackoff", got)
	}
	// The gate returns before the family loop, so no dial/seed ran. A dial would
	// have burned up to seedTimeout (5s) inside seedHandshake; the round is
	// bounded well under that.
	if elapsed >= seedTimeout {
		t.Fatalf("punch took %v: it dialed/seeded despite the unsettled cipher", elapsed)
	}
}

// TestPunchTraceRing: the trace ring caps at punchTraceCap, reads oldest ->
// newest, drops the oldest past the cap, and traceLines returns a copy.
func TestPunchTraceRing(t *testing.T) {
	dc := &directConn{}
	if got := dc.traceLines(); got != nil {
		t.Fatalf("fresh trace = %v, want nil", got)
	}
	for i := 1; i <= punchTraceCap; i++ {
		dc.noteRound("line %d", i)
	}
	got := dc.traceLines()
	if len(got) != punchTraceCap {
		t.Fatalf("trace len = %d, want %d", len(got), punchTraceCap)
	}
	if got[0] != "line 1" || got[len(got)-1] != fmt.Sprintf("line %d", punchTraceCap) {
		t.Fatalf("trace order wrong: first=%q last=%q", got[0], got[len(got)-1])
	}
	// One more line drops the oldest and keeps the newest at the end.
	dc.noteRound("line %d", punchTraceCap+1)
	got = dc.traceLines()
	if len(got) != punchTraceCap {
		t.Fatalf("trace len after wrap = %d, want %d", len(got), punchTraceCap)
	}
	if got[0] != "line 2" || got[len(got)-1] != fmt.Sprintf("line %d", punchTraceCap+1) {
		t.Fatalf("ring did not drop the oldest: first=%q last=%q", got[0], got[len(got)-1])
	}
	// traceLines returns a copy: mutating it must not change the ring.
	got[0] = "mutated"
	if again := dc.traceLines(); again[0] == "mutated" {
		t.Fatal("traceLines aliases the ring")
	}
}
