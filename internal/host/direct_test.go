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
	"syscall"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"

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
	// The silent-peer growth doubles from backoffPeriod and stops here, so a
	// test can reach the cap in a few rounds instead of minutes.
	deadPeerWaitCap = 4 * time.Second
	// The H3 hysteresis doubles from backoffPeriod and stops here, so a test can
	// reach the cap in a few short-lived directs instead of minutes.
	directRepunchBackoffCap = 4 * time.Second
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

// hasDirect reports whether an engine has an established direct path to peer:
// the directConn is up (a punched socket registered as the pair's underlay).
func hasDirect(e *engine, peer derpclient.PublicKey) bool {
	dc := e.getDirect(peer)
	return dc != nil && dc.isUp()
}

// pairSecureForTest reports whether the pair's secure session to peer has
// settled. The direct underlay rides that same session (there is no separate
// direct secure session after Task 7), so this reads it under the engine lock
// and its keys under the session's own lock — never the session's lock while
// holding e.mu. It is a property of the pair, not of the direct path: a caller
// asserting the direct path is encrypted must also assert the underlay is up.
func pairSecureForTest(e *engine, peer derpclient.PublicKey) bool {
	e.mu.Lock()
	ss := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if ss == nil {
		return false
	}
	_, _, ok := ss.keys()
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

// TestSeedHandshakeUDPRoundTrip: two raw-UDP sockets run the token-echo
// handshake at each other; both complete within the timeout. It is the raw-UDP
// analogue of TestSeedHandshake, over the socket the punch actually owns.
func TestSeedHandshakeUDPRoundTrip(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer a.Close()
	defer b.Close()
	pa, pb := udpAddrPort(t, a), udpAddrPort(t, b)

	seedHandshakeUDPRetry(t, a, b, pa, pb)
}

// TestSeedHandshakeUDPTimesOut: one side runs alone; nothing echoes its token,
// so it ends in errSeedTimeout once the timeout elapses. The sandbox's
// intermittent sendto EPERM (see seedHandshakeUDPRetry) is retried; the timing
// is asserted only on the genuine timeout.
func TestSeedHandshakeUDPTimesOut(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t) // a valid peer address that never answers
	defer a.Close()
	defer b.Close()

	var err error
	for attempt := 0; attempt < 5; attempt++ {
		start := time.Now()
		err = seedHandshakeUDP(a, udpAddrPort(t, b), 300*time.Millisecond)
		elapsed := time.Since(start)
		if errors.Is(err, errSeedTimeout) {
			if elapsed < 250*time.Millisecond {
				t.Fatalf("seedHandshakeUDP timed out after %v, want the timeout waited out", elapsed)
			}
			return
		}
		if err == nil {
			t.Fatal("seedHandshakeUDP returned nil with no responder")
		}
		if !seedErrRetryable(err) {
			t.Fatalf("seedHandshakeUDP: %v", err)
		}
	}
	t.Fatalf("seedHandshakeUDP never timed out (last error: %v)", err)
}

// TestSeedHandshakeUDPIgnoresNoise: a datagram without the seed magic (from the
// peer) and a seed-magic probe from a third socket (wrong source) must not
// complete the handshake. Neither is an echo of this side's own token, so it
// must end in errSeedTimeout. A write may fail with the sandbox's intermittent
// EPERM; the noise then simply was not sent, which does not weaken the
// assertion that no false success occurs.
func TestSeedHandshakeUDPIgnoresNoise(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	c := mustListenUDP(t) // foreign source
	defer a.Close()
	defer b.Close()
	defer c.Close()

	_, _ = b.WriteToUDP([]byte("hello"), a.LocalAddr().(*net.UDPAddr))
	noise := append(append([]byte(nil), seedProbeMagic[:]...), make([]byte, seedTokenLen)...)
	_, _ = c.WriteToUDP(noise, a.LocalAddr().(*net.UDPAddr))

	err := seedHandshakeUDP(a, udpAddrPort(t, b), 400*time.Millisecond)
	if err == nil {
		t.Fatal("seedHandshakeUDP completed on non-seed/foreign noise")
	}
	if !errors.Is(err, errSeedTimeout) && !errors.Is(err, syscall.EPERM) {
		t.Fatalf("seedHandshakeUDP: %v", err)
	}
}

// TestSeedHandshakeUDPEchoesRetransmittedProbe is the C1 regression: a peer's
// probe token is constant across its retransmits, so the handshake must echo
// every probe, not just the first. A per-token dedupe dropped the retries and
// stranded the peer when the single echo was lost — the very failure the resend
// loop exists to cover on a lossy raw-UDP path.
func TestSeedHandshakeUDPEchoesRetransmittedProbe(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer a.Close()
	defer b.Close()
	pb := udpAddrPort(t, b)

	done := make(chan error, 1)
	go func() { done <- seedHandshakeUDP(a, pb, 700*time.Millisecond) }()

	var tokB [seedTokenLen]byte
	tokB[0] = 0xAB
	probeB := append(append([]byte(nil), seedProbeMagic[:]...), tokB[:]...)
	// The same probe twice, exactly as a retransmitting peer would send it.
	for i := 0; i < 2; i++ {
		if _, err := b.WriteToUDP(probeB, a.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Skipf("sandbox sendto denied the probe (EPERM): %v", err)
		}
	}

	echos := 0
	deadline := time.Now().Add(500 * time.Millisecond)
	buf := make([]byte, 64)
	for echos < 2 && time.Now().Before(deadline) {
		b.SetReadDeadline(deadline)
		n, _, err := b.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if bytes.Equal(buf[:n], probeB) {
			echos++
		}
	}
	if echos < 2 {
		t.Fatalf("a echoed a retransmitted probe %d time(s), want 2 (a per-token dedupe drops the retry)", echos)
	}
	// No responder ever echoes a's own token, so it must end in the timeout.
	if err := <-done; !errors.Is(err, errSeedTimeout) {
		t.Fatalf("handshake = %v, want errSeedTimeout", err)
	}
}

// drainUDP discards datagrams already queued on c until a short read window
// elapses.
func drainUDP(c *net.UDPConn) {
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 2048)
	for {
		if _, _, err := c.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

// seedHandshakeUDPOnce runs seedHandshakeUDP at each end of the a/b pair.
func seedHandshakeUDPOnce(a, b *net.UDPConn, pa, pb netip.AddrPort) (errA, errB error) {
	ra, rb := make(chan error, 1), make(chan error, 1)
	go func() { ra <- seedHandshakeUDP(a, pb, 2*time.Second) }()
	go func() { rb <- seedHandshakeUDP(b, pa, 2*time.Second) }()
	return <-ra, <-rb
}

// seedErrRetryable reports whether err alone is one to retry: nil (success) or
// the sandbox's intermittent sendto EPERM. Any other error is a real defect and
// fails at once — the environmental excuse must not hide a real intermittent
// bug.
func seedErrRetryable(err error) bool {
	return err == nil || errors.Is(err, syscall.EPERM)
}

// seedPairRetryable reports whether a two-ended handshake's errors are worth
// retrying. One side's sendto EPERM leaves the other side with a plain timeout
// (nothing echoed its probe), so the pair is retryable when EITHER side saw
// EPERM; a pair that failed without any EPERM is a real defect.
func seedPairRetryable(errA, errB error) bool {
	return errors.Is(errA, syscall.EPERM) || errors.Is(errB, syscall.EPERM)
}

// seedHandshakeUDPRetry runs seedHandshakeUDPOnce until both ends succeed.
// Only the sandbox's intermittent sendto EPERM (absent in CI; the same flake
// TestSeedHandshake documents) is retried; any other error fails immediately.
func seedHandshakeUDPRetry(t *testing.T, a, b *net.UDPConn, pa, pb netip.AddrPort) {
	t.Helper()
	var errA, errB error
	for attempt := 0; attempt < 5; attempt++ {
		errA, errB = seedHandshakeUDPOnce(a, b, pa, pb)
		if errA == nil && errB == nil {
			return
		}
		if !seedPairRetryable(errA, errB) {
			t.Fatalf("seedHandshakeUDP: A=%v B=%v", errA, errB)
		}
		drainUDP(a)
		drainUDP(b)
	}
	t.Fatalf("seedHandshakeUDP: A=%v B=%v", errA, errB)
}

// seedHandshakeUDPPair completes the token handshake at each end of the a/b
// socket pair and returns both tokens. It retries for the same environmental
// EPERM reason as seedHandshakeUDPRetry; here the handshake is setup for the
// echo-quiesce test, which is what this returns the tokens for.
func seedHandshakeUDPPair(t *testing.T, a, b *net.UDPConn, pa, pb netip.AddrPort) (ta, tb [seedTokenLen]byte) {
	t.Helper()
	var errA, errB error
	for attempt := 0; attempt < 5; attempt++ {
		type res struct {
			tok [seedTokenLen]byte
			err error
		}
		ra, rb := make(chan res, 1), make(chan res, 1)
		go func() { tok, err := seedHandshakeUDPToken(a, pb, 2*time.Second); ra <- res{tok, err} }()
		go func() { tok, err := seedHandshakeUDPToken(b, pa, 2*time.Second); rb <- res{tok, err} }()
		x, y := <-ra, <-rb
		ta, tb, errA, errB = x.tok, y.tok, x.err, y.err
		if errA == nil && errB == nil {
			return ta, tb
		}
		if !seedPairRetryable(errA, errB) {
			t.Fatalf("seed handshakes: A=%v B=%v", errA, errB)
		}
		drainUDP(a)
		drainUDP(b)
	}
	t.Fatalf("seed handshakes: A=%v B=%v", errA, errB)
	return ta, tb
}

// TestDirectUnderlaySeedEchoQuiesces is the two-underlay quiesce test for the
// parked H2 ping-pong ruling: with the seed echo made token-aware, two
// registered underlays must not echo each other's echoes forever. Both seed
// handshakes complete first (as the punch tail does), then both sides' probes
// are delivered. Each side echoes the peer's probe exactly once; the returning
// echo carries this side's own token and is dropped instead of echoed again, so
// the exchange goes quiet.
func TestDirectUnderlaySeedEchoQuiesces(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	pa, pb := udpAddrPort(t, a), udpAddrPort(t, b)

	tokA, tokB := seedHandshakeUDPPair(t, a, b, pa, pb)
	// Drain any retransmitted probes still in flight after the handshakes, so
	// the echo counts below start from a clean socket.
	drainUDP(a)
	drainUDP(b)

	uA := newDirectUnderlayToken(a, pb, tokA)
	uB := newDirectUnderlayToken(b, pa, tokB)
	defer uA.close()
	defer uB.close()

	readLoop := func(u *directUnderlay) {
		buf := make([]byte, 2048)
		for {
			if _, err := u.readFrom(buf); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
				return
			}
		}
	}
	go readLoop(uA)
	go readLoop(uB)

	// Both sides still probing (the late-responder scenario): each sends its
	// own-token probe to the peer.
	probe := func(tok [seedTokenLen]byte) []byte {
		p := make([]byte, 0, len(seedProbeMagic)+seedTokenLen)
		p = append(p, seedProbeMagic[:]...)
		p = append(p, tok[:]...)
		return p
	}
	if _, err := uA.writeTo(probe(tokA)); err != nil {
		t.Fatal(err)
	}
	if _, err := uB.writeTo(probe(tokB)); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool {
		return uA.seedEchoes.Load() == 1 && uB.seedEchoes.Load() == 1
	})
	// Let any ping-pong play out: a looping echo would keep incrementing.
	time.Sleep(3 * seedRetransmit)
	if gotA, gotB := uA.seedEchoes.Load(), uB.seedEchoes.Load(); gotA != 1 || gotB != 1 {
		t.Fatalf("seed echo ping-ponged: A echoed %d, B echoed %d, want exactly 1 each", gotA, gotB)
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

// TestRegisterDirectUnderlayInstallsOnPair: a punched socket registered for a
// peer becomes the pair's direct underlay, preferred immediately, with the seed
// token threaded through so the underlay can echo the peer's late probes.
func TestRegisterDirectUnderlayInstallsOnPair(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{7}
	sock := mustListenUDP(t)
	peerAddr := udpAddrPort(t, mustListenUDP(t))
	token := [seedTokenLen]byte{0xAB}

	e.registerDirectUnderlay(peer, sock, peerAddr, token)

	pair := e.relayKCPPairFor(peer)
	if !pair.preferredDirect() {
		t.Fatal("preferredDirect() = false right after registration, want true")
	}
	if got := pair.pathName(); got != "direct" {
		t.Fatalf("pathName() = %q, want direct", got)
	}
	pair.mu.Lock()
	u := pair.direct
	pair.mu.Unlock()
	if u == nil {
		t.Fatal("the pair holds no direct underlay after registration")
	}
	if u.sock != sock {
		t.Fatal("the pair's underlay wraps a different socket")
	}
	if !u.hasToken || u.localToken != token {
		t.Fatalf("the underlay lost the seed token: hasToken=%v token=%x", u.hasToken, u.localToken)
	}
}

// TestDirectUnderlayDeadClearsAndRepunches: the pair's idle watchdog retiring
// the underlay marks the peer's directConn down and schedules a re-punch, so the
// path comes back on its own.
func TestDirectUnderlayDeadClearsAndRepunches(t *testing.T) {
	e := newTestEngine(t)
	e.stunAddr = "127.0.0.1:3478" // a candidate source, so start() launches a round
	peer := derpclient.PublicKey{8}
	dc := e.directConn(peer)
	sock := mustListenUDP(t)
	dc.markUp(sock, udpAddrPort(t, mustListenUDP(t)), [seedTokenLen]byte{0x11})
	// Make the underlay look long-lived so the re-punch is immediate (no H3
	// backoff): its lifetime is what keys the hysteresis.
	dc.mu.Lock()
	dc.sessAt = time.Now().Add(-3 * directUnderlayIdle)
	dc.mu.Unlock()

	pair := e.relayKCPPairFor(peer)
	pair.mu.Lock()
	u := pair.direct
	pair.mu.Unlock()
	if u == nil {
		t.Fatal("no underlay registered")
	}

	e.directUnderlayDead(peer, u)

	if pair.preferredDirect() {
		t.Fatal("preferredDirect() = true after the underlay died, want false")
	}
	if dc.isUp() {
		t.Fatal("isUp() = true after the underlay died, want false")
	}
	switch dc.stateOf() {
	case directAttempting, directBackoff:
		// a re-punch is in flight or scheduled
	default:
		// directNone here means nothing was scheduled: the regression this
		// guards (a death that does not re-punch) would pass otherwise.
		t.Fatalf("state = %v after the death, want a re-punch scheduled", dc.stateOf())
	}
}

// TestRegisterDirectUnderlayRetiresOldSocket: registering a second punched
// socket retires the first (its underlay is closed exactly once, by the
// underlay's sync.Once) and the pair serves only the new one, never the old.
func TestRegisterDirectUnderlayRetiresOldSocket(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{9}
	peerAddr := udpAddrPort(t, mustListenUDP(t))
	sock1 := mustListenUDP(t)
	e.registerDirectUnderlay(peer, sock1, peerAddr, [seedTokenLen]byte{1})

	sock2 := mustListenUDP(t)
	e.registerDirectUnderlay(peer, sock2, peerAddr, [seedTokenLen]byte{2})

	// sock1 is closed: a read on it fails. (The underlay's sync.Once is what
	// makes the retirement happen exactly once.)
	sock1.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 8)
	if _, _, err := sock1.ReadFromUDP(buf); err == nil {
		t.Fatal("sock1 is still readable after being retired, want it closed")
	}

	pair := e.relayKCPPairFor(peer)
	pair.mu.Lock()
	u := pair.direct
	pair.mu.Unlock()
	if u == nil || u.sock != sock2 {
		t.Fatal("the pair does not hold the new socket after re-registration")
	}
}

// TestClearDirectUnderlayIfLeavesReplacement pins the compare-and-clear the idle
// watchdog needs (C1): a retirement aimed at an underlay the pair no longer
// holds must not clear the replacement — that is the direct↔relay flapping a
// plain check-then-clear causes.
func TestClearDirectUnderlayIfLeavesReplacement(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{11}
	pair := e.relayKCPPairFor(peer)
	addr := udpAddrPort(t, mustListenUDP(t))

	sock1 := mustListenUDP(t)
	pair.setDirectUnderlay(newDirectUnderlay(sock1, addr))
	pair.mu.Lock()
	u1 := pair.direct
	pair.mu.Unlock()

	sock2 := mustListenUDP(t)
	pair.setDirectUnderlay(newDirectUnderlay(sock2, addr))
	pair.mu.Lock()
	u2 := pair.direct
	pair.mu.Unlock()

	// A stale retirement for u1 must not clear u2.
	if pair.clearDirectUnderlayIf(u1) {
		t.Fatal("clearDirectUnderlayIf(u1) cleared a replacement underlay")
	}
	pair.mu.Lock()
	held := pair.direct
	pair.mu.Unlock()
	if held != u2 {
		t.Fatal("the replacement underlay was retired by a stale clear")
	}
	if u2.closed() {
		t.Fatal("the replacement underlay's socket was closed")
	}

	// The current identity clears, and closes exactly that underlay.
	if !pair.clearDirectUnderlayIf(u2) {
		t.Fatal("clearDirectUnderlayIf(u2) did not clear the current underlay")
	}
	if !u2.closed() {
		t.Fatal("the cleared underlay was not closed")
	}
}

// TestRegisterDirectUnderlayRetiresWhenSecureFails: a peer that passes the
// plaintext seed handshake but cannot settle the pair's secure handshake must
// not be left reported direct. The underlay is installed by the seed, then the
// async pair-session ensure refuses the unsettled cipher and retires it — the
// replacement for the deleted direct encryption gate (I4).
func TestRegisterDirectUnderlayRetiresWhenSecureFails(t *testing.T) {
	defer func(d time.Duration) { handshakeTimeout = d }(handshakeTimeout)
	handshakeTimeout = 300 * time.Millisecond

	rs := &relayServer{}
	url := rs.start(t)
	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	eA := newEngine(url, "", privA, slog.Default())
	eB := newEngine(url, "", privB, slog.Default())
	t.Cleanup(func() { eA.Close(); eB.Close() })
	if err := eA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := eB.Connect(); err != nil {
		t.Fatal(err)
	}

	// The relay drops every ctrlSecure frame, so the pair's secure handshake can
	// never settle (the same injection TestRelayRefusesUnencryptedPeer uses).
	rs.mu.Lock()
	rs.dropCtrl = func(_ [32]byte, payload []byte) bool {
		return len(payload) > 1 && payload[1] == ctrlSecure
	}
	rs.mu.Unlock()

	peer := pubB
	dc := eA.directConn(peer)
	sock := mustListenUDP(t)
	dc.markUp(sock, udpAddrPort(t, mustListenUDP(t)), [seedTokenLen]byte{0x5A})
	if !dc.isUp() {
		t.Fatal("markUp did not install the underlay")
	}

	// The pair-session ensure refuses the unsettled cipher and retires the
	// underlay, so the peer is not reported direct while carrying nothing.
	waitFor(t, 5*time.Second, func() bool { return !dc.isUp() })
	found := false
	for _, l := range dc.traceLines() {
		if strings.Contains(l, "encrypted: not settled") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("the retirement was not recorded as a secure refusal: %v", dc.traceLines())
	}
}

// TestDirectShortLivedBacksOff: a direct that keeps dying shortly after it came
// up must back off instead of flapping direct↔relay. Each short-lived death
// doubles the scheduled re-punch wait, up to the cap.
func TestDirectShortLivedBacksOff(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{10}
	dc := e.directConn(peer)

	var waits []time.Duration
	for i := 0; i < 5; i++ {
		dc.markUp(mustListenUDP(t), udpAddrPort(t, mustListenUDP(t)), [seedTokenLen]byte{byte(i)})
		pair := e.relayKCPPairFor(peer)
		pair.mu.Lock()
		u := pair.direct
		pair.mu.Unlock()
		if u == nil {
			t.Fatalf("round %d: no underlay registered", i)
		}
		// Young underlay: its lifetime is ~0, well under 2×directUnderlayIdle.
		e.directUnderlayDead(peer, u)
		waits = append(waits, lastBackoffWait(t, dc))
	}

	for i := 1; i < len(waits); i++ {
		if waits[i] < waits[i-1] {
			t.Errorf("wait %d = %v, want at least the previous %v", i, waits[i], waits[i-1])
		}
	}
	if waits[len(waits)-1] <= waits[0] {
		t.Errorf("backoff did not grow across short-lived directs: %v", waits)
	}
	if waits[len(waits)-1] > directRepunchBackoffCap {
		t.Errorf("backoff %v over the cap %v", waits[len(waits)-1], directRepunchBackoffCap)
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

// TestDirectSessionEncrypted proves the hole-punched direct path carries
// encrypted bytes: after a direct underlay is up, a stream round-trips over it
// with the relay data plane cut, and the pair secure session it rides is
// settled. There is no separate direct secure session after Task 7, so the
// encryption property belongs to the pair — the test asserts the underlay is up
// as well, or the pair-secure assertion would hold even with no direct path.
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

	// The direct underlay is up on both ends, and the pair secure session it
	// rides has settled — that is what makes the round trip above encrypted.
	if !hasDirect(engineA, pubB) || !hasDirect(engineB, engineA.pub) {
		t.Fatal("the direct underlay is not up after the punch")
	}
	if !pairSecureForTest(engineA, pubB) {
		t.Fatal("A's pair secure session did not settle")
	}
	if !pairSecureForTest(engineB, engineA.pub) {
		t.Fatal("B's pair secure session did not settle")
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

	// Simulate the idle-keepalive death: retire the direct underlay on both
	// sides through the pair's idle-watchdog path. Nothing dials afterwards —
	// the death itself must bring the path back. That is the phone's Wi-Fi ↔
	// cellular switch: the path dies with the old interface, and without the
	// re-punch the pair sits on the relay until something dials.
	for _, e := range []*engine{engineA, engineB} {
		peer := pubB
		if e == engineB {
			peer = engineA.pub
		}
		pair := e.relayKCPPairGet(peer)
		if pair == nil {
			continue
		}
		pair.mu.Lock()
		u := pair.direct
		pair.mu.Unlock()
		if u != nil {
			e.directUnderlayDead(peer, u)
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
// The re-punch race this test guards against had two defects, both fixed:
// (1) onCandidates answered a peer's fresh announcement with dc.mine, the
// candidate list of the session the announcement just made stale. The peer
// dialed that socket, whose KCP session rejects the new source address, so the
// seed handshake hung for seedTimeout (5s) — well past punchWaitTimeout — and
// OpenStream fell back to the relay whose data frames this test has just cut.
// onCandidates now answers only from directAttempting (a round in flight, whose
// candidates are fresh); the re-punch it starts publishes the fresh list
// instead. (2) the re-punch gate in retry used peerLive, which treats "no relay
// session" (a host that never dialed the peer — this test's passive B) the same
// as "peer gone", so the accepting side re-armed forever instead of re-punching.
// retry now gates on peerGoneForPunch: positive evidence of death (a relay
// session that died with no direct session serving), which a passive host never
// has.
//
// With both fixed the race no longer reproduces (0 in 40 classified runs
// failed on a seed timeout; the stale-candidate "seed failed: timeout" mode is
// gone). The test can still fail intermittently without -race — but only from
// an environmental cause: this sandbox intermittently denies the sendmmsg
// syscall (EPERM) under load, breaking the seed handshake on the direct punch
// socket; that is absent in CI/normal environments, never reproduces under
// -race, and is not a product race (see the docs note). Re-run and report it;
// it is not your change.
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
	if !dcA.isUp() {
		t.Fatal("A has no direct path to watch")
	}

	// B's punch socket goes away without the relay being told: from A's side
	// this is a black path, which is the case the idle watchdog has to cover.
	dcB := engineB.directConn(engineA.pub)
	dcB.mu.Lock()
	sockB := dcB.sock
	dcB.mu.Unlock()
	if sockB == nil {
		t.Fatal("B has no punch socket to close")
	}
	sockB.Close()

	// The direct idle bound (directUnderlayIdle, 6s) plus a read tick. The
	// relay keepalive this replaced would take 30-60s, so the bound proves
	// which one is in play.
	closed := time.Now()
	waitFor(t, 12*time.Second, func() bool { return !engineA.directConn(pubB).isUp() })
	t.Logf("silent direct path noticed after %v (idle %v)",
		time.Since(closed).Round(time.Millisecond), directUnderlayIdle)
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
	if !dcA.isUp() {
		t.Fatal("A has no direct path to watch")
	}

	// B's relay connection goes away, so the relay reports it gone to A. B's
	// process — and with it the punch socket — stays up, which is the case the
	// direct path must survive.
	engineB.mu.Lock()
	clientB := engineB.client
	engineB.mu.Unlock()
	if clientB == nil {
		t.Fatal("B has no relay connection to drop")
	}
	clientB.Close()

	waitFor(t, 5*time.Second, func() bool { return engineA.isGone(pubB) })

	// Longer than the direct idle detection window: a path that survives this
	// is genuinely alive, not just unexamined.
	time.Sleep(3 * directUnderlayIdle)
	if !hasDirect(engineA, pubB) {
		t.Fatal("a PeerGone tore down the live direct path")
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
	newEngine := func(state directState) (*engine, *directConn) {
		e := &engine{
			direct:   true,
			stunAddr: "127.0.0.1:3478",
			log:      slog.Default(),
			stop:     make(chan struct{}),
			directs:  make(map[derpclient.PublicKey]*directConn),
			peers:    make(map[derpclient.PublicKey]*peerConn),
		}
		peer := derpclient.PublicKey{9}
		sock := mustListenUDP(t)
		t.Cleanup(func() { sock.Close() })
		dc := &directConn{e: e, peer: peer, sock: sock, state: state, cand: make(chan []candidate, 1)}
		e.directs[peer] = dc
		return e, dc
	}
	cands := []candidate{{addr: netip.MustParseAddrPort("203.0.113.7:1234")}}

	// A live direct underlay stays live across an announcement, whatever the
	// punch state: a peer's re-announcement must not tear down a working path.
	for _, state := range []directState{directUp, directBackoff} {
		_, dc := newEngine(state)
		dc.onCandidates(cands)
		if !dc.isUp() {
			t.Errorf("state %v: after candidates isUp = false, want the underlay untouched", state)
		}
	}

	// Either way a round runs: the peer is punching now, and a round is what
	// repairs a path that really is stale.
	_, dc := newEngine(directBackoff)
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
	if dc.isUp() {
		t.Error("isUp() = true, want false with the direct path off")
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

// lastBackoffWait reads the wait the most recent backoff scheduled, out of the
// punch trace ("backoff 30s") that retry records.
func lastBackoffWait(t *testing.T, dc *directConn) time.Duration {
	t.Helper()
	lines := dc.traceLines()
	for i := len(lines) - 1; i >= 0; i-- {
		rest, ok := strings.CutPrefix(lines[i], "backoff ")
		if !ok {
			continue
		}
		d, err := time.ParseDuration(rest)
		if err != nil {
			t.Fatalf("trace line %q: %v", lines[i], err)
		}
		return d
	}
	t.Fatalf("no backoff in the punch trace: %q", lines)
	return 0
}

// TestSilentPeerWaitGrows covers the wait a punch hands out for a peer that
// shows no live path. Two cases, and the asymmetry between them is the whole
// point:
//
//   - The peer has a path. The wait is the one asked for, every time. A round
//     here is probing a path that blipped — a phone's Wi-Fi ↔ cellular switch —
//     and giving it a growing wait would strand that peer when it returns.
//   - The peer has no path, which for a host that never dialed it is forever:
//     peerGoneForPunch needs a relay session this side built, and there is
//     none to die, so nothing ever skips the round. Without growth it is a
//     STUN lookup, a broadcast and a timeout every backoffPeriod for as long as
//     the peer stays away. The wait doubles, and stops at the cap.
//
// It also covers the reset: a peer that gets a path again must not inherit the
// wait its absence earned.
func TestSilentPeerWaitGrows(t *testing.T) {
	t.Run("grows while the peer is silent", func(t *testing.T) {
		dc := newSlotConn(t)
		// No peerConn for this peer at all: the accepting side of a pair that
		// only ever had a direct path, which no amount of waiting proves gone.
		dc.e.client = &derpclient.Client{}

		var got []time.Duration
		for i := 0; i < 6; i++ {
			got = append(got, dc.silentPeerWait(backoffPeriod))
		}
		// Monotonic up to the cap, and flat at it: reaching the cap is the point,
		// so the tail of the sequence must not keep climbing.
		for i := 1; i < len(got); i++ {
			if got[i] < got[i-1] {
				t.Errorf("wait %d = %v, want at least %v", i, got[i], got[i-1])
			}
			if got[i] != deadPeerWaitCap && got[i] <= got[i-1] {
				t.Errorf("wait %d = %v, want more than %v below the cap %v",
					i, got[i], got[i-1], deadPeerWaitCap)
			}
			if got[i] > deadPeerWaitCap {
				t.Errorf("wait %d = %v, over the cap %v", i, got[i], deadPeerWaitCap)
			}
		}
		if last := got[len(got)-1]; last != deadPeerWaitCap {
			t.Errorf("wait = %v after 6 silent rounds, want the cap %v", last, deadPeerWaitCap)
		}
	})

	t.Run("grows from the wait asked for, not from zero", func(t *testing.T) {
		dc := newSlotConn(t)
		dc.e.client = &derpclient.Client{}

		// A gate re-arm passes the previous wait, not backoffPeriod: growth has
		// to continue from it or the two paths would fight over the value.
		first := dc.silentPeerWait(backoffPeriod)
		second := dc.silentPeerWait(first)
		if second <= first {
			t.Errorf("re-armed wait = %v, want more than the %v it was given", second, first)
		}
	})

	// The unit subtests above pin the arithmetic; this one drives the production
	// path — backoff() is what a failed round actually calls — and reads the
	// waits back out of the punch trace, so what is asserted is the delay the
	// next round is really scheduled with and not the helper's return value.
	t.Run("grows through backoff", func(t *testing.T) {
		dc := newSlotConn(t)
		dc.e.client = &derpclient.Client{}

		dc.backoff()
		first := lastBackoffWait(t, dc)
		for i := 0; i < 3; i++ {
			dc.backoff()
		}
		last := lastBackoffWait(t, dc)

		if last <= first {
			t.Errorf("scheduled backoff %v after four rounds, want more than the %v of the first",
				last, first)
		}
		if last > deadPeerWaitCap {
			t.Errorf("scheduled backoff %v, over the cap %v", last, deadPeerWaitCap)
		}
	})

	t.Run("resets when the peer has a path", func(t *testing.T) {
		dc := newSlotConn(t)
		dc.e.client = &derpclient.Client{}
		dc.e.peers[dc.peer] = &peerConn{peer: dc.peer, sess: newTestSess(t)}

		for i := 0; i < 4; i++ {
			dc.silentPeerWait(backoffPeriod)
		}

		// The peer comes back. Its wait is the one asked for, and the growth a
		// returning peer would otherwise inherit is gone.
		if got := dc.silentPeerWait(50 * time.Millisecond); got != 50*time.Millisecond {
			t.Errorf("wait = %v for a peer with a live path, want the 50ms asked for", got)
		}
		dc.mu.Lock()
		left := dc.silentFor
		dc.mu.Unlock()
		if left != 0 {
			t.Errorf("silentFor = %v after the peer returned, want 0", left)
		}
	})
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

// A live direct underlay ending must be counted once, and only when the
// underlay actually owned the state: a round already rebuilding is not a new
// drop.
func TestUnderlayDeadCountsDropOnce(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{1}
	sock := mustListenUDP(t)
	dc := &directConn{e: e, peer: peer, sock: sock, state: directUp}
	e.directs[peer] = dc
	u := &directUnderlay{sock: sock}

	dc.underlayDead(u)
	if got := dc.drops.Load(); got != 1 {
		t.Errorf("drops = %d, want 1", got)
	}
	if dc.isUp() {
		t.Error("isUp = true after the underlay died, want false")
	}
	if dc.sock != nil {
		t.Error("sock not cleared after the underlay died")
	}

	// A second death has nothing to clear: no second drop.
	dc.underlayDead(u)
	if got := dc.drops.Load(); got != 1 {
		t.Errorf("drops = %d after a no-op death, want 1", got)
	}
}

// TestDirectSessionAgeZeroedAfterEnd: SessionAge is the age of the *live* direct
// underlay, so a peer whose direct path has ended (state none/backoff, path no
// longer direct) must report 0 — never a phantom age that keeps growing while
// the same row's state/path say the path is gone. Both retirement paths
// (underlayDead, and teardown) zero it.
func TestDirectSessionAgeZeroedAfterEnd(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{7}
	dc := &directConn{e: e, peer: peer}
	e.directs[peer] = dc

	sock1 := mustListenUDP(t)
	dc.markUp(sock1, netip.AddrPort{}, [seedTokenLen]byte{})
	if d := e.peerDiagnostics(e.peerTransports())[keyName(peer)]; d.Path != transportDirect || d.SessionAge <= 0 {
		t.Fatalf("live session: path=%q age=%v, want direct with age > 0", d.Path, d.SessionAge)
	}

	// The underlay-death path.
	dc.underlayDead(&directUnderlay{sock: sock1})
	if at := dc.sessAtOf(); !at.IsZero() {
		t.Errorf("sessAt = %v after underlay death, want zero", at)
	}
	if d := e.peerDiagnostics(e.peerTransports())[keyName(peer)]; d.SessionAge != 0 {
		t.Errorf("SessionAge = %v after the session ended, want 0", d.SessionAge)
	}

	// teardown's path.
	sock2 := mustListenUDP(t)
	dc.markUp(sock2, netip.AddrPort{}, [seedTokenLen]byte{})
	dc.teardown()
	if at := dc.sessAtOf(); !at.IsZero() {
		t.Errorf("sessAt = %v after teardown, want zero", at)
	}
	if d := e.peerDiagnostics(e.peerTransports())[keyName(peer)]; d.SessionAge != 0 {
		t.Errorf("SessionAge = %v after teardown, want 0", d.SessionAge)
	}
}

// An underlay that did not own the state (a round is already rebuilding) is not
// this side's drop to count: the re-punch is left to that round.
func TestUnderlayDeadIgnoresNonOwningState(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{1}
	sock := mustListenUDP(t)
	dc := &directConn{e: e, peer: peer, sock: sock, state: directAttempting}
	e.directs[peer] = dc

	dc.underlayDead(&directUnderlay{sock: sock})

	if got := dc.drops.Load(); got != 0 {
		t.Errorf("drops = %d, want 0", got)
	}
	if dc.stateOf() != directAttempting {
		t.Errorf("state = %v, want directAttempting (round left to finish)", dc.stateOf())
	}
}

// A direct underlay coming up counts as an up.
func TestMarkUpCountsUps(t *testing.T) {
	e := newTestEngine(t)
	dc := &directConn{e: e, peer: derpclient.PublicKey{1}}
	sock := mustListenUDP(t)

	dc.markUp(sock, netip.AddrPort{}, [seedTokenLen]byte{})

	if got := dc.ups.Load(); got != 1 {
		t.Errorf("ups = %d, want 1", got)
	}
	if dc.stateOf() != directUp {
		t.Errorf("state = %v, want directUp", dc.stateOf())
	}
	if !dc.isUp() {
		t.Error("isUp = false after markUp, want true")
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
