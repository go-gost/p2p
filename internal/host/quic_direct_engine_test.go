package host

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestQUICModeDirectPunch is the Task 10 integration: two QUIC-mode engines
// establish their pair over the relay, the pair's establishment starts the
// existing hole punch, and the punched socket is installed as the QUIC pair's
// direct underlay. Traffic then rides the direct path with relay data frames
// cut, and no KCP pair is ever built.
func TestQUICModeDirectPunch(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privB, pubB, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newQUICTestEngine(t, url, "", privA)
	b := newQUICTestEngine(t, url, echo, privB)
	// newQUICTestEngine leaves direct off; this task is what wires the punch
	// into QUIC mode, so turn it on with a candidate source.
	a.direct, b.direct = true, true
	a.stunAddr, b.stunAddr = stun, stun

	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := b.Connect(); err != nil {
		t.Fatal(err)
	}

	// The first stream proves the relay path and drives QUIC establishment.
	// Pair establishment is the QUIC-mode punch trigger (there is no KCP
	// ensureSession to start one).
	s, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream over relay: %v", err)
	}
	roundTrip(t, s, "quic-relay-before-punch")
	s.Close()

	waitFor(t, 10*time.Second, func() bool {
		return quicPairEstablished(a, pubB) && quicPairEstablished(b, a.pub)
	})
	waitFor(t, 15*time.Second, func() bool {
		return hasDirect(a, pubB) && hasDirect(b, a.pub)
	})
	// Both sides must observe the migrated path before the relay data plane is
	// cut: the client switches preferred on install, while the server follows
	// the source of the first direct datagram.
	waitFor(t, 10*time.Second, func() bool {
		return quicPairPath(a, pubB) == quicPathDirect && quicPairPath(b, a.pub) == quicPathDirect
	})

	// Cut relay data frames; only the direct underlay can carry this stream.
	rs.setDropData(true)
	s2, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream on direct: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "quic-direct")

	if !hasDirect(a, pubB) || !hasDirect(b, a.pub) {
		t.Fatal("a direct underlay is not up after the punch")
	}
	for name, e := range map[string]*engine{"a": a, "b": b} {
		peer := pubB
		if name == "b" {
			peer = a.pub
		}
		if dc := e.getDirect(peer); dc == nil || dc.stateName() != "up" {
			t.Fatalf("engine %s direct state = %q, want up", name, dcStateName(e, peer))
		}
		if n := relayKCPCount(e); n != 0 {
			t.Fatalf("engine %s built %d relay KCP pairs in QUIC mode, want 0", name, n)
		}
	}
}

// dcStateName names the peer's punch state, or "" when no directConn exists.
func dcStateName(e *engine, peer derpclient.PublicKey) string {
	dc := e.getDirect(peer)
	if dc == nil {
		return ""
	}
	return dc.stateName()
}

// TestQUICDirectInstallFailureStaysAttempting pins the failure window: a punch's
// markUp install fails (the QUIC pair closed under it), and until punch() calls
// backoff() the state must stay directAttempting. A peer candidate announcement
// in that window must not start a second round; backoff then owns the single
// attempting -> backoff transition (retryFrom would otherwise clobber the new
// round's state).
func TestQUICDirectInstallFailureStaysAttempting(t *testing.T) {
	e := newTestEngine(t)
	e.transport = transportQUIC
	e.direct = true
	e.stunAddr = "127.0.0.1:3478"
	peer := derpclient.PublicKey{9}
	dc := e.directConn(peer)
	// A round is in flight when markUp runs: start sets this before punch.
	dc.mu.Lock()
	dc.state = directAttempting
	dc.mu.Unlock()

	sock := mustListenUDP(t)
	err := dc.markUp(sock, netip.AddrPort{}, [seedTokenLen]byte{})
	if !errors.Is(err, errQUICPairNoConn) {
		t.Fatalf("markUp error = %v, want errQUICPairNoConn", err)
	}
	if dc.isUp() {
		t.Fatal("direct path marked up without an established QUIC pair")
	}
	if got := dc.stateOf(); got != directAttempting {
		t.Fatalf("state = %v after a failed install, want directAttempting until backoff", got)
	}

	// An announcement lands between markUp returning and backoff: it must not
	// start a second round over the failed one.
	dc.onCandidates([]candidate{{addr: netip.MustParseAddrPort("203.0.113.7:1234")}})
	if got := dc.stateOf(); got != directAttempting {
		t.Fatalf("state = %v after candidates in the failure window, want directAttempting", got)
	}
	if dc.start() {
		t.Fatal("start() in the failure window started a second round")
	}

	// The punch's own backoff is the single transition out of attempting.
	dc.backoff()
	if got := dc.stateOf(); got != directBackoff {
		t.Fatalf("state = %v after backoff, want directBackoff", got)
	}
}

// TestRetireDirectQUICRemovesUnderlay pins engine.retireDirect's QUIC dispatch:
// the pair's direct underlay is detached by socket identity and the socket is
// closed, so a directConn teardown returns the pair to the relay without waiting
// for the pair to close. Engine shutdown clears quics before tearing the
// directConns down, so this is covered at the hook rather than end to end.
func TestRetireDirectQUICRemovesUnderlay(t *testing.T) {
	e := &engine{
		transport: transportQUIC,
		quics:     make(map[derpclient.PublicKey]*quicPeer),
	}
	peer := derpclient.PublicKey{9}
	pair := newQUICPair(e, peer, quicRoleClient, nil, nil, nil)
	t.Cleanup(pair.close)
	e.quics[peer] = &quicPeer{pair: pair}

	peerSock := mustListenUDP(t)
	t.Cleanup(func() { peerSock.Close() })
	sock := mustListenUDP(t)
	token := [seedTokenLen]byte{1}
	if err := pair.addDirect(sock, udpAddrPort(t, peerSock), token); err != nil {
		t.Fatalf("addDirect: %v", err)
	}
	if got := pair.pathName(); got != quicPathDirect {
		t.Fatalf("path after addDirect = %q, want %q", got, quicPathDirect)
	}

	e.retireDirect(peer, sock)

	if got := pair.pathName(); got != quicPathRelay {
		t.Fatalf("path after retireDirect = %q, want %q", got, quicPathRelay)
	}
	pair.mu.Lock()
	direct := pair.directSock
	pair.mu.Unlock()
	if direct != nil {
		t.Fatal("retireDirect left the direct socket installed on the pair")
	}
	if _, err := sock.WriteToUDP([]byte("x"), net.UDPAddrFromAddrPort(udpAddrPort(t, peerSock))); err == nil {
		t.Fatal("retireDirect did not close the socket")
	}
}

// TestQUICDirectInstallRequiresPair pins the failure half of the hook: a QUIC
// install with no established pair must not mark the direct path up or retain
// the socket, so the punch backs off instead of reporting a path QUIC does not
// hold.
func TestQUICDirectInstallRequiresPair(t *testing.T) {
	e := &engine{transport: transportQUIC}
	dc := &directConn{e: e, peer: derpclient.PublicKey{9}}
	sock := mustListenUDP(t)

	err := dc.markUp(sock, netip.AddrPort{}, [seedTokenLen]byte{})
	if !errors.Is(err, errQUICPairNoConn) {
		t.Fatalf("markUp error = %v, want errQUICPairNoConn", err)
	}
	if dc.isUp() {
		t.Fatal("direct path marked up without an established QUIC pair")
	}
	if dc.stateName() != "none" {
		t.Fatalf("direct state = %q after a failed install, want none", dc.stateName())
	}
	if _, err := sock.WriteToUDP([]byte("x"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1"))); err == nil {
		t.Fatal("failed install left the punch socket open")
	}
}

// quicPairPath returns the peer's QUIC path name, or "" before a pair exists.
func quicPairPath(e *engine, peer derpclient.PublicKey) string {
	pair := e.getQUIC(peer)
	if pair == nil {
		return ""
	}
	return pair.pathName()
}
