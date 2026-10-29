package host

import (
	"errors"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// newQUICFailurePair brings up two QUIC engines over the fake relay. With
// direct set, both also punch and migrate onto a direct underlay. It returns
// the connected engines; the caller drives the failure under test.
func newQUICFailurePair(t *testing.T, direct bool) (a, b *engine) {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privB, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a = newQUICTestEngine(t, url, echo, privA)
	b = newQUICTestEngine(t, url, echo, privB)
	if direct {
		stun := startFakeSTUN(t, "")
		a.direct, b.direct = true, true
		a.stunAddr, b.stunAddr = stun, stun
	}
	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := b.Connect(); err != nil {
		t.Fatal(err)
	}
	return a, b
}

// establishQUICRelayAndDirect drives the first stream (which establishes the
// pair) and waits for both ends to migrate onto the direct path.
func establishQUICRelayAndDirect(t *testing.T, a, b *engine) {
	t.Helper()
	s, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream over relay: %v", err)
	}
	roundTrip(t, s, "quic-relay-before-failure")
	s.Close()

	waitFor(t, 10*time.Second, func() bool {
		return quicPairEstablished(a, b.pub) && quicPairEstablished(b, a.pub)
	})
	waitFor(t, 15*time.Second, func() bool {
		return hasDirect(a, b.pub) && hasDirect(b, a.pub)
	})
	waitFor(t, 10*time.Second, func() bool {
		return quicPairPath(a, b.pub) == quicPathDirect && quicPairPath(b, a.pub) == quicPathDirect
	})
}

// setShortDirectHeartbeat shrinks the direct heartbeat/watchdog window for one
// test and restores the package defaults afterwards. The idle window must stay
// above the underlay's 1s read tick (directUnderlayReadTimeout).
func setShortDirectHeartbeat(t *testing.T) {
	t.Helper()
	oldIdle := directUnderlayIdle.Load()
	oldHb := directHeartbeatInterval.Load()
	directUnderlayIdle.Store(int64(2500 * time.Millisecond))
	directHeartbeatInterval.Store(int64(200 * time.Millisecond))
	t.Cleanup(func() {
		directUnderlayIdle.Store(oldIdle)
		directHeartbeatInterval.Store(oldHb)
	})
}

// relayUnderlayState snapshots whether the peer's QUIC state has a relay
// underlay installed, and which one.
func relayUnderlayState(e *engine, peer derpclient.PublicKey) (up bool, relay *relayQUICConn) {
	e.quicMu.Lock()
	defer e.quicMu.Unlock()
	qp := e.quics[peer]
	if qp == nil {
		return false, nil
	}
	return qp.relayUp, qp.relay
}

// quicRoles names which engine drives path selection (the client) and which
// follows (the server) for this pair. QUIC role is decided by public-key order,
// not by which side opens the first stream.
func quicRoles(a, b *engine) (client, server *engine) {
	if p := a.getQUIC(b.pub); p != nil && p.role == quicRoleClient {
		return a, b
	}
	return b, a
}

// TestQUICDirectLossFallsBackToRelay covers the direct half of §8.10: the
// client's direct heartbeat stops being answered, the watchdog retires the
// direct underlay and prefers the relay, the QUIC connection and an open
// stream survive, and the server follows the client onto the relay. No KCP pair
// is ever built.
func TestQUICDirectLossFallsBackToRelay(t *testing.T) {
	setShortDirectHeartbeat(t)
	a, b := newQUICFailurePair(t, true)
	establishQUICRelayAndDirect(t, a, b)
	client, server := quicRoles(a, b)

	stream, err := client.OpenStream(server.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream on direct: %v", err)
	}
	defer stream.Close()
	roundTrip(t, stream, "before-direct-loss")

	clientPair := client.getQUIC(server.pub)
	serverPair := server.getQUIC(client.pub)
	if clientPair == nil || serverPair == nil {
		t.Fatal("no QUIC pair before the direct loss")
	}

	// Kill the server's direct socket: the client's heartbeats are then sent
	// into a closed port and never echoed back, which is the loss the client's
	// watchdog exists to detect.
	serverPair.mu.Lock()
	peerSock := serverPair.directSock
	serverPair.mu.Unlock()
	if peerSock == nil {
		t.Fatal("no direct socket installed on the server")
	}
	if err := peerSock.Close(); err != nil {
		t.Fatalf("close the server direct socket: %v", err)
	}

	waitFor(t, 10*time.Second, func() bool {
		return quicPairPath(client, server.pub) == quicPathRelay
	})
	// The open stream must ride the relay now, on the same QUIC connection.
	roundTrip(t, stream, "after-direct-loss")
	if got := client.getQUIC(server.pub); got != clientPair {
		t.Fatal("direct loss rebuilt the QUIC connection instead of migrating it")
	}
	if !clientPair.established() {
		t.Fatal("QUIC connection died when the direct path was retired")
	}
	waitFor(t, 5*time.Second, func() bool { return !hasDirect(client, server.pub) })
	waitFor(t, 5*time.Second, func() bool {
		return quicPairPath(server, client.pub) == quicPathRelay
	})

	clientPair.mu.Lock()
	directSock := clientPair.directSock
	clientPair.mu.Unlock()
	if directSock != nil {
		t.Fatal("watchdog fallback left the direct socket installed on the pair")
	}
	if up, _ := relayUnderlayState(client, server.pub); !up {
		t.Fatal("relay underlay is not installed after the direct fallback")
	}
	for name, e := range map[string]*engine{"a": a, "b": b} {
		if n := relayKCPCount(e); n != 0 {
			t.Fatalf("engine %s built %d KCP pairs in QUIC mode, want 0", name, n)
		}
	}
}

// TestQUICRelayLossKeepsDirect covers the second row of §8.10: with a live
// direct path the relay can disappear without touching the QUIC connection or
// its streams. On reconnect a fresh relay underlay (new batching conn, new
// adapter write) is installed on the same synthetic relay address, and it
// carries traffic once the direct path is gone.
func TestQUICRelayLossKeepsDirect(t *testing.T) {
	a, b := newQUICFailurePair(t, true)
	establishQUICRelayAndDirect(t, a, b)

	stream, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream on direct: %v", err)
	}
	defer stream.Close()
	roundTrip(t, stream, "before-relay-loss")

	pair := a.getQUIC(b.pub)
	if pair == nil {
		t.Fatal("no QUIC pair before the relay loss")
	}
	oldUp, oldRelay := relayUnderlayState(a, b.pub)
	if !oldUp || oldRelay == nil {
		t.Fatal("relay underlay is not installed before the relay loss")
	}

	a.mu.Lock()
	relayClient := a.client
	a.mu.Unlock()
	if relayClient == nil {
		t.Fatal("no relay client to tear down")
	}
	a.teardown(relayClient, errors.New("test: relay link lost"))

	if got := a.getQUIC(b.pub); got != pair {
		t.Fatal("relay loss rebuilt or dropped the QUIC pair with a live direct path")
	}
	if !pair.established() {
		t.Fatal("relay loss closed the QUIC connection with a live direct path")
	}
	if got := quicPairPath(a, b.pub); got != quicPathDirect {
		t.Fatalf("path after relay loss = %q, want %q", got, quicPathDirect)
	}
	if up, relay := relayUnderlayState(a, b.pub); up || relay != nil {
		t.Fatal("relay loss left the dead relay underlay installed")
	}
	// The stream keeps working: everything it needs rides the direct path.
	roundTrip(t, stream, "direct-while-relay-is-down")

	// The relay comes back: a fresh underlay must be installed on the same
	// synthetic address, without disturbing the QUIC connection.
	if err := a.Connect(); err != nil {
		t.Fatalf("reconnect relay: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool {
		up, relay := relayUnderlayState(a, b.pub)
		return up && relay != nil
	})
	if got := a.getQUIC(b.pub); got != pair {
		t.Fatal("relay reconnect rebuilt the QUIC pair instead of reusing it")
	}
	up, fresh := relayUnderlayState(a, b.pub)
	if !up || fresh == nil {
		t.Fatal("relay reconnect did not install a relay underlay")
	}
	if fresh == oldRelay {
		t.Fatal("relay reconnect reused the dead relay underlay instead of replacing it")
	}
	if got := fresh.LocalAddr().String(); got != quicPathRelay {
		t.Fatalf("fresh relay underlay address = %q, want %q", got, quicPathRelay)
	}
	roundTrip(t, stream, "after-relay-reconnect")

	// Prove the restored underlay carries data: drop the client's direct path
	// and let the stream fall back to the relay.
	client, server := quicRoles(a, b)
	clientPair := client.getQUIC(server.pub)
	if clientPair == nil {
		t.Fatal("no client QUIC pair before the relay check")
	}
	clientPair.mu.Lock()
	directSock := clientPair.directSock
	clientPair.mu.Unlock()
	if directSock == nil {
		t.Fatal("direct underlay disappeared before the relay check")
	}
	clientPair.removeDirect(directSock)
	// Writing the stream drives the relay path immediately; without traffic
	// QUIC would only notice the path change on its next keepalive.
	roundTrip(t, stream, "relay-underlay-carries")
	if got := quicPairPath(client, server.pub); got != quicPathRelay {
		t.Fatalf("path after direct removal = %q, want %q", got, quicPathRelay)
	}
	waitFor(t, 5*time.Second, func() bool {
		return quicPairPath(server, client.pub) == quicPathRelay
	})

	if n := relayKCPCount(a); n != 0 {
		t.Fatalf("engine built %d KCP pairs in QUIC mode, want 0", n)
	}
	if n := relayKCPCount(b); n != 0 {
		t.Fatalf("engine built %d KCP pairs in QUIC mode, want 0", n)
	}
}

// TestQUICConnDeathRebuildsQUIC covers the connection row of §8.10: a closed
// QUIC connection drops its pair from the engine state and the next OpenStream
// builds a new QUIC pair over the relay, never a KCP one.
func TestQUICConnDeathRebuildsQUIC(t *testing.T) {
	a, b := newQUICFailurePair(t, false)

	s, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream over relay: %v", err)
	}
	roundTrip(t, s, "before-conn-death")
	s.Close()
	waitFor(t, 10*time.Second, func() bool {
		return quicPairEstablished(a, b.pub) && quicPairEstablished(b, a.pub)
	})

	old := a.getQUIC(b.pub)
	if old == nil {
		t.Fatal("no QUIC pair before the connection death")
	}
	old.mu.Lock()
	conn := old.conn
	old.mu.Unlock()
	if conn == nil {
		t.Fatal("QUIC pair has no connection")
	}
	_ = conn.CloseWithError(0, "test: connection death")

	waitFor(t, 5*time.Second, func() bool { return !old.established() })

	// The next open rebuilds over the relay from the cached peer caps; the
	// connection, not the negotiation, is what died.
	s2, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream after QUIC connection death: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "rebuilt-quic")

	fresh := a.getQUIC(b.pub)
	if fresh == nil || fresh == old {
		t.Fatal("OpenStream did not rebuild the QUIC pair")
	}
	if !fresh.established() {
		t.Fatal("rebuilt QUIC pair is not established")
	}
	for name, e := range map[string]*engine{"a": a, "b": b} {
		if n := relayKCPCount(e); n != 0 {
			t.Fatalf("engine %s built %d KCP pairs after a QUIC death, want 0", name, n)
		}
	}
}
