package host

import (
	"context"
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
	return qp.relayInstalled, qp.relay
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

	// Retire the peer's direct underlay through the engine — the same hook a
	// local read failure or a connection death uses — instead of closing the
	// socket out from under the pair. The client's heartbeats then go into a
	// closed port and are never echoed back, which is the loss the client's
	// watchdog exists to detect.
	serverPair.mu.Lock()
	peerSock := serverPair.directSock
	serverPair.mu.Unlock()
	if peerSock == nil {
		t.Fatal("no direct socket installed on the server")
	}
	server.retireQUICDirect(serverPair)
	if hasDirect(server, client.pub) {
		t.Fatal("engine retirement left the server's direct path up")
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
	// The migration history is a Status surface, not only a log line: the
	// direct install counted a relay->direct flip and the watchdog fallback
	// counted the direct->relay flip, its idle subset and the re-punch.
	srv := newServer(client)
	t.Cleanup(srv.close)
	st := srv.status()
	d, ok := st.PeerDiagnostics[server.PublicKey()]
	if !ok {
		t.Fatalf("no diagnostic for %s after fallback: %+v",
			server.PublicKey(), st.PeerDiagnostics)
	}
	if d.PairMigrations < 1 {
		t.Fatalf("PairMigrations = %d after direct install, want >= 1", d.PairMigrations)
	}
	if d.PairFallbacks < 1 {
		t.Fatalf("PairFallbacks = %d after heartbeat fallback, want >= 1", d.PairFallbacks)
	}
	if d.DirectIdleEvictions < 1 {
		t.Fatalf("DirectIdleEvictions = %d after heartbeat fallback, want >= 1",
			d.DirectIdleEvictions)
	}
	if d.RepunchAfterIdle < 1 {
		t.Fatalf("RepunchAfterIdle = %d after heartbeat fallback, want >= 1",
			d.RepunchAfterIdle)
	}
	if st.PairMigrations != d.PairMigrations ||
		st.PairFallbacks != d.PairFallbacks ||
		st.DirectIdleEvictions != d.DirectIdleEvictions ||
		st.RepunchAfterIdle != d.RepunchAfterIdle {
		t.Fatalf("Status sums = %d/%d/%d/%d, want the single peer's %d/%d/%d/%d",
			st.PairMigrations, st.PairFallbacks, st.DirectIdleEvictions, st.RepunchAfterIdle,
			d.PairMigrations, d.PairFallbacks, d.DirectIdleEvictions, d.RepunchAfterIdle)
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

// TestQUICConnClosedKeepsRebuildSetup pins the close-watcher ordering: an
// OpenStream that sees the dead connection starts its setup before the watcher
// drops the pair. The watcher must not cancel that setup — it is the rebuild —
// or the open fails with "handshake: context canceled" and nothing retries it.
func TestQUICConnClosedKeepsRebuildSetup(t *testing.T) {
	e := newTestEngine(t) // KCP mode makes maybeStartQUIC a no-op here.
	peer := derpclient.PublicKey{7}
	pair := newQUICPair(e, peer, quicRoleClient, nil, nil, nil)
	t.Cleanup(pair.close)

	ctx, cancel := context.WithCancel(context.Background())
	setup := &quicSetup{done: make(chan struct{}), cancel: cancel}
	e.quicMu.Lock()
	e.quics = map[derpclient.PublicKey]*quicPeer{peer: {pair: pair, setup: setup}}
	e.quicMu.Unlock()

	e.quicConnClosed(pair, errors.New("test: connection death"))

	if ctx.Err() != nil {
		t.Fatal("connection death canceled the in-flight rebuild setup")
	}
	e.quicMu.Lock()
	qp := e.quics[peer]
	e.quicMu.Unlock()
	if qp == nil || qp.pair != nil {
		t.Fatal("connection death did not drop the dead pair")
	}
	cancel()
	close(setup.done)
}

// TestQUICConnDeathWithLiveDirectRepunches covers the failure the direct-path
// teardown used to leave behind: the QUIC connection dies while both ends hold a
// live direct underlay. Closing the pair closes that underlay with the
// multiPathConn, so the punch state must be retired too; otherwise directConn
// keeps reporting directUp, the rebuilt pair's punch trigger refuses to start,
// and the peer stays relay-only forever. The rebuilt QUIC pair must punch a
// fresh direct underlay on both ends, again without ever building KCP.
func TestQUICConnDeathWithLiveDirectRepunches(t *testing.T) {
	a, b := newQUICFailurePair(t, true)
	establishQUICRelayAndDirect(t, a, b)

	client, server := quicRoles(a, b)
	oldPair := client.getQUIC(server.pub)
	serverOld := server.getQUIC(client.pub)
	if oldPair == nil || serverOld == nil {
		t.Fatal("no QUIC pairs before the connection death")
	}
	oldPair.mu.Lock()
	conn, oldSock := oldPair.conn, oldPair.directSock
	oldPair.mu.Unlock()
	if conn == nil {
		t.Fatal("client QUIC pair has no connection")
	}
	if oldSock == nil {
		t.Fatal("client QUIC pair has no direct underlay")
	}

	// Kill only the QUIC connection: both direct sockets are still open, so
	// nothing but the connection death can retire the paths.
	_ = conn.CloseWithError(0, "test: connection death with live direct")

	// The rebuilt pair must start a fresh punch on its own (no local open to
	// drive it) and install a new direct underlay on both ends.
	waitFor(t, 20*time.Second, func() bool {
		p := client.getQUIC(server.pub)
		if p == nil || p == oldPair || !p.established() {
			return false
		}
		p.mu.Lock()
		sock := p.directSock
		p.mu.Unlock()
		return sock != nil && sock != oldSock && hasDirect(client, server.pub)
	})
	waitFor(t, 20*time.Second, func() bool {
		p := server.getQUIC(client.pub)
		return p != nil && p != serverOld && p.established() && hasDirect(server, client.pub)
	})

	if got := client.getQUIC(server.pub); got == nil || got == oldPair {
		t.Fatal("client kept the dead QUIC pair instead of rebuilding it")
	}
	if got := server.getQUIC(client.pub); got == nil || got == serverOld {
		t.Fatal("server kept the dead QUIC pair instead of rebuilding it")
	}

	// The rebuilt pair carries traffic on the fresh direct path. The write is
	// also what drives the server's QUIC migration: it follows the source of
	// the first packet on the new path, and without traffic the server path
	// would only follow on an idle/PTO timer.
	s, err := client.OpenStream(server.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream after conn death with live direct: %v", err)
	}
	defer s.Close()
	roundTrip(t, s, "rebuilt-direct")
	waitFor(t, 10*time.Second, func() bool {
		return quicPairPath(client, server.pub) == quicPathDirect &&
			quicPairPath(server, client.pub) == quicPathDirect
	})
	if got := quicPairPath(client, server.pub); got != quicPathDirect {
		t.Fatalf("path after rebuild = %q, want %q", got, quicPathDirect)
	}

	for name, e := range map[string]*engine{"a": a, "b": b} {
		if n := relayKCPCount(e); n != 0 {
			t.Fatalf("engine %s built %d KCP pairs after a direct conn death, want 0", name, n)
		}
	}
}

// TestQUICRelayTeardownRestoreOrder pins the teardown/restore ordering: a
// reconnect's restore may run while teardown still has the stale underlay marked
// installed and skip, and a delayed relayDown must not remove the fresh
// underlay a later restore installed in the same slot.
func TestQUICRelayTeardownRestoreOrder(t *testing.T) {
	a, b := newQUICFailurePair(t, true)
	establishQUICRelayAndDirect(t, a, b)

	pair := a.getQUIC(b.pub)
	if pair == nil {
		t.Fatal("no QUIC pair before the relay teardown")
	}
	up, oldRelay := relayUnderlayState(a, b.pub)
	if !up || oldRelay == nil {
		t.Fatal("relay underlay is not installed before the teardown")
	}

	// Restore-first race: the reconnect's restore runs while the old underlay
	// is still installed, so it must leave it alone (the teardown below still
	// owns it).
	a.relayRestoredQUIC()
	if gotUp, gotRelay := relayUnderlayState(a, b.pub); !gotUp || gotRelay != oldRelay {
		t.Fatal("restore replaced or removed a relay underlay the teardown still owns")
	}

	// The teardown detaches the only relay underlay. The relay client is back
	// (the reconnect won the race), so the teardown must re-run the restore by
	// itself: nothing else revisits a pair that survived on its direct path.
	a.relayDownQUIC()

	waitFor(t, 10*time.Second, func() bool {
		up, relay := relayUnderlayState(a, b.pub)
		return up && relay != nil && relay != oldRelay
	})
	if got := a.getQUIC(b.pub); got != pair {
		t.Fatal("relay teardown/restore replaced the QUIC pair instead of keeping it")
	}
	if !pair.established() {
		t.Fatal("relay teardown/restore closed the QUIC connection")
	}

	// A delayed relayDown holding the stale snapshot must not detach the fresh
	// underlay now installed in the same slot.
	pair.relayDown(oldRelay)
	up, fresh := relayUnderlayState(a, b.pub)
	if !up || fresh == nil || fresh == oldRelay {
		t.Fatal("stale relayDown cleared the installed relay state")
	}
	pair.mp.mu.RLock()
	installed := pair.mp.underlays[quicPathRelay]
	pair.mp.mu.RUnlock()
	if installed == nil || installed.u.pc != fresh {
		t.Fatal("stale relayDown removed the fresh relay underlay")
	}
	if got := a.getQUIC(b.pub); got != pair || !pair.established() {
		t.Fatal("stale relayDown disturbed the QUIC pair")
	}
}

// TestQUICPeerGoneClearsHandshakeUnderLiveDirect is the phone-restart bug in one
// test, and it is deliberately narrower than "drop everything".
//
// H1 protects the direct path across a *relay* blip: the pair must survive our
// own relay loss, keep its streams, and re-attach an underlay when the relay
// returns (TestQUICRelayLossKeepsDirect). This case is a different event —
// peerGone, the peer itself going away — and there the pair's control plane is
// exactly what went stale: the relay registration it would re-handshake through
// still points at the peer's old connection, so every open rode the surviving
// pair and timed out three times at 10s. The phone's restart then cost 20-35s
// instead of the ~50ms a healthy handshake takes.
//
// So: the direct path and the pair object stay (H1), but the handshake state
// that says "this peer is already established with us" must be invalidated, or
// the next establish() short-circuits against a session that no longer exists
// on the other side.
func TestQUICPeerGoneClearsHandshakeUnderLiveDirect(t *testing.T) {
	a, b := newQUICFailurePair(t, true)
	establishQUICRelayAndDirect(t, a, b)

	if a.getQUIC(b.pub) == nil {
		t.Fatal("no QUIC pair before the peer-gone notice")
	}

	a.peerGone(b.pub)

	// H1's promise: the direct path survives.
	if !hasDirect(a, b.pub) {
		t.Fatal("peer-gone retired the direct path, which it must not")
	}
	// The stale half: caps belong to the session that just died, so a peer
	// coming back must re-exchange them rather than be answered from a cache
	// describing the connection it no longer has.
	a.quicMu.Lock()
	qp := a.quics[b.pub]
	cached := qp != nil && qp.haveCaps
	a.quicMu.Unlock()
	if cached {
		t.Fatal("peer-gone kept the peer's cached caps; the next establish " +
			"will short-circuit on a session the peer no longer has")
	}
}

// TestQUICSessionResetRebuildsFromFreshRouting is the second half of the restart
// problem, and the half the derper cannot help with.
//
// The peer-gone notice is best-effort: it depends on the derper noticing an
// undeliverable packet, and on this host having a live direct path at that
// moment it takes the H1 branch. Measured on the deployed hub, restarts where
// the notice never arrived still spent three 10s handshake deadlines —
// TestQUICPeerGoneClearsHandshakeUnderLiveDirect does not cover those, because
// nothing told the hub anything.
//
// So the peer says it itself: on reconnect it sends ctrlSessionReset, and the
// receiver forgets what it knew about that peer's session and rebuilds. The
// message is sealed to the peer's key like every other control frame, so only
// the peer it names can send it.
func TestQUICSessionResetRebuildsFromFreshRouting(t *testing.T) {
	a, b := newQUICFailurePair(t, true)
	establishQUICRelayAndDirect(t, a, b)

	if a.getQUIC(b.pub) == nil {
		t.Fatal("no QUIC pair before the reset")
	}

	// b restarts and announces it. From a's side this must look exactly like a
	// peer-gone: the session state goes, the direct path stays.
	b.sendSessionReset(a.pub)

	waitFor(t, 5*time.Second, func() bool {
		a.quicMu.Lock()
		qp := a.quics[b.pub]
		cached := qp != nil && qp.haveCaps
		a.quicMu.Unlock()
		return !cached
	})
	if !hasDirect(a, b.pub) {
		t.Fatal("the reset retired the direct path, which it must not")
	}

	// And the peer can be reached again immediately: this is the whole point.
	s, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream after a session reset: %v", err)
	}
	defer s.Close()
	roundTrip(t, s, "after-session-reset")
}

// TestQUICSessionResetRequiresThePeersSeal: only the named peer can reset its
// own session. A frame sealed by a third party must be dropped, or anyone who
// learns a key could tear down another host's connections.
func TestQUICSessionResetRejectsForeignSeal(t *testing.T) {
	a, b := newQUICFailurePair(t, true)
	establishQUICRelayAndDirect(t, a, b)

	// A third identity that a has never dealt with.
	privC, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// Sealed by C, claiming to be B: the open must fail, because a looks for a
	// box from B's key.
	a.quicMu.Lock()
	before := a.quics[b.pub]
	a.quicMu.Unlock()
	if before == nil {
		t.Fatal("no QUIC state before the forged frame")
	}

	a.handleControl(b.pub, append([]byte{ctrlSessionReset}, privC.SealTo(b.pub, nil)...))

	// Nothing changed: the peer's own state is untouched.
	a.quicMu.Lock()
	after := a.quics[b.pub]
	a.quicMu.Unlock()
	if after != before {
		t.Fatal("a foreign-sealed reset frame replaced the peer's state")
	}
}

// TestResetAnnounceTargetsIncludesWarmedPeers: a cold start announces itself
// before any peer state exists.
//
// The first call on a fresh host is Warm/Punch, which reaches ensureTransport
// without ever building a peerConn — so a target list drawn from e.peers is
// empty exactly when the announcement matters most. Measured on a real phone:
// the first start after the fix still took 35s because nothing was sent, even
// though the frame and its handler were in place.
func TestResetAnnounceTargetsIncludesWarmedPeers(t *testing.T) {
	a, _ := newQUICFailurePair(t, false)
	peer := derpclient.PublicKey{7}

	if got := a.resetAnnounceTargets(); len(got) != 0 {
		t.Fatalf("a fresh engine has %d announce targets, want none", len(got))
	}

	a.noteAnnouncedPeer(peer)
	got := a.resetAnnounceTargets()
	if len(got) != 1 || got[0] != peer {
		t.Fatalf("announce targets = %v, want the warmed peer", got)
	}

	// Deduplicated: a peer that also has live state is announced once.
	a.peerConn(peer)
	if got := a.resetAnnounceTargets(); len(got) != 1 {
		t.Fatalf("announce targets = %v, want the peer once", got)
	}
}

// TestWarmAnnouncesWhenRelayIsAlreadyUp: the cold-start ordering that made the
// announcement silent.
//
// A fresh host is built, its relay dials, and only then does the caller warm its
// first peer. The reconnect loop announces on the wasDown transition it observes
// on its own tick — which has already happened by then, so nothing is sent, and
// the start this exists for got no help at all. Measured on a real phone: six
// cold starts after the frame shipped, one announcement.
//
// The announcement is what a peer sees as its session state being dropped, so
// that is what is asserted here: b has a pair to a, a warms b while its relay is
// already up, and b must forget the session without waiting for a transition.
func TestWarmAnnouncesWhenRelayIsAlreadyUp(t *testing.T) {
	a, b := newQUICFailurePair(t, true)
	establishQUICRelayAndDirect(t, a, b)

	if b.getQUIC(a.pub) == nil {
		t.Fatal("no QUIC pair on b before the announcement")
	}

	// a's relay is already up (newQUICFailurePair connected it), so this must
	// send immediately rather than schedule for a later transition.
	a.noteAnnouncedPeer(b.pub)

	waitFor(t, 5*time.Second, func() bool {
		b.quicMu.Lock()
		qp := b.quics[a.pub]
		cached := qp != nil && qp.haveCaps
		b.quicMu.Unlock()
		return !cached
	})
}

// TestWarmBeforeRelayAnnouncesWhenItConnects: the cold-start race the
// transition-gated announcement cannot see.
//
// A restarting host warms its peer while its own relay dial is still in flight.
// The announcement was wired to the down->up transition the reconnect ticker
// observes, and to an immediately-up relay at warm time — neither applies here:
// warm saw no client, so it sent nothing but still recorded the peer as already
// told, and by the first tick the eager Connect had made the client non-nil, so
// there was no transition to observe. The peer was then never told and kept its
// stale registration state.
func TestWarmBeforeRelayAnnouncesWhenItConnects(t *testing.T) {
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
	a := newQUICTestEngine(t, url, echo, privA)
	b := newQUICTestEngine(t, url, echo, privB)

	// b is up so it can hear; a's relay is still down.
	if err := b.Connect(); err != nil {
		t.Fatalf("b connect: %v", err)
	}

	// b holds a cached session for a — the state the announcement must clear.
	b.quicMu.Lock()
	qp := b.quicPeerLocked(a.pub)
	qp.caps = capsInfo{Bits: capsQUIC}
	qp.haveCaps = true
	qp.capsSent = true
	b.quicMu.Unlock()

	// a warms b while a has no relay at all, so nothing can be sent yet.
	a.noteAnnouncedPeer(b.pub)
	b.quicMu.Lock()
	stillCached := b.quics[a.pub].haveCaps
	b.quicMu.Unlock()
	if !stillCached {
		t.Fatal("a sent a session reset with no relay: want nothing sent")
	}

	// a's relay comes up; the owed announcement must follow immediately.
	if err := a.Connect(); err != nil {
		t.Fatalf("a connect: %v", err)
	}

	waitFor(t, 5*time.Second, func() bool {
		b.quicMu.Lock()
		defer b.quicMu.Unlock()
		qp := b.quics[a.pub]
		return qp == nil || !qp.haveCaps
	})
}

// TestQUICRebuildsWhenThePeerAdvertisesANewIdentity: the hub's side of a peer
// restart, decided from evidence instead of from a timeout.
//
// A restarted peer has a rebuilt engine and so a new QUIC identity. The hub's
// connection still looks established — the peer's death has not been noticed
// yet — so it answered every handshake packet with that dead connection, each
// attempt costing a full handshake deadline before the blackhole cure. The
// peer's caps carry the new fingerprint, and a mismatch with the one the pair
// pins is proof the pair can never carry it.
func TestQUICRebuildsWhenThePeerAdvertisesANewIdentity(t *testing.T) {
	a, b := newQUICFailurePair(t, false)

	s, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer s.Close()
	oldPair := a.getQUIC(b.pub)
	if oldPair == nil {
		t.Fatal("no pair after OpenStream")
	}

	// The peer comes back with a new identity: same relay key, different
	// fingerprint in its caps, exactly as a rebuilt engine advertises.
	a.quicMu.Lock()
	qp := a.quicPeerLocked(b.pub)
	if qp.caps.QUIC == nil {
		a.quicMu.Unlock()
		t.Fatal("peer caps carried no quic identity to change")
	}
	info := qp.caps
	q := *info.QUIC
	q.Fingerprint[0] ^= 0xff
	info.QUIC = &q
	qp.caps = info
	qp.haveCaps = true
	a.quicMu.Unlock()

	a.maybeStartQUIC(b.pub)

	if got := a.getQUIC(b.pub); got == oldPair {
		t.Fatal("the stale pair survived a peer that advertised a new identity")
	}
	// The caps that carried the news are what the rebuild handshakes against:
	// losing them sends it back to waiting for a frame the peer will not resend.
	a.quicMu.Lock()
	qp = a.quicPeerLocked(b.pub)
	kept := qp.haveCaps && qp.caps.QUIC != nil
	a.quicMu.Unlock()
	if !kept {
		t.Fatal("the rebuild discarded the caps that proved the new identity")
	}
}

// TestPeerLiveSeesAnEstablishedQUICPair: an established QUIC pair is a live
// data path, and peerLive has to say so.
//
// peerLive is what decides whether a failed punch round grows its wait
// (silentPeerWait): a peer with a path gets the wait it asked for, one without
// doubles it. In QUIC mode none of the three things peerLive used to consult
// exist — there is no KCP session on the peer adapter, the directConn only goes
// live once a punch installs an underlay, and QUIC builds no KCP pair — so a
// peer we were actively connected to read as absent. Measured on a phone after
// an app restart: one failed punch round armed a 60s wait instead of 30s, and
// the direct path took 66s to come up while the relay carried traffic.
func TestPeerLiveSeesAnEstablishedQUICPair(t *testing.T) {
	a, b := newQUICFailurePair(t, false)

	s, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer s.Close()
	roundTrip(t, s, "before-live-check")

	if got := a.getQUIC(b.pub); got == nil || !got.established() {
		t.Fatal("no established pair to test against")
	}
	if !a.peerLive(b.pub) {
		t.Fatal("an established quic pair is a live data path")
	}
}
