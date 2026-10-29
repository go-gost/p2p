package host

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

// newQUICTestEngine builds an engine in QUIC mode. newEngine itself leaves the
// transport at its KCP default; production code sets these fields from
// host.New, and tests do the same directly.
func newQUICTestEngine(t *testing.T, url, target string, priv derpclient.PrivateKey) *engine {
	t.Helper()
	e := newEngine(url, target, priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	cfg, err := resolveQUICSettings(nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e.transport = transportQUIC
	e.quicCfg = cfg
	e.quicID = id
	// Most tests here exercise the relay path; keeping the punch off also
	// keeps a stray candidate frame from starting a direct round.
	e.direct = false
	return e
}

// quicPairEstablished reports whether e has a live QUIC pair to peer.
func quicPairEstablished(e *engine, peer derpclient.PublicKey) bool {
	p := e.getQUIC(peer)
	return p != nil && p.established()
}

// peerCapsSeen reports whether e has recorded a caps frame from peer.
func peerCapsSeen(e *engine, peer derpclient.PublicKey) bool {
	e.quicMu.Lock()
	defer e.quicMu.Unlock()
	qp := e.quics[peer]
	return qp != nil && qp.haveCaps
}

// relayKCPCount snapshots the number of KCP pairs an engine has built.
func relayKCPCount(e *engine) int {
	e.kcpMu.Lock()
	defer e.kcpMu.Unlock()
	return len(e.relayKCPs)
}

// TestQUICModeOpensTunnelOverRelay is the end-to-end shape of the QUIC mode:
// two engines negotiate caps through the real fake relay, establish a QUIC
// connection over the relay underlay, and carry an echo tunnel over a QUIC
// stream. Neither engine may build a KCP pair.
func TestQUICModeOpensTunnelOverRelay(t *testing.T) {
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
	a := newQUICTestEngine(t, url, "", privA)
	b := newQUICTestEngine(t, url, echo, privB)
	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := b.Connect(); err != nil {
		t.Fatal(err)
	}

	conn, err := a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	roundTrip(t, conn, "quic over relay")
	conn.Close()

	waitFor(t, 10*time.Second, func() bool {
		return quicPairEstablished(a, b.pub) && quicPairEstablished(b, a.pub)
	})
	if a.transport != transportQUIC || b.transport != transportQUIC {
		t.Fatalf("transports = %v/%v, want quic/quic", a.transport, b.transport)
	}
	for name, e := range map[string]*engine{"a": a, "b": b} {
		e.kcpMu.Lock()
		n := len(e.relayKCPs)
		e.kcpMu.Unlock()
		if n != 0 {
			t.Fatalf("engine %s built %d relay KCP pairs in QUIC mode, want 0", name, n)
		}
	}
}

// TestQUICModeRejectsKCPPeer pins the strict side of the global switch: a peer
// that advertises no QUIC caps is unreachable, not served over KCP, and the
// refusal happens as soon as its caps arrive (no caps-timeout wait).
func TestQUICModeRejectsKCPPeer(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	privA, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privB, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newQUICTestEngine(t, url, "", privA)
	b := newEngine(url, "", privB, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(b.Close)
	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := b.Connect(); err != nil {
		t.Fatal(err)
	}

	// Send the bits-only caps a KCP peer advertises (no QUIC bit). Wait until
	// the QUIC engine has seen them so the open below takes the immediate
	// unsupported path instead of the caps timeout. b.warm is not used: its
	// KCP session waits for a secure half a QUIC peer never sends.
	if err := b.sendCaps(a.pub, capsInfo{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return peerCapsSeen(a, b.pub) })

	conn, err := a.OpenStream(b.PublicKey())
	if err == nil {
		conn.Close()
		t.Fatal("OpenStream to a KCP-only peer succeeded, want ErrTransportUnsupported")
	}
	if !errors.Is(err, p2p.ErrTransportUnsupported) {
		t.Fatalf("OpenStream error = %v, want ErrTransportUnsupported", err)
	}
	if n := relayKCPCount(a); n != 0 {
		t.Fatalf("engine built %d KCP pairs in QUIC mode, want 0", n)
	}
}

// TestQUICModeHandshakeFailureRetriesOnSamePair drops relay data frames, so the
// QUIC handshake times out: OpenStream reports ErrPeerUnreachable, no KCP pair
// exists, and once the data path heals the next open succeeds on the same pair
// and relay underlay.
func TestQUICModeHandshakeFailureRetriesOnSamePair(t *testing.T) {
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
	a := newQUICTestEngine(t, url, "", privA)
	b := newQUICTestEngine(t, url, echo, privB)
	// Keep the failed handshake short. The budget has to span at least one
	// QUIC retransmission (the relay saw the first Initial), or the server's
	// listener window can close between two of the client's retries. B's budget
	// is set explicitly too: its listener must outlive A's failure and retry,
	// rather than depending on the package default staying longer than A's.
	const aHandshake = 2 * time.Second
	a.quicCfg.HandshakeTimeout = aHandshake
	b.quicCfg.HandshakeTimeout = 2 * aHandshake
	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := b.Connect(); err != nil {
		t.Fatal(err)
	}

	rs.setDropData(true)
	conn, err := a.OpenStream(b.PublicKey())
	if err == nil {
		conn.Close()
		t.Fatal("OpenStream succeeded while relay data was dropped")
	}
	if !errors.Is(err, p2p.ErrPeerUnreachable) {
		t.Fatalf("OpenStream error = %v, want ErrPeerUnreachable", err)
	}
	if n := relayKCPCount(a); n != 0 {
		t.Fatalf("engine built %d KCP pairs after handshake failure, want 0", n)
	}
	pair := a.getQUIC(b.pub)
	if pair == nil {
		t.Fatal("no QUIC pair retained for a retry")
	}

	rs.setDropData(false)
	conn, err = a.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("OpenStream after relay recovery: %v", err)
	}
	roundTrip(t, conn, "retry on same pair")
	conn.Close()

	if got := a.getQUIC(b.pub); got != pair {
		t.Fatal("retry replaced the QUIC pair instead of reusing it")
	}
	if n := relayKCPCount(a); n != 0 {
		t.Fatalf("engine built %d KCP pairs after retry, want 0", n)
	}
}

// TestQUICPairForDoesNotResurrectDeletedState pins the guard that keeps a
// closed peer from getting a new pair: quicPairFor must re-check map identity
// instead of recreating the state entry (which would pin a zero fingerprint).
func TestQUICPairForDoesNotResurrectDeletedState(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newQUICTestEngine(t, url, "", priv)
	peer := derpclient.PublicKey{0x33}
	fp := [32]byte{0x44}

	e.quicMu.Lock()
	e.quicPeerLocked(peer)
	e.quicMu.Unlock()
	pair := e.quicPairFor(peer, quicRoleClient, fp)
	if pair == nil {
		t.Fatal("quicPairFor returned nil for a live state")
	}
	e.quicMu.Lock()
	if got := e.quics[peer].pairFP; got != fp {
		e.quicMu.Unlock()
		t.Fatalf("pair fingerprint = %x, want %x", got, fp)
	}
	delete(e.quics, peer)
	e.quicMu.Unlock()

	if got := e.quicPairFor(peer, quicRoleClient, fp); got != nil {
		t.Fatal("quicPairFor resurrected a deleted state")
	}
	e.quicMu.Lock()
	_, resurrected := e.quics[peer]
	e.quicMu.Unlock()
	if resurrected {
		t.Fatal("quicPairFor recreated a deleted state entry")
	}
	pair.close()
}

// TestQUICRelayUnderlayDoesNotResurrectDeletedState pins the same guard on the
// underlay install path: it must fail rather than recreate a state entry for a
// peer whose state was already dropped.
func TestQUICRelayUnderlayDoesNotResurrectDeletedState(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newQUICTestEngine(t, url, "", priv)
	peer := derpclient.PublicKey{0x34}
	fp := [32]byte{0x45}

	e.quicMu.Lock()
	e.quicPeerLocked(peer)
	e.quicMu.Unlock()
	pair := e.quicPairFor(peer, quicRoleClient, fp)
	if pair == nil {
		t.Fatal("quicPairFor returned nil for a live state")
	}
	pc := e.peerConn(peer)
	e.quicMu.Lock()
	delete(e.quics, peer)
	e.quicMu.Unlock()

	if err := e.quicRelayUnderlay(peer, pair, pc); err == nil {
		t.Fatal("quicRelayUnderlay succeeded after the state was deleted")
	}
	e.quicMu.Lock()
	_, resurrected := e.quics[peer]
	e.quicMu.Unlock()
	if resurrected {
		t.Fatal("quicRelayUnderlay recreated a deleted state entry")
	}
	pair.close()
}

// TestQUICTransportErrorDoesNotResurrectClosedState pins the late-error guard:
// an establishment that unwinds after closeQUIC must not recreate the state the
// close just dropped, while the next explicit establishment still can.
func TestQUICTransportErrorDoesNotResurrectClosedState(t *testing.T) {
	e := &engine{quics: make(map[derpclient.PublicKey]*quicPeer)}
	peer := derpclient.PublicKey{0x56}

	e.quicMu.Lock()
	e.quicPeerLocked(peer)
	e.quicMu.Unlock()
	e.closeQUIC(peer)

	e.setQUICTransportError(peer, "caps-timeout")
	e.quicMu.Lock()
	_, resurrected := e.quics[peer]
	e.quicMu.Unlock()
	if resurrected {
		t.Fatal("setQUICTransportError recreated a state closeQUIC dropped")
	}

	// A new establishment clears the tombstone: its own outcome is recorded.
	e.quicMu.Lock()
	e.quicPeerLocked(peer)
	e.quicMu.Unlock()
	e.setQUICTransportError(peer, "caps-timeout")
	e.quicMu.Lock()
	got := ""
	if qp := e.quics[peer]; qp != nil {
		got = qp.lastErr
	}
	e.quicMu.Unlock()
	if got != "caps-timeout" {
		t.Fatalf("lastErr = %q, want caps-timeout after an explicit new attempt", got)
	}
}

// TestQUICCloseUnderlayConcurrent hammers the teardown/install interleaving.
// closeQUIC must snapshot pair, relay and relayUp under quicMu, because
// quicRelayUnderlay sets relayUp under that lock after installing the underlay;
// reading the fields unlocked is the data race the race detector flags here.
func TestQUICCloseUnderlayConcurrent(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newQUICTestEngine(t, url, "", priv)

	for i := 0; i < 50; i++ {
		peer := derpclient.PublicKey{byte(i + 1)}
		e.quicMu.Lock()
		e.quicPeerLocked(peer)
		e.quicMu.Unlock()
		pair := e.quicPairFor(peer, quicRoleClient, [32]byte{byte(i + 1)})
		if pair == nil {
			t.Fatal("quicPairFor returned nil for a live state")
		}
		pc := &peerConn{e: e, peer: peer, closeCh: make(chan struct{})}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = e.quicRelayUnderlay(peer, pair, pc)
		}()
		go func() {
			defer wg.Done()
			e.closeQUIC(peer)
		}()
		wg.Wait()

		e.quicMu.Lock()
		_, exists := e.quics[peer]
		e.quicMu.Unlock()
		if exists {
			t.Fatal("closeQUIC left the peer state behind")
		}
	}
}

// TestQUICCloseCancelsInflightSetup pins the teardown fast path: a peer whose
// state is dropped must cancel the setup context instead of leaving its waiters
// parked through the caps/handshake budget.
func TestQUICCloseCancelsInflightSetup(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newQUICTestEngine(t, url, "", priv)
	peer := derpclient.PublicKey{0x35}

	ctx, cancel := context.WithCancel(context.Background())
	e.quicMu.Lock()
	e.quicPeerLocked(peer).setup = &quicSetup{done: make(chan struct{}), cancel: cancel}
	e.quicMu.Unlock()

	e.closeQUIC(peer)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("closeQUIC did not cancel the in-flight setup")
	}
}

// TestQUICModeSinkSurvivesAdapterReplacement pins the Task 6 carry-forward:
// the data sink belongs to the adapter, so a replacement adapter must get one
// too or its inbound relay packets would fall through to the KCP path.
func TestQUICModeSinkSurvivesAdapterReplacement(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newQUICTestEngine(t, url, "", priv)
	if err := e.Connect(); err != nil {
		t.Fatal(err)
	}

	peer := derpclient.PublicKey{0x5a}
	first := e.peerConn(peer)
	if first.dataSink.Load() == nil {
		t.Fatal("no QUIC data sink on the first adapter")
	}
	first.Close()

	second := e.peerConn(peer)
	if second == first {
		t.Fatal("closed adapter was not replaced")
	}
	sink := second.dataSink.Load()
	if sink == nil {
		t.Fatal("no QUIC data sink on the replacement adapter")
	}

	// A non-nil pointer alone is weak: prove the replacement sink actually
	// routes into the current pair's relay underlay (and therefore never falls
	// through to the KCP session path).
	in := make(chan []byte, 1)
	relay := newRelayQUICConn(in, func([]byte) error { return nil }, nil, quicRelayOptions{})
	pair := newQUICPair(e, peer, quicRoleClient,
		quicTLSConfig(e.quicID, [32]byte{1}, false),
		quicConfigFromSettings(e.quicCfg), nil)
	if err := pair.addRelayUnderlay(relay); err != nil {
		t.Fatal(err)
	}
	e.quicMu.Lock()
	e.quicPeerLocked(peer).pair = pair
	e.quicMu.Unlock()

	payload := []byte("relay payload")
	(*sink)(payload)
	select {
	case got := <-in:
		if string(got) != string(payload) {
			t.Fatalf("sink delivered %q, want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replacement sink did not deliver to the QUIC pair")
	}
	if n := relayKCPCount(e); n != 0 {
		t.Fatalf("engine built %d KCP pairs, want 0", n)
	}
}
