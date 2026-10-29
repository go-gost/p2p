package host

import (
	"errors"
	"io"
	"log/slog"
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
	// The relay path is the only one wired into QUIC by this change; keeping
	// the punch off also keeps a stray candidate frame from building KCP.
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
	// listener window can close between two of the client's retries.
	a.quicCfg.HandshakeTimeout = 2 * time.Second
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
	if second.dataSink.Load() == nil {
		t.Fatal("no QUIC data sink on the replacement adapter")
	}
}
