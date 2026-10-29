package host

import (
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestQUICStrictMultiPeerIsolation pins the per-peer transport boundary: one
// host with two QUIC peers owns two independent pairs, each with its own
// quic.Transport (a zero-length CID cannot demultiplex), multiPathConn and
// relay underlay. Killing the connection to one peer must not disturb the
// other peer's pair or streams, and no KCP pair may appear on any side.
func TestQUICStrictMultiPeerIsolation(t *testing.T) {
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
	privC, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}

	a := newQUICTestEngine(t, url, echo, privA)
	b := newQUICTestEngine(t, url, echo, privB)
	c := newQUICTestEngine(t, url, echo, privC)
	for name, e := range map[string]*engine{"a": a, "b": b, "c": c} {
		if err := e.Connect(); err != nil {
			t.Fatalf("connect %s: %v", name, err)
		}
	}

	openAndRoundTrip := func(dst *engine, payload string) {
		t.Helper()
		conn, err := a.OpenStream(dst.PublicKey())
		if err != nil {
			t.Fatalf("OpenStream %s: %v", payload, err)
		}
		roundTrip(t, conn, payload)
		conn.Close()
	}
	openAndRoundTrip(b, "a-to-b")
	openAndRoundTrip(c, "a-to-c")

	// Hold one A-C stream open across the A-B teardown: a tunnel that survives
	// a different peer's connection death is the isolation the contract needs,
	// not just a pair that can be rebuilt afterwards.
	streamC, err := a.OpenStream(c.PublicKey())
	if err != nil {
		t.Fatalf("open persistent A-C stream: %v", err)
	}
	t.Cleanup(func() { streamC.Close() })
	roundTrip(t, streamC, "a-to-c-before-b-close")

	waitFor(t, 10*time.Second, func() bool {
		return quicPairEstablished(a, b.pub) && quicPairEstablished(a, c.pub)
	})
	pairB, pairC := a.getQUIC(b.pub), a.getQUIC(c.pub)
	if pairB == nil || pairC == nil {
		t.Fatal("a is missing one of its two QUIC pairs")
	}
	if pairB == pairC {
		t.Fatal("a reused one quicPair for two peers")
	}

	pairB.mu.Lock()
	trB, mpB, relayB := pairB.tr, pairB.mp, pairB.relay
	pairB.mu.Unlock()
	pairC.mu.Lock()
	trC, mpC, relayC := pairC.tr, pairC.mp, pairC.relay
	pairC.mu.Unlock()

	if trB == nil || trC == nil {
		t.Fatalf("missing per-peer transports: b=%v c=%v", trB, trC)
	}
	if trB == trC {
		t.Fatal("two peers share one quic.Transport; zero-length CIDs cannot demultiplex")
	}
	if trB.ConnectionIDGenerator == nil || trC.ConnectionIDGenerator == nil {
		t.Fatal("per-peer transport has no connection ID generator")
	}
	if got := trB.ConnectionIDGenerator.ConnectionIDLen(); got != 0 {
		t.Fatalf("peer b connection ID length = %d, want 0", got)
	}
	if got := trC.ConnectionIDGenerator.ConnectionIDLen(); got != 0 {
		t.Fatalf("peer c connection ID length = %d, want 0", got)
	}
	if mpB == mpC {
		t.Fatal("two peers share one multiPathConn")
	}
	if relayB == nil || relayC == nil {
		t.Fatal("missing relay underlay on a QUIC pair")
	}
	if relayB == relayC {
		t.Fatal("two peers share one relay underlay; cross-routing is possible")
	}

	// The accepting side must be isolated the same way.
	waitFor(t, 10*time.Second, func() bool {
		return quicPairEstablished(b, a.pub) && quicPairEstablished(c, a.pub)
	})
	pairBA, pairCA := b.getQUIC(a.pub), c.getQUIC(a.pub)
	if pairBA == nil || pairCA == nil {
		t.Fatal("accepting side is missing a per-peer QUIC pair")
	}
	if pairBA == pairCA {
		t.Fatal("accepting side reused one quicPair for two peers")
	}
	pairBA.mu.Lock()
	trBA := pairBA.tr
	pairBA.mu.Unlock()
	pairCA.mu.Lock()
	trCA := pairCA.tr
	pairCA.mu.Unlock()
	if trBA == nil || trCA == nil || trBA == trCA {
		t.Fatalf("accepting side transports are not per-peer: %v/%v", trBA, trCA)
	}

	// Kill only the A-B connection. The A-C pair must survive untouched: same
	// pair, same transport, same connection, same open stream.
	pairB.mu.Lock()
	connB := pairB.conn
	pairB.mu.Unlock()
	pairC.mu.Lock()
	connC := pairC.conn
	pairC.mu.Unlock()
	if connB == nil {
		t.Fatal("peer b has no QUIC connection to close")
	}
	if err := connB.CloseWithError(0, "test close"); err != nil {
		t.Fatalf("close peer b connection: %v", err)
	}
	// Let a observe the death (and, if it already rebuilt the peer, let that
	// rebuild run) before checking peer c: an isolation bug that tears down
	// every pair on one connection's death must have time to show up here.
	waitFor(t, 5*time.Second, func() bool { return a.getQUIC(b.pub) != pairB })

	if got := a.getQUIC(c.pub); got != pairC {
		t.Fatalf("closing peer b replaced peer c's pair: %p -> %p", pairC, got)
	}
	pairC.mu.Lock()
	connCAfter := pairC.conn
	pairC.mu.Unlock()
	if connCAfter == nil {
		t.Fatal("peer c lost its QUIC connection when peer b was closed")
	}
	if connCAfter != connC {
		t.Fatalf("peer c's connection changed when peer b was closed: %p -> %p", connC, connCAfter)
	}
	if !pairC.established() {
		t.Fatal("peer c's QUIC pair stopped being established after peer b closed")
	}
	if got := c.getQUIC(a.pub); got != pairCA {
		t.Fatalf("peer b's close reached peer c's accepting pair: %p -> %p", pairCA, got)
	}

	roundTrip(t, streamC, "a-to-c-after-b-close")
	streamC.Close()
	openAndRoundTrip(c, "a-to-c-new-stream-after-b-close")

	for name, e := range map[string]*engine{"a": a, "b": b, "c": c} {
		if n := relayKCPCount(e); n != 0 {
			t.Fatalf("%s built %d KCP pairs in QUIC mode, want 0", name, n)
		}
	}
}
