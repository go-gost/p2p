package host

// The per-peer NAT shape as the status snapshot carries it: the engine reads
// two observations — the peer's answering endpoint against the one it
// announced, and the one-way episode on the pair's direct path — and turns
// them into the pair's verdict.
//
// It is deliberately white-box on a raw engine (no relay, no real punch), the
// way the pair-level diagnostic tests are: the facts are set on the objects
// that hold them, and the snapshot is asked for.

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// installPairUnderlay installs a direct underlay on pair without a pump: a
// real underlay would run one, and the pump's own tick would end the one-way
// episode the moment it found no traffic — the test would be racing the thing
// it measures. The socket is real because the pair closes the path's socket
// when it retires it.
func installPairUnderlay(t *testing.T, pair *relayKCPPair) *directUnderlay {
	t.Helper()
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	t.Cleanup(func() { b.Close() })
	u := newDirectUnderlay(a, udpAddrPort(t, b))
	pair.direct = u
	pair.directStop = make(chan struct{})
	return u
}

// TestPeerDiagnosticsCarryNATShape: a peer whose mapping answers from an
// endpoint it never announced, on a direct path that carries nothing, reads as
// the combination of the two — with the observation's age and the one-way
// duration attached, so a reader can tell how fresh the verdict is.
func TestPeerDiagnosticsCarryNATShape(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{63}
	dc := e.directConn(peer)
	dc.notePeerEndpoint(netip.MustParseAddrPort("203.0.113.9:51000"),
		[]netip.AddrPort{netip.MustParseAddrPort("203.0.113.4:3478")})

	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)
	u := installPairUnderlay(t, pair)

	// The live path sends and receives nothing: the one-way shape.
	now := time.Now()
	for i := 0; i < 3; i++ {
		pair.directBytesSent.Add(2048)
		pair.directOneWayDead(u)
		now = now.Add(time.Second)
	}
	time.Sleep(2 * time.Millisecond)

	out := e.peerDiagnostics(map[string]string{keyName(peer): "derp"})
	d, ok := out[keyName(peer)]
	if !ok {
		t.Fatalf("no diagnostic for peer %s", keyName(peer))
	}
	if d.NATShape != "one-way+peer-endpoint-differs" {
		t.Fatalf("NATShape = %q, want %q", d.NATShape, "one-way+peer-endpoint-differs")
	}
	if d.NATObservedAge <= 0 {
		t.Fatalf("NATObservedAge = %s, want a positive age", d.NATObservedAge)
	}
	if d.OneWayFor <= 0 {
		t.Fatalf("OneWayFor = %s, want a positive duration", d.OneWayFor)
	}
}

// TestPeerDiagnosticsCarryAnEndedOneWayEpisode: the episode outlives the
// path. The peer has fallen back to the relay — the moment the reader needs
// to know the direct path was one-way — and the snapshot still says so, dated.
func TestPeerDiagnosticsCarryAnEndedOneWayEpisode(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)
	defer func(w time.Duration) { directOneWayWindow = w }(directOneWayWindow)
	directOneWayWindow = 20 * time.Millisecond

	peer := derpclient.PublicKey{64}
	e.directConn(peer) // the peer must exist to be reported
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)
	u := installPairUnderlay(t, pair)

	// The path goes one-way and stays that way past the window: the shape
	// mattered, it declared the path dead.
	var dead bool
	for i := 0; i < 50 && !dead; i++ {
		pair.directBytesSent.Add(2048)
		time.Sleep(time.Millisecond)
		dead = pair.directOneWayDead(u)
	}
	if !dead {
		t.Fatal("the one-way path was never declared dead")
	}

	// The path is retired: the pair falls back to the relay.
	if !pair.clearDirectUnderlayIf(u, pathChangeClear) {
		t.Fatal("the direct underlay was not retired")
	}

	out := e.peerDiagnostics(map[string]string{keyName(peer): "derp"})
	d, ok := out[keyName(peer)]
	if !ok {
		t.Fatalf("no diagnostic for peer %s", keyName(peer))
	}
	if d.NATShape != "one-way" {
		t.Fatalf("NATShape = %q, want %q", d.NATShape, "one-way")
	}
	if d.OneWayFor <= 0 {
		t.Fatalf("OneWayFor = %s, want the duration the episode lasted", d.OneWayFor)
	}
	if d.OneWayAge <= 0 {
		t.Fatalf("OneWayAge = %s, want the episode dated after the retirement", d.OneWayAge)
	}
}
