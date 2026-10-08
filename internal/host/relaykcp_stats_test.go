package host

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestPeerDiagnosticsReportsRelayKCPStats pins the diagnostic surface: a peer
// with a live relay session reports its relay KCP session health through
// Status.PeerDiagnostics, read the same way RelayRebuilds is. It asserts on the
// field values that are deterministic (Live, Conv, the configured MTU/window
// constants, and non-negative counters), never on SRTT/RTO values — those are
// kcp-go's timing and would be flaky.
func TestPeerDiagnosticsReportsRelayKCPStats(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{11}
	settled, _ := settledSecurePair(t, secureTransportRelay)
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, inboundQueueSize),
		closeCh: make(chan struct{}),
		secure:  settled,
	}
	e.mu.Lock()
	e.peers[peer] = pc
	e.mu.Unlock()
	pc.mu.Lock()
	if _, err := pc.sessionLocked(); err != nil {
		pc.mu.Unlock()
		t.Fatalf("build session: %v", err)
	}
	pc.mu.Unlock()

	d := e.peerDiagnostics(map[string]string{keyName(peer): transportRelay})[keyName(peer)]
	k := d.RelayKCP
	if !k.Live {
		t.Fatal("RelayKCP.Live = false for a peer with a built session")
	}
	if k.Conv != relayConv(e.pub, peer) {
		t.Fatalf("Conv = %d, want %d (the pair's deterministic conversation id)", k.Conv, relayConv(e.pub, peer))
	}
	if k.Mtu != relayKCPMtu {
		t.Fatalf("Mtu = %d, want the relayKCPMtu constant %d", k.Mtu, relayKCPMtu)
	}
	if k.SndWnd != relayKCPSndWnd || k.RcvWnd != relayKCPRcvWnd {
		t.Fatalf("windows = %d/%d, want %d/%d", k.SndWnd, k.RcvWnd, relayKCPSndWnd, relayKCPRcvWnd)
	}
	// Byte counters and timing stats are non-negative; their exact values are
	// traffic/timing-dependent and out of scope.
	if k.BytesSent > 1<<40 || k.BytesRcvd > 1<<40 {
		t.Fatalf("byte counters implausibly large: sent=%d rcvd=%d", k.BytesSent, k.BytesRcvd)
	}
	if k.SRTT < 0 || k.RTO < 0 || k.RTTVar < 0 {
		t.Fatalf("negative timing stat: srtt=%d rto=%d rttvar=%d", k.SRTT, k.RTO, k.RTTVar)
	}
}

// TestRelayKCPPairByteCounters pins the per-pair datagram counters we own: each
// WriteTo adds the datagram's length to bytesSent, each successful ReadFrom adds
// the delivered length to bytesRcvd. Deterministic — no KCP session is built, so
// no read loop competes for the queue, and no timing is involved.
func TestRelayKCPPairByteCounters(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{13}
	pair := newRelayKCPPair(e, peer)
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 4),
		closeCh: make(chan struct{}),
	}
	pair.register(pc)

	var wantSent, wantRcvd uint64
	for i := 0; i < 3; i++ {
		pkt := make([]byte, 100+i)
		wantSent += uint64(len(pkt))
		if n, err := pair.WriteTo(pkt, nil); err != nil || n != len(pkt) {
			t.Fatalf("WriteTo = %d, %v; want %d, nil", n, err, len(pkt))
		}
	}
	for i := 0; i < 2; i++ {
		pkt := make([]byte, 50+i)
		pc.inbound <- pkt
		wantRcvd += uint64(len(pkt))
		n, _, err := pair.ReadFrom(make([]byte, 128))
		if err != nil || n != len(pkt) {
			t.Fatalf("ReadFrom = %d, %v; want %d, nil", n, err, len(pkt))
		}
	}

	s := pair.snapshot()
	if s.bytesSent != wantSent {
		t.Fatalf("bytesSent = %d, want %d", s.bytesSent, wantSent)
	}
	if s.bytesRcvd != wantRcvd {
		t.Fatalf("bytesRcvd = %d, want %d", s.bytesRcvd, wantRcvd)
	}
	if s.present {
		t.Fatal("snapshot reports a session that was never built")
	}
}

// TestRelayKCPStatsOnResetLog pins that the KCP epoch-reset line carries the
// pair's KCP stats as structured fields, read before the session is dropped.
// It asserts on the stable, greppable field names and the configured constants,
// not on SRTT/RTO values.
func TestRelayKCPStatsOnResetLog(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{17}
	settled, _ := settledSecurePair(t, secureTransportRelay)
	pc := e.peerConn(peer)
	pc.mu.Lock()
	pc.secure = settled
	pc.mu.Unlock()
	pc.mu.Lock()
	if _, err := pc.sessionLocked(); err != nil {
		pc.mu.Unlock()
		t.Fatalf("build session: %v", err)
	}
	pc.mu.Unlock()

	pc.killSession(errors.New("test: link lost"), true, reasonLinkLost)

	attrs := capture.nth("relay kcp pair reset", 0)
	if attrs == nil {
		t.Fatal("the epoch-ending kill logged no \"relay kcp pair reset\" record")
	}
	// Existing fields are preserved.
	if attrs["peer"] == "" || attrs["gen"] == "" || attrs["cause"] == "" {
		t.Fatalf("reset log lost an existing field: %v", attrs)
	}
	if attrs["kcpConv"] == "" {
		t.Fatal("reset log carries no kcpConv")
	}
	if got := attrs["kcpMtu"]; got != fmt.Sprint(relayKCPMtu) {
		t.Fatalf("kcpMtu = %q, want %d", got, relayKCPMtu)
	}
	if got := attrs["kcpSndWnd"]; got != fmt.Sprint(relayKCPSndWnd) {
		t.Fatalf("kcpSndWnd = %q, want %d", got, relayKCPSndWnd)
	}
	if got := attrs["kcpRcvWnd"]; got != fmt.Sprint(relayKCPRcvWnd) {
		t.Fatalf("kcpRcvWnd = %q, want %d", got, relayKCPRcvWnd)
	}
	if attrs["kcpSrtt"] == "" || attrs["kcpRto"] == "" || attrs["kcpRttVar"] == "" {
		t.Fatal("reset log is missing a KCP timing stat")
	}
	if attrs["kcpBytesSent"] == "" || attrs["kcpBytesRcvd"] == "" {
		t.Fatal("reset log is missing a KCP byte counter")
	}
}

// TestRelayKCPStatsOnRebuildLog pins that the clean-kill rebuild line carries
// the surviving pair KCP session's stats: a clean kill keeps the pair, so its
// health rides the rebuild line; an epoch-ending kill would have dropped the
// pair and carries no KCP attrs.
func TestRelayKCPStatsOnRebuildLog(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{19}
	settled, _ := settledSecurePair(t, secureTransportRelay)
	pc := e.peerConn(peer)
	pc.mu.Lock()
	pc.secure = settled
	pc.mu.Unlock()
	pc.mu.Lock()
	if _, err := pc.sessionLocked(); err != nil {
		pc.mu.Unlock()
		t.Fatalf("build session: %v", err)
	}
	pc.mu.Unlock()

	pc.killSession(errors.New("test: clean kill"), true, reasonLocalKill)
	if got := e.peerConn(peer); got == pc {
		t.Fatal("the killed adapter was handed back instead of a replacement")
	}

	attrs := capture.nth("relay session rebuilt", 0)
	if attrs == nil {
		t.Fatal("replacing a killed adapter logged no \"relay session rebuilt\" record")
	}
	if attrs["gen"] == "" {
		t.Fatal("rebuild log carries no gen")
	}
	if attrs["kcpConv"] == "" {
		t.Fatal("rebuild log carries no kcpConv (the clean kill kept the pair)")
	}
	if got := attrs["kcpMtu"]; got != fmt.Sprint(relayKCPMtu) {
		t.Fatalf("kcpMtu = %q, want %d", got, relayKCPMtu)
	}
	if attrs["kcpSrtt"] == "" || attrs["kcpRto"] == "" || attrs["kcpRttVar"] == "" {
		t.Fatal("rebuild log is missing a KCP timing stat")
	}
	if attrs["kcpBytesSent"] == "" || attrs["kcpBytesRcvd"] == "" {
		t.Fatal("rebuild log is missing a KCP byte counter")
	}
}

// TestRelayKCPPairFreshestRecv pins the merged underlay recency the peer-down
// observability reads: the FRESHER of the two underlays' last inbound datagram.
// Not the relay's stamp alone (a peer alive on the direct underlay leaves the
// relay's stamp aging, so the relay-only read calls a live peer silent), and not
// gated on the pair's presence (a kill that resets the pair's KCP epoch retires
// the session while the recency is exactly what explains the death).
func TestRelayKCPPairFreshestRecv(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{23}
	relayAt := time.Date(2026, 1, 1, 0, 0, 3, 0, time.UTC)
	directAt := time.Date(2026, 1, 1, 0, 0, 7, 0, time.UTC)

	tests := []struct {
		name           string
		lastRelayRecv  time.Time
		lastDirectRecv time.Time
		want           time.Time
		wantOK         bool
	}{
		{"neither underlay heard from", time.Time{}, time.Time{}, time.Time{}, false},
		{"relay only", relayAt, time.Time{}, relayAt, true},
		{"direct only", time.Time{}, directAt, directAt, true},
		{"direct fresher", relayAt, directAt, directAt, true},
		{"relay fresher", directAt, relayAt, directAt, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pair := newRelayKCPPair(e, peer)
			t.Cleanup(pair.shutdown)
			pair.lastRelayRecv = tc.lastRelayRecv
			pair.lastDirectRecv = tc.lastDirectRecv

			got, ok := pair.freshestRecv()
			if ok != tc.wantOK {
				t.Fatalf("freshestRecv ok = %v, want %v", ok, tc.wantOK)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("freshestRecv = %v, want %v", got, tc.want)
			}
		})
	}

	// No KCP session exists in any case above, and that must not hide the
	// recency: absent-session is the state a kill leaves behind, and the
	// peer-down observability reads this precisely then.
	pair := newRelayKCPPair(e, peer)
	t.Cleanup(pair.shutdown)
	if pair.snapshot().present {
		t.Fatal("a fresh pair reports a live KCP session")
	}
	pair.lastDirectRecv = directAt
	if got, ok := pair.freshestRecv(); !ok || !got.Equal(directAt) {
		t.Fatalf("freshestRecv with no KCP session = %v, %v; want %v, true", got, ok, directAt)
	}
}

// TestEngineRelayKCPFreshness pins the engine-side read: a peer the engine has
// no pair for reports no recency, rather than a zero time that would age into
// "since 1970" in a downstream log.
func TestEngineRelayKCPFreshness(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)

	peer := derpclient.PublicKey{29}
	if at, ok := e.relayKCPFreshness(peer); ok {
		t.Fatalf("freshness for a peer with no pair = %v, true; want false", at)
	}

	at := time.Date(2026, 1, 1, 0, 0, 11, 0, time.UTC)
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)
	pair.lastRelayRecv = at
	got, ok := e.relayKCPFreshness(peer)
	if !ok || !got.Equal(at) {
		t.Fatalf("relayKCPFreshness = %v, %v; want %v, true", got, ok, at)
	}
}
