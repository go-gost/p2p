package host

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestStatusNoEngine covers stub mode (--derp unset): Status must report zeros
// rather than dereferencing a nil engine.
func TestStatusNoEngine(t *testing.T) {
	s := newServer(nil)
	st := s.status()
	if st.Tunnels != 0 || st.DirectPeers != 0 || st.DerpPeers != 0 ||
		st.PunchAttempts != 0 || st.PunchSuccess != 0 ||
		st.StreamsDirect != 0 || st.StreamsDerp != 0 {
		t.Fatalf("stub-mode Status = %+v, want all zeros", st)
	}
	if st.RelayConnected || st.PeerDiagnostics != nil {
		t.Errorf("stub-mode relay/peer fields = %v/%v, want false/nil", st.RelayConnected, st.PeerDiagnostics)
	}
}

// TestStatusReportsTransportStats covers engine mode: the gauges and counters
// reach the reply.
func TestStatusReportsTransportStats(t *testing.T) {
	e := &engine{
		directs: make(map[derpclient.PublicKey]*directConn),
		peers:   make(map[derpclient.PublicKey]*peerConn),
	}
	e.stats.punchAttempts.Store(7)
	e.stats.punchSuccess.Store(3)
	e.stats.streamsDirect.Store(11)
	e.stats.streamsDerp.Store(5)

	peerDirect := derpclient.PublicKey{1}
	peerRelay := derpclient.PublicKey{2}
	dc := &directConn{e: e, peer: peerDirect, sock: mustListenUDP(t), state: directUp}
	dc.attempts.Store(4)
	dc.ups.Store(2)
	dc.drops.Store(1)
	e.directs[peerDirect] = dc
	e.peers[peerRelay] = &peerConn{peer: peerRelay, sess: newTestSess(t)}

	s := newServer(e)
	st := s.status()
	if st.DirectPeers != 1 || st.DerpPeers != 1 {
		t.Fatalf("gauges = %d/%d, want 1/1", st.DirectPeers, st.DerpPeers)
	}
	if st.PunchAttempts != 7 || st.PunchSuccess != 3 ||
		st.StreamsDirect != 11 || st.StreamsDerp != 5 {
		t.Fatalf("counters = %d/%d/%d/%d, want 7/3/11/5",
			st.PunchAttempts, st.PunchSuccess, st.StreamsDirect, st.StreamsDerp)
	}

	// The relay's own state, and the direct peer's punch history.
	if st.RelayConnected {
		t.Error("RelayConnected = true, want false for an engine with no client")
	}
	if st.RelayRTT != 0 {
		t.Errorf("RelayRTT = %d, want 0 for an engine with no client", st.RelayRTT)
	}
	if got, ok := st.PeerDiagnostics[base64.RawURLEncoding.EncodeToString(peerDirect[:])]; !ok {
		t.Errorf("PeerDiagnostics has no entry for the direct peer: %+v", st.PeerDiagnostics)
	} else if got.Attempts != 4 || got.Ups != 2 || got.Drops != 1 {
		t.Errorf("PeerDiagnostic = %+v, want attempts=4 ups=2 drops=1", got)
	}
}

// TestRelayRTTMillis pins the conversion the status line does: a loopback or
// LAN relay answers a ping in well under a millisecond, and a truncating
// Milliseconds() would report 0 for it — the value that means "not measured" —
// so every fast relay would read as unmeasured. Round half up, with a 1ms
// floor for any answered ping; zero stays zero (no client, no ping answered).
func TestRelayRTTMillis(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want int64
	}{
		{0, 0},
		{1, 1},
		{300 * time.Microsecond, 1},
		{900 * time.Microsecond, 1},
		{1400 * time.Microsecond, 1},
		{1500 * time.Microsecond, 2},
		{1600 * time.Microsecond, 2},
		{2600 * time.Microsecond, 3},
		{42 * time.Millisecond, 42},
	} {
		if got := relayRTTMillis(tc.d); got != tc.want {
			t.Errorf("relayRTTMillis(%v) = %d, want %d", tc.d, got, tc.want)
		}
	}
}

// TestStatusRelayRTTIsVisible is the end-to-end shape of the rounding: a relay
// that has answered a ping over loopback (a sub-millisecond round trip, the
// normal case on a LAN relay) must reach Status as at least 1ms. The
// truncating conversion reported it as 0, which the report then rendered as
// "not measured yet" for a relay that was measured.
func TestStatusRelayRTTIsVisible(t *testing.T) {
	url, _ := startCountingDERPServer(t)

	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := derpclient.Dial(context.Background(), url, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// A reader is what turns the server's reply into a stamped pong: Recv
	// consumes pongs internally.
	go func() {
		for {
			if _, _, err := c.Recv(); err != nil {
				return
			}
		}
	}()
	if err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	var rtt time.Duration
	for deadline := time.Now().Add(2 * time.Second); rtt == 0 && time.Now().Before(deadline); {
		rtt = c.LastRTT()
		time.Sleep(5 * time.Millisecond)
	}
	if rtt == 0 {
		t.Fatal("no pong within the deadline: the test server must answer a ping")
	}

	st := newServer(&engine{client: c}).status()
	if st.RelayRTT < 1 {
		t.Errorf("RelayRTT = %d, want >= 1 for a measured round trip of %v",
			st.RelayRTT, rtt)
	}
}

// TestAddForward covers spec parsing and the DERP-mode gate. A valid spec
// binds a real listener and registers one tunnel; the engine is a zero value
// because startTunnel never calls an engine method during construction.
func TestAddForward(t *testing.T) {
	s := newServer(nil)

	// DERP mode gate: no engine → error even for an otherwise-valid spec.
	if err := s.addForward("127.0.0.1:0=x"); err == nil {
		t.Fatal("addForward without --derp = nil, want error")
	}

	s.engine = &engine{}

	// Malformed specs.
	for _, spec := range []string{
		"",                         // empty
		"no-equals",                // missing '='
		"=peerkey",                 // empty listen addr
		"127.0.0.1:0=",             // empty peer key
		"not-a-host",               // SplitHostPort fails
		"127.0.0.1:0=not-base64!!", // invalid peer key
	} {
		if err := s.addForward(spec); err == nil {
			t.Fatalf("addForward(%q) = nil, want error", spec)
		}
	}

	// Valid spec: a real 32-byte base64 public key on an ephemeral port.
	_, pub, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(pub[:])
	if err := s.addForward("127.0.0.1:0=" + key); err != nil {
		t.Fatalf("addForward(valid) = %v, want nil", err)
	}
	got := s.status()
	if got.Tunnels != 1 {
		t.Fatalf("tunnel count = %d, want 1", got.Tunnels)
	}

	for _, tn := range s.tunnels {
		tn.close()
	}
}

// TestForwardSurvivesGC: --forward listeners live for the process lifetime —
// the pending GC must only reclaim stream records (those without a listener).
func TestForwardSurvivesGC(t *testing.T) {
	oldTTL, oldInterval := pendingTTL, gcInterval
	pendingTTL, gcInterval = 30*time.Millisecond, 10*time.Millisecond
	defer func() { pendingTTL, gcInterval = oldTTL, oldInterval }()

	s := newServer(nil)
	s.engine = &engine{}

	_, pub, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(pub[:])
	if err := s.addForward("127.0.0.1:0=" + key); err != nil {
		t.Fatalf("addForward(valid) = %v, want nil", err)
	}

	time.Sleep(120 * time.Millisecond) // > TTL: several sweeps must skip it
	s.mu.Lock()
	n := len(s.tunnels)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("forward tunnel reclaimed by the GC: count = %d, want 1", n)
	}

	for _, tn := range s.tunnels {
		tn.close()
	}
}
