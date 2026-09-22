package host

import (
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
	dc := &directConn{e: e, peer: peerDirect, sess: newTestSess(t), state: directUp}
	e.directs[peerDirect] = dc
	e.peers[peerRelay] = &peerConn{}

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
