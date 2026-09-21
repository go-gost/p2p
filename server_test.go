package p2p

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/go-gost/plugin/p2p/proto"
)

// TestStatusNoEngine covers stub mode (--derp unset): Status must report zeros
// rather than dereferencing a nil engine.
func TestStatusNoEngine(t *testing.T) {
	s := newServer(nil)
	reply, err := s.Status(context.Background(), &proto.StatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Tunnels != 0 || reply.DirectPeers != 0 || reply.DerpPeers != 0 ||
		reply.PunchAttempts != 0 || reply.PunchSuccess != 0 ||
		reply.StreamsDirect != 0 || reply.StreamsDerp != 0 {
		t.Fatalf("stub-mode Status = %+v, want all zeros", reply)
	}
}

// TestStatusReportsTransportStats covers engine mode: the gauges and counters
// reach the reply.
func TestStatusReportsTransportStats(t *testing.T) {
	e := &Engine{
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
	reply, err := s.Status(context.Background(), &proto.StatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if reply.DirectPeers != 1 || reply.DerpPeers != 1 {
		t.Fatalf("gauges = %d/%d, want 1/1", reply.DirectPeers, reply.DerpPeers)
	}
	if reply.PunchAttempts != 7 || reply.PunchSuccess != 3 ||
		reply.StreamsDirect != 11 || reply.StreamsDerp != 5 {
		t.Fatalf("counters = %d/%d/%d/%d, want 7/3/11/5",
			reply.PunchAttempts, reply.PunchSuccess, reply.StreamsDirect, reply.StreamsDerp)
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

	s.engine = &Engine{}

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
	got, err := s.Status(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
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
	s.engine = &Engine{}

	_, pub, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(pub[:])
	if err := s.addForward("127.0.0.1:0=" + key); err != nil {
		t.Fatalf("addForward(valid) = %v, want nil", err)
	}

	time.Sleep(120 * time.Millisecond) // > TTL: several sweeps must skip it
	if got := tunnelCount(s); got != 1 {
		t.Fatalf("forward tunnel reclaimed by the GC: count = %d, want 1", got)
	}

	for _, tn := range s.tunnels {
		tn.close()
	}
}
