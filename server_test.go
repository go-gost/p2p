package main

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

// TestOpenTunnelHubRefusesUDP: with hub mode on, a udp OpenTunnel is refused —
// the hub owns those channels, so a stray GOST dial cannot replace a hub edge.
// tcp is unaffected.
func TestOpenTunnelHubRefusesUDP(t *testing.T) {
	e := newTestEngine(t)
	_, spec := startHubStub(t)
	if err := e.addTargets([]string{spec}); err != nil {
		t.Fatal(err)
	}
	_, key, _ := derpclient.Generate()
	if err := e.EnableHub([]derpclient.PublicKey{key}); err != nil {
		t.Fatal(err)
	}
	s := newServer(e)
	peer := keyName(key)

	if _, err := s.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: peer, Network: "udp"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("hub udp OpenTunnel = %v, want PermissionDenied", err)
	}
	if _, err := s.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: peer, Network: "tcp"}); err != nil {
		t.Fatalf("hub tcp OpenTunnel = %v, want nil", err)
	}
}
