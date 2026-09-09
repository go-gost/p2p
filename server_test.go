package main

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestAddForward covers spec parsing and the DERP-mode gate. A valid spec
// binds a real listener and registers one tunnel; the engine is a zero value
// because startTunnel never calls an engine method during construction.
func TestAddForward(t *testing.T) {
	s := newServer("127.0.0.1", nil)

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
