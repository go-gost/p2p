package host

import (
	"strings"
	"testing"
	"time"

	"github.com/go-gost/p2p"
)

func (s *relayServer) clientCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

// TestMultipleHostsSameIdentityDifferentRelays: one process can run several
// endpoints with the same identity, one relay each. The instances are
// independent: closing one must leave the other's relay session up.
func TestMultipleHostsSameIdentityDifferentRelays(t *testing.T) {
	keyHex := strings.Repeat("ab", 32)
	direct := false

	rs1 := &relayServer{}
	url1 := rs1.start(t)
	rs2 := &relayServer{}
	url2 := rs2.start(t)

	newHost := func(url string) *Host {
		t.Helper()
		h, err := New(&p2p.Config{Derp: url, Key: keyHex, Direct: &direct})
		if err != nil {
			t.Fatalf("New(%s): %v", url, err)
		}
		if err := h.Connect(); err != nil {
			t.Fatalf("Connect(%s): %v", url, err)
		}
		return h
	}

	h1 := newHost(url1)
	h2 := newHost(url2)
	defer h1.Close()
	defer h2.Close()

	if h1.PublicKey() != h2.PublicKey() {
		t.Fatalf("public keys differ: %q != %q", h1.PublicKey(), h2.PublicKey())
	}
	waitFor(t, 2*time.Second, func() bool {
		return rs1.clientCount() == 1 && rs2.clientCount() == 1
	})

	if err := h1.Close(); err != nil {
		t.Fatalf("close h1: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return rs1.clientCount() == 0 })
	if got := rs2.clientCount(); got != 1 {
		t.Fatalf("relay 2 clients after closing host 1 = %d, want 1", got)
	}
	if st := h2.Status(); !st.RelayConnected {
		t.Fatalf("host 2 relay connection dropped with host 1: %+v", st)
	}
}
