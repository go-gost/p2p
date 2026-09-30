package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/go-gost/p2p"
)

// TestReport pins the report's shape and its verdicts against a hand-built
// snapshot — two peers, one relay-only with a punch trace and one direct — so
// the formatter is verified without a live host.
func TestReport(t *testing.T) {
	const (
		relayKey  = "relayPEERkey"
		directKey = "directPEERkey"
	)
	yes := true
	st := p2p.Status{
		Tunnels:        2,
		DirectPeers:    1,
		DerpPeers:      1,
		PunchAttempts:  5,
		PunchSuccess:   3,
		StreamsDirect:  10,
		StreamsDerp:    2,
		EncryptedPeers: 2,
		RelayConnected: true,
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{
			relayKey: {
				Path:       "failed",
				State:      "backoff",
				Failed:     true,
				LastError:  "seed failed: timeout",
				Candidates: 2,
				Caps:       []string{"ipv6"},
				Attempts:   4,
				Trace:      []string{"round: seed ok", "round: seed failed: timeout"},
			},
			directKey: {
				Path:        "direct",
				State:       "up",
				PeerAddr:    "203.0.113.5:5678",
				Candidates:  1,
				SessionAge:  12 * time.Second,
				LastRecvAge: 300 * time.Millisecond,
				Attempts:    1,
				Ups:         1,
			},
		},
	}
	opts := Options{
		Version:  "test-ver",
		Host:     "127.0.0.1:9000",
		Identity: "LOCALKEY",
		RelayURL: "wss://relay.example/derp",
		Direct:   &yes,
	}

	out := Report(st, opts)

	for _, want := range []string{
		"p2p doctor test-ver",
		"host:",
		"127.0.0.1:9000",
		"local key:",
		"LOCALKEY",
		"relay:",
		"wss://relay.example/derp",
		"relay state:",
		"connected",
		"direct path:",
		"on",
		"summary:",
		"tunnels:",
		"5 attempts, 3 success",
		"peers:",
		relayKey,
		"last error:",
		"seed failed: timeout",
		"trace:",
		"round: seed ok",
		directKey,
		"session age:",
		"12s",
		"verdicts:",
		"relay: connected",
		"encryption: every connected peer",
		"STUN: not configured",
		"peer " + relayKey + ": on the relay; punch failed (seed failed: timeout) — candidates 2",
		"peer " + directKey + ": direct path up (session 12s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n---\n%s", want, out)
		}
	}
}

// TestReportVerdicts covers the derived one-liners the main test does not: an
// unreachable relay outranking the inference, and --peer narrowing (found and
// absent).
func TestReportVerdicts(t *testing.T) {
	st := p2p.Status{
		DirectPeers: 1,
		DerpPeers:   1,
		RelayError:  "dial tcp: connection refused",
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{
			"a": {Path: "derp"},
			"b": {Path: "direct", SessionAge: time.Second},
		},
	}
	opts := Options{Version: "v", RelayURL: "wss://r/derp", STUN: "stun.example:3478"}

	out := Report(st, opts)
	if !strings.Contains(out, "relay: UNREACHABLE (dial tcp: connection refused)") {
		t.Errorf("relay error not surfaced:\n%s", out)
	}
	if !strings.Contains(out, "STUN stun.example:3478: configured") {
		t.Errorf("stun configured verdict missing:\n%s", out)
	}

	narrowed := Report(st, Options{Version: "v", Peer: "b"})
	if !strings.Contains(narrowed, "peer b: direct path up") {
		t.Errorf("narrowed report dropped the peer verdict:\n%s", narrowed)
	}
	if strings.Contains(narrowed, "peer a:") {
		t.Errorf("narrowed report kept another peer:\n%s", narrowed)
	}

	absent := Report(st, Options{Version: "v", Peer: "zzz"})
	if !strings.Contains(absent, "peer zzz: not connected") {
		t.Errorf("absent peer not reported:\n%s", absent)
	}
}

// TestReportDegradesWithoutRelayState pins the degradation a gRPC caller that
// does not carry the relay fields still gets: the state is inferred from a peer
// served over the relay, and otherwise reported as unknown.
func TestReportDegradesWithoutRelayState(t *testing.T) {
	served := p2p.Status{
		DerpPeers:       1,
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{"k": {Path: "derp"}},
	}
	if out := Report(served, Options{}); !strings.Contains(out, "relay: connected (peer k is served over it)") {
		t.Errorf("relay not inferred from a served peer:\n%s", out)
	}

	none := p2p.Status{}
	out := Report(none, Options{})
	if !strings.Contains(out, "relay state:") || !strings.Contains(out, "not reported by the control plane") {
		t.Errorf("unknown relay state not reported:\n%s", out)
	}
	if !strings.Contains(out, "relay: unknown (not reported by the control plane)") {
		t.Errorf("unknown relay verdict missing:\n%s", out)
	}
}
