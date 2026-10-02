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
// TestReportDirectConfig: the report must say which direct path the host is
// *running* with, not only the caller's "direct path: on". An embedder that
// probed STUN and got no answer hands p2p an empty server, so a host configured
// for direct runs relay-only — and that gap is invisible unless the running
// configuration is on the page.
func TestReportDirectConfig(t *testing.T) {
	st := p2p.Status{
		DirectConfig: p2p.DirectConfig{
			Direct:     true,
			Stun:       "derp.example:3478",
			StunFailed: true,
			IPv6:       false,
			Reason:     "stun-unreachable",
		},
	}
	yes := true

	out := Report(st, Options{Direct: &yes})

	for _, want := range []string{
		"direct path:", "on",
		"direct config:", "on=true",
		"derp.example:3478", "(does not answer)",
		"ipv6=false",
		"direct reason:", "stun-unreachable",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q:\n%s", want, out)
		}
	}
}

// TestReportDirectConfigOff: the switch off is the common case (relay-only),
// and it must be legible too — including when no STUN server was ever held.
func TestReportDirectConfigOff(t *testing.T) {
	st := p2p.Status{
		DirectConfig: p2p.DirectConfig{Direct: false, Reason: "disabled"},
	}
	no := false

	out := Report(st, Options{Direct: &no})

	for _, want := range []string{
		"direct path:", "off",
		"direct config:", "on=false",
		"stun=(none)",
		"direct reason:", "disabled",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q:\n%s", want, out)
		}
	}
}

// TestReportOmitsDirectConfigWhenUnreported: a control plane that does not
// carry it (the frozen gRPC proto) must not get a misleading blank line.
func TestReportOmitsDirectConfigWhenUnreported(t *testing.T) {
	if out := Report(p2p.Status{}, Options{}); strings.Contains(out, "direct config") {
		t.Errorf("report invents a direct config it was not given:\n%s", out)
	}
}

// TestReportRelayChurn: a pair whose relay session is rebuilt repeatedly is
// flapping, and that used to be visible only by grepping the log (the field case
// was five peer-rekeyed teardowns in twelve minutes). The counters show on the
// peer's block — but only when non-zero, so a healthy pair's report is not
// padded with zeros that read like a problem.
func TestReportRelayChurn(t *testing.T) {
	key := "peerkey-peerkey-peerkey-peerkey-peerkey-peerkey-pe"
	base := func(rebuilds, rekeys int64) p2p.Status {
		return p2p.Status{
			PeerTransports: map[string]string{key: "derp"},
			PeerDiagnostics: map[string]p2p.PeerDiagnostic{
				key: {Path: "derp", State: "none", RelayRebuilds: rebuilds, PeerRekeys: rekeys},
			},
		}
	}

	out := Report(base(5, 5), Options{})
	if !strings.Contains(out, "relay churn") {
		t.Errorf("flapping peer has no churn line:\n%s", out)
	}
	for _, want := range []string{"5 rebuilds", "5 peer rekeys"} {
		if !strings.Contains(out, want) {
			t.Errorf("churn line is missing %q:\n%s", want, out)
		}
	}

	if out := Report(base(0, 0), Options{}); strings.Contains(out, "relay churn") {
		t.Errorf("healthy peer carries a churn line:\n%s", out)
	}
}

// TestReportPeerDirectOffVerdict: the asymmetry is a *setting*, not a failure.
// "punch failed" names a symmetric NAT and sends the reader after a NAT problem
// that is not there; the verdict has to say the peer asked for the relay.
func TestReportPeerDirectOffVerdict(t *testing.T) {
	key := "peerkey-peerkey-peerkey-peerkey-peerkey-peerkey-pe"
	st := p2p.Status{
		PeerTransports: map[string]string{key: "peer-direct-off"},
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{
			key: {
				Path:       "peer-direct-off",
				State:      "none",
				Candidates: 0,
				Caps:       []string{"no-direct"},
			},
		},
	}

	out := Report(st, Options{})
	if !strings.Contains(out, "the peer has its direct path off") {
		t.Errorf("verdict does not name the peer's setting:\n%s", out)
	}
	// And it must not read as the punch-failure verdict.
	for _, unwanted := range []string{"punch failed", "symmetric NAT"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("verdict reads as a failure (%q):\n%s", unwanted, out)
		}
	}
}

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
