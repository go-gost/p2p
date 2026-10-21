package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/go-gost/p2p"
)

// natStatus is a snapshot with one peer's NAT shape observed.
func natStatus(shape string, observedAge, oneWay time.Duration) p2p.Status {
	return p2p.Status{
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{
			"peerKey": {
				Path:           "derp",
				State:          "backoff",
				PeerAddr:       "203.0.113.9:51000",
				NATShape:       shape,
				NATObservedAge: observedAge,
				OneWayFor:      oneWay,
			},
		},
	}
}

// verdictLine returns the one-liner the report gives a peer.
func verdictLine(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "peer peerKey:") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("no peer verdict in the report:\n%s", out)
	return ""
}

// TestPeerBlockShowsNATShape: the shape reaches the per-peer block, with the
// endpoint the peer answered from and how long ago that was seen — the
// evidence behind the word, not the word alone.
func TestPeerBlockShowsNATShape(t *testing.T) {
	out := Report(natStatus("peer-endpoint-differs", 2*time.Minute, 0), Options{InProcess: true})
	for _, want := range []string{"nat shape", "peer-endpoint-differs", "203.0.113.9:51000", "2m0s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the report is missing %q:\n%s", want, out)
		}
	}
}

// TestPeerVerdictNamesPeerEndpoint: the verdict says which endpoint the peer
// answered from and that it is not the one it announced.
func TestPeerVerdictNamesPeerEndpoint(t *testing.T) {
	out := Report(natStatus("peer-endpoint-differs", 2*time.Minute, 0), Options{InProcess: true})
	for _, want := range []string{"answers from 203.0.113.9:51000", "did not announce"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the report is missing %q:\n%s", want, out)
		}
	}
}

// TestPeerVerdictNamesOneWay: a one-way path is named as such — and it is a
// path-health fact, so the verdict must not present it as a NAT conclusion.
func TestPeerVerdictNamesOneWay(t *testing.T) {
	out := Report(natStatus("one-way", 0, 3*time.Minute), Options{InProcess: true})
	line := verdictLine(t, out)
	for _, want := range []string{"one-way", "3m0s"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the peer verdict is missing %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "NAT") {
		t.Fatalf("the peer verdict calls a one-way path a NAT conclusion: %s", line)
	}
}

// TestPeerVerdictDatesAnEndedOneWay: the one-way episode outlives the path,
// so the verdict says it happened and when — the moment a peer is back on the
// relay is when the reader needs to know the path was one-way.
func TestPeerVerdictDatesAnEndedOneWay(t *testing.T) {
	st := natStatus("one-way", 0, 3*time.Minute)
	d := st.PeerDiagnostics["peerKey"]
	d.OneWayAge = 40 * time.Second
	st.PeerDiagnostics["peerKey"] = d

	out := Report(st, Options{InProcess: true})
	line := verdictLine(t, out)
	for _, want := range []string{"was one-way for 3m0s", "40s ago"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the peer verdict is missing %q:\n%s", want, line)
		}
	}
}

// TestReportNATShapeSummary: the host-level line counts the peers that were
// observed and the ones that answer from an endpoint they did not announce. A
// peer nobody observed is in neither count.
func TestReportNATShapeSummary(t *testing.T) {
	st := p2p.Status{
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{
			"peerA": {
				Path:           "derp",
				PeerAddr:       "203.0.113.9:51000",
				NATShape:       "peer-endpoint-differs",
				NATObservedAge: 2 * time.Minute,
			},
			"peerB": {
				Path:           "derp",
				NATShape:       "one-way",
				NATObservedAge: time.Minute,
				OneWayFor:      3 * time.Minute,
			},
			"peerC": {Path: "derp"}, // never observed
		},
	}
	out := Report(st, Options{InProcess: true})
	want := "NAT shape: 1 of 2 observed peers answer from an endpoint they did not announce"
	if !strings.Contains(out, want) {
		t.Fatalf("the report is missing %q:\n%s", want, out)
	}
}

// TestReportSaysNATShapeNotReportedOverWire: the control plane does not carry
// the shape, so a wire-sourced report must say so rather than let a zero read
// as "nothing was observed".
func TestReportSaysNATShapeNotReportedOverWire(t *testing.T) {
	st := natStatus("peer-endpoint-differs", 2*time.Minute, 0)

	wire := Report(st, Options{})
	if !strings.Contains(wire, "NAT shape: not reported by the control plane") {
		t.Fatalf("the wire report does not say the shape was not reported:\n%s", wire)
	}

	local := Report(st, Options{InProcess: true})
	if strings.Contains(local, "NAT shape: not reported by the control plane") {
		t.Fatalf("the in-process report claims the control plane did not report the shape:\n%s", local)
	}
}

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
		RelayRTT:       42,
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
		"relay rtt:",
		"42ms",
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

// TestReportRelayRTTNotMeasured: a connected relay that has not answered a
// ping yet says so, rather than leaving a reader to wonder whether the line
// was dropped. This is the in-process caller's zero: the relay really has not
// been measured here.
func TestReportRelayRTTNotMeasured(t *testing.T) {
	report := Report(p2p.Status{RelayConnected: true}, Options{InProcess: true, RelayURL: "wss://relay.example/derp"})
	for _, want := range []string{"relay rtt:", "not measured"} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q\n---\n%s", want, report)
		}
	}
}

// TestReportRelayRTTNotReportedByControlPlane: a wire-sourced caller (the p2p
// doctor CLI, whose proto is frozen) structurally reads zero in every field the
// proto does not carry — so a host that has answered pings for days would be
// described as "not measured yet", byte-identical to the genuine first-30s
// case. Over the wire the report must name the field as unreported, the idiom
// the relay state line above it already uses.
func TestReportRelayRTTNotReportedByControlPlane(t *testing.T) {
	report := Report(p2p.Status{RelayConnected: true}, Options{RelayURL: "wss://relay.example/derp"})
	for _, want := range []string{"relay rtt:", "not reported by the control plane"} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q\n---\n%s", want, report)
		}
	}
	if strings.Contains(report, "not measured yet") {
		t.Errorf("wire-sourced report claims the relay never measured an RTT:\n%s", report)
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

// TestReportStatesThePeerDownPairingRule pins the reading rule in the place an
// operator reaches for when a peer misbehaves. It is prose, not state: the
// rebuild line is log-only (Status carries no down/up fields), so without this
// the rule lives nowhere a reader will look — and "a rebuild with no kill" reads
// like a bug to whoever meets it first.
func TestReportStatesThePeerDownPairingRule(t *testing.T) {
	out := Report(p2p.Status{}, Options{})
	for _, want := range []string{
		"one outage = one \"relay session rebuilt\"",
		"empty relayReason",
		"a rebuild without a kill is normal",
		"a kill without a rebuild",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing the pairing rule %q\n---\n%s", want, out)
		}
	}
}

// TestReportMentionsRelaySilentStrikes pins the two-strike reading rule where
// an operator looks when a peer flaps: strike 1 kills only the mux (clean,
// keys kept), strike 2 resets the pair. Without it a "relay-silent" kill
// reads as a software kick and a "link-lost" after it reads as a second,
// unrelated outage.
func TestReportMentionsRelaySilentStrikes(t *testing.T) {
	out := Report(p2p.Status{}, Options{})
	for _, want := range []string{
		"relay-silent",
		"strike 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing the two-strike rule %q\n---\n%s", want, out)
		}
	}
}
