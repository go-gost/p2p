package doctor

// The report's one-word summary — "path: direct, state: up" — used to be the
// whole picture, and it was the reason a 45-minute blackhole went unnoticed in
// the field. The measured shape was `path: direct`, `state: up`,
// `last traffic: 4m47s` on a host whose data plane was one-way dead: the peer
// listened, the pings were answered, and nothing came back.
//
// Those three fields are set by three different layers, and only one of them was
// ever printed as its own line. "state" is the punch state machine. "path" is
// underlay recency — which the bare-UDP heartbeat refreshes without any KCP
// traffic, by construction. "last traffic" is the data plane, and it came with a
// parenthetical ("a connected idle peer ages here") that told the reader to
// discount it. So a dead data plane under a heartbeat-alive underlay printed as
// healthy, and the one field that would have contradicted it was the one the
// report told you to ignore.
//
// These tests pin the three layers as three separately-attributed lines, so none
// of them can be read as a summary of the others.

import (
	"strings"
	"testing"
	"time"

	p2p "github.com/go-gost/p2p"
)

// deadDataPlanePeer is the field shape: an underlay the heartbeat still answers,
// a session that is gone, and a data plane that has been silent for minutes.
func deadDataPlanePeer() p2p.PeerDiagnostic {
	return p2p.PeerDiagnostic{
		Path:        "direct",
		State:       "up",
		PeerAddr:    "203.0.113.5:5678",
		Candidates:  1,
		SessionAge:  4*time.Minute + 47*time.Second,
		LastRecvAge: 5 * time.Second,
		Attempts:    1,
		Ups:         1,
		RelayKCP: p2p.RelayKCPStats{
			Path:              "direct",
			DirectAlive:       true,
			DirectLastRecvAge: 4*time.Minute + 47*time.Second,
			RelayLastRecvAge:  -1,
			RelayBytesSent:    1 << 20,
			RelayBytesRcvd:    1 << 20,
			DirectBytesSent:   0,
			DirectBytesRcvd:   0,
		},
		// The layer with no field at all today: the smux session's own liveness.
		SessionState: "down",
	}
}

func optsForReport() Options {
	yes := true
	return Options{
		Version:  "test-ver",
		Host:     "127.0.0.1:9000",
		Identity: "LOCALKEY",
		RelayURL: "wss://relay.example/derp",
		Direct:   &yes,
	}
}

// TestReportSeparatesUnderlaySessionAndDataPlane: the per-underlay ages and the
// heartbeat aliveness must appear as their own attributed lines. They already
// existed on the struct; the report dropped them, so a reader could not tell an
// underlay carrying traffic from one carrying only a heartbeat echo.
func TestReportSeparatesUnderlaySessionAndDataPlane(t *testing.T) {
	st := p2p.Status{
		DirectPeers: 1,
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{
			"directPEERkey": deadDataPlanePeer(),
		},
	}
	out := Report(st, optsForReport())

	for _, want := range []string{
		"underlay:",
		"direct last recv 4m47s",
		"direct hb alive",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not attribute the underlay layer: missing %q\n%s", want, out)
		}
	}
}

// TestReportNamesADeadSessionUnderALiveUnderlay: a peer whose session is gone
// must not read "up". The verdict line always said "direct path up" whenever the
// punch was up and the underlay was fresh, which is exactly the case where the
// data plane is one-way dead and nobody watching the report would know.
func TestReportNamesADeadSessionUnderALiveUnderlay(t *testing.T) {
	st := p2p.Status{
		DirectPeers: 1,
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{
			"directPEERkey": deadDataPlanePeer(),
		},
	}
	out := Report(st, optsForReport())

	if !strings.Contains(out, "session:") {
		t.Fatalf("report has no session line at all\n%s", out)
	}
	if strings.Contains(out, "session: up") && !strings.Contains(out, "session: down") {
		t.Errorf("report reports the session as up while it is dead\n%s", out)
	}
	if strings.Contains(out, "peer directPEERkey: direct path up") {
		t.Errorf("verdict claims the path is up while the session is dead\n%s", out)
	}
}

// TestReportKeepsAGenuinelyHealthyPeerWhole: the whole point of splitting the
// layers is that a live-on-all-three peer still reads as healthy, so the report
// does not cry wolf and get muted. session, underlay and data plane all agree.
func TestReportKeepsAGenuinelyHealthyPeerWhole(t *testing.T) {
	d := deadDataPlanePeer()
	d.SessionState = "up"
	d.LastRecvAge = 40 * time.Millisecond
	d.RelayKCP.DirectLastRecvAge = 40 * time.Millisecond
	st := p2p.Status{
		DirectPeers: 1,
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{
			"directPEERkey": d,
		},
	}
	out := Report(st, optsForReport())

	// The label is padded to a fixed column, so assert on the label and then on
	// the line it introduces rather than on one literal string.
	if !strings.Contains(out, "session:") {
		t.Fatalf("report has no session line at all\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "session:") {
			continue
		}
		if strings.Contains(line, "down") {
			t.Errorf("a live session is reported as down: %q", strings.TrimSpace(line))
		}
		if !strings.Contains(line, "up") {
			t.Errorf("a live session is not reported as up: %q", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(out, "peer directPEERkey: direct path up") {
		t.Errorf("a healthy peer's verdict lost its up\n%s", out)
	}
}

// TestReportDoesNotClaimUnmeasuredSessionOverWire: the gRPC proto is frozen and
// does not carry SessionState, and a diagnostic that never reported it says
// nothing either way. The zero of a string field is "(none)" here, which is why
// the field is a string: a bool would have read as "down" for every peer on the
// wire and made the report cry wolf the moment anyone used `p2p doctor` against
// a remote host.
//
// This is the same rule TestDoctorReportOverWireDoesNotClaimUnmeasured already
// pins for the relay fields, extended to the layer this change added.
func TestReportDoesNotClaimUnmeasuredSessionOverWire(t *testing.T) {
	// Exactly what statusFromReply builds from a reply: SessionState unset, and
	// the whole RelayKCP block absent because the proto does not carry it.
	var d p2p.PeerDiagnostic
	d = deadDataPlanePeer()
	d.SessionState = ""
	d.RelayKCP = p2p.RelayKCPStats{}
	st := p2p.Status{
		DirectPeers: 1,
		PeerDiagnostics: map[string]p2p.PeerDiagnostic{
			"directPEERkey": d,
		},
	}
	out := Report(st, optsForReport())

	if !strings.Contains(out, "session:") {
		t.Fatalf("report has no session line at all\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "session:") {
			continue
		}
		if !strings.Contains(line, "(none)") {
			t.Errorf("an unmeasured session is asserted: %q", strings.TrimSpace(line))
		}
	}
	if strings.Contains(out, "session is DOWN") {
		t.Errorf("the verdict claims a dead session the host never measured\n%s", out)
	}
	// The underlay line must read as unmeasured, not as silence: a wire report
	// carries no KCP stats, so "never" would be a lie about a live path.
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "underlay:") {
			continue
		}
		if !strings.Contains(line, "unknown") {
			t.Errorf("an unmeasured underlay is asserted: %q", strings.TrimSpace(line))
		}
	}
}
