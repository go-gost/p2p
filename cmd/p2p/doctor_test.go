package main

import (
	"strings"
	"testing"
	"time"

	"github.com/go-gost/p2p/doctor"
	pb "github.com/go-gost/plugin/p2p/proto"
)

// TestStatusFromReplyRelay pins the wire mapping the CLI doctor added relay
// fields for: the control plane's relay liveness and its last error reach the
// in-process Status the report reads.
func TestStatusFromReplyRelay(t *testing.T) {
	st := statusFromReply(&pb.StatusReply{
		RelayConnected: true,
		Tunnels:        3,
		PeerDiagnostics: []*pb.PeerDiagnostic{{
			Peer:          "k",
			Path:          "failed",
			LastError:     "seed failed",
			Candidates:    2,
			SessionAgeMs:  (12 * time.Second).Milliseconds(),
			LastRecvAgeMs: 300,
		}},
	})

	if !st.RelayConnected || st.RelayError != "" {
		t.Errorf("relay connected = %v, err %q; want connected", st.RelayConnected, st.RelayError)
	}
	if st.Tunnels != 3 {
		t.Errorf("tunnels = %d, want 3", st.Tunnels)
	}
	d, ok := st.PeerDiagnostics["k"]
	if !ok {
		t.Fatalf("peer diagnostics not mapped: %+v", st.PeerDiagnostics)
	}
	if d.Path != "failed" || d.Candidates != 2 || d.SessionAge != 12*time.Second {
		t.Errorf("peer mapping = %+v", d)
	}

	unreachable := statusFromReply(&pb.StatusReply{RelayError: "dial tcp: refused"})
	if unreachable.RelayConnected || unreachable.RelayError != "dial tcp: refused" {
		t.Errorf("relay error = %q; want the dial failure surfaced", unreachable.RelayError)
	}
}

// TestDoctorReportOverWireDoesNotClaimUnmeasured pins the report the CLI
// actually renders: its Status comes from statusFromReply, whose proto carries
// no relay RTT, so a connected relay always reports RelayRTT 0 here — for a
// host that may have answered pings for days. The line must then say the number
// was not reported by the control plane (the idiom the relay state line uses),
// never "not measured yet", which would assert the relay never answered one.
func TestDoctorReportOverWireDoesNotClaimUnmeasured(t *testing.T) {
	st := statusFromReply(&pb.StatusReply{RelayConnected: true, Tunnels: 1})
	out := doctor.Report(st, doctor.Options{
		RelayURL: "wss://relay.example/derp",
	})
	for _, want := range []string{
		"relay rtt:",
		"not reported by the control plane",
		"relay state:",
		"connected",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "not measured yet") {
		t.Errorf("CLI report claims an unmeasured relay over the wire:\n%s", out)
	}
}
