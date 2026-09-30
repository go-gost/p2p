package main

import (
	"testing"
	"time"

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
