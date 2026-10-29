package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestQUICDirect runs the quic-direct scenario on its own. It is the QUIC
// counterpart of the derp-direct row: relay-only first stream, relay->direct
// migration under a live transfer, and a direct->relay fallback when the direct
// UDP path is blackholed. Like TestSuite it is gated because it needs root (or
// a user namespace) and Docker to extract derper.
//
//	P2P_E2E=1 go test ./tests/e2e -run TestQUICDirect -v
//	P2P_E2E=1 P2P_E2E_ARGS="--keep" go test ./tests/e2e -run TestQUICDirect -v
func TestQUICDirect(t *testing.T) {
	if os.Getenv("P2P_E2E") == "" {
		t.Skip("set P2P_E2E=1 to run the p2p e2e suite (needs root, Docker, openssl)")
	}
	args := append([]string{"--scenario", "quic-direct"},
		strings.Fields(os.Getenv("P2P_E2E_ARGS"))...)
	cmd := exec.Command("./run.sh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		t.Fatalf("p2p quic-direct e2e failed: %v", err)
	}
}
