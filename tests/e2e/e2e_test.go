// Package e2e wraps the shell-driven p2p end-to-end suite so it can also be
// run from `go test`. It is skipped by default: the suite builds real
// binaries, starts a real DERP server, and manipulates network namespaces, so
// it needs root (or a user namespace) plus Docker and is not a CI gate.
//
//	P2P_E2E=1 go test ./tests/e2e -v
//	P2P_E2E=1 P2P_E2E_ARGS="--scenario udp-tun --keep" go test ./tests/e2e -v
package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestSuite runs run.sh and fails if any scenario assertion fails. Configure
// extra run.sh flags with P2P_E2E_ARGS (whitespace separated).
func TestSuite(t *testing.T) {
	if os.Getenv("P2P_E2E") == "" {
		t.Skip("set P2P_E2E=1 to run the p2p e2e suite (needs root, Docker, openssl)")
	}
	args := strings.Fields(os.Getenv("P2P_E2E_ARGS"))
	cmd := exec.Command("./run.sh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		t.Fatalf("p2p e2e suite failed: %v", err)
	}
}
