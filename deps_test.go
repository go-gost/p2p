package p2p

import (
	"os/exec"
	"strings"
	"testing"
)

// TestRootHasNoExternalDependencies pins the promise this package makes to
// third parties: importing the contracts pulls nothing outside the standard
// library, so a caller that only wants Config, Status and the sentinel errors
// does not inherit an engine, a transport or a parser. Skipped when the go tool
// is not on PATH.
func TestRootHasNoExternalDependencies(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	out, err := exec.Command(goTool, "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for dep := range strings.FieldsSeq(string(out)) {
		if dep == "github.com/go-gost/p2p" {
			continue // this package
		}
		if !strings.Contains(dep, ".") {
			continue // a standard-library path
		}
		t.Errorf("the contract package depends on %s; keep it stdlib-only", dep)
	}
}
