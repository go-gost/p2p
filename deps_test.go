package p2p

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestContractsAreStdlibOnly pins the promise these packages make to third
// parties: importing the contracts pulls nothing outside the standard library,
// so a caller that only wants Config, Status and the sentinel errors does not
// inherit an engine, a transport or a parser — and a caller that only wants the
// doctor's formatter (wisper) inherits the contract package and nothing else.
// Skipped when the go tool is not on PATH.
func TestContractsAreStdlibOnly(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	cases := []struct {
		pkg   string
		allow []string // further in-module packages this one may import
	}{
		{pkg: "."},
		{pkg: "./doctor", allow: []string{"github.com/go-gost/p2p/doctor"}},
	}
	for _, tc := range cases {
		out, err := exec.Command(goTool, "list", "-deps", tc.pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", tc.pkg, err)
		}
		for dep := range strings.FieldsSeq(string(out)) {
			if dep == "github.com/go-gost/p2p" || slices.Contains(tc.allow, dep) {
				continue // this package, or the contract package
			}
			if !strings.Contains(dep, ".") {
				continue // a standard-library path
			}
			t.Errorf("%s depends on %s; keep it stdlib-only", tc.pkg, dep)
		}
	}
}
