package main

import "testing"

// TestControlPlaneOff pins the rule that decides whether this node listens for a
// GOST client at all: the control plane is opt-in, so an unset (or explicitly
// worded) address means no listener — the point of the flag's empty default.
func TestControlPlaneOff(t *testing.T) {
	for _, tc := range []struct {
		addr string
		off  bool
	}{
		{"", true},
		{"off", true},
		{"OFF", true},
		{" none ", true},
		{"127.0.0.1:8003", false},
		{"0.0.0.0:8003", false},
		{"offsite:8003", false},
	} {
		if got := controlPlaneOff(tc.addr); got != tc.off {
			t.Errorf("controlPlaneOff(%q) = %v, want %v", tc.addr, got, tc.off)
		}
	}
}
