package host

import (
	"testing"
	"time"
)

// TestRelayHandshakeBlackhole pins the relay re-registration tripwire's
// policy: a run of failed handshakes earns a fresh registration only while the
// relay connection itself is healthy and no peer is connected. A connected
// peer proves our registration is being routed; a dead relay is the pong
// watchdog's to cure; a short run is not evidence yet; and the shared
// cooldown keeps the two blackhole cures from tearing every session down back
// to back.
func TestRelayHandshakeBlackhole(t *testing.T) {
	cooldown := controlBlackholeCooldown
	cases := []struct {
		name    string
		fails   int
		relayUp bool
		peers   bool
		since   time.Duration
		want    bool
	}{
		{"a relay-connected peer means the registration is routed", 5, true, true, 2 * cooldown, false},
		{"relay down belongs to the pong watchdog", 5, false, false, 2 * cooldown, false},
		{"short run is not evidence", controlBlackholeThreshold - 1, true, false, 2 * cooldown, false},
		{"threshold with no relay peer re-registers", controlBlackholeThreshold, true, false, 2 * cooldown, true},
		{"cooldown holds the next trip", 5, true, false, cooldown / 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relayHandshakeBlackhole(tc.fails, tc.relayUp, tc.peers, tc.since); got != tc.want {
				t.Fatalf("relayHandshakeBlackhole(%d, %v, %v, %v) = %v, want %v",
					tc.fails, tc.relayUp, tc.peers, tc.since, got, tc.want)
			}
		})
	}
}
