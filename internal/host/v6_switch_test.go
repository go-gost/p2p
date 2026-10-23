package host

// The IPv6 family is opt-in. Before this, any host with a global IPv6 egress
// probed it at startup, collected v6 candidates and advertised the v6
// capability bit without asking; an operator who did not want p2p using v6 had
// no way to say so. Config.IPv6 (off by default) is that switch, and it gates
// every place v6 becomes visible: the egress probe, the candidate collection
// and the capability bit.

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-gost/p2p"
)

// TestIPv6OffAdvertisesNothing: with the switch off, even an explicitly
// supplied v6 egress must stay invisible — no capability bit, and the v4 path
// must keep working.
func TestIPv6OffAdvertisesNothing(t *testing.T) {
	e := newTestEngine(t)
	e.stunAddr = "127.0.0.1:1"
	e.v6Addr = &net.UDPAddr{IP: net.IPv6loopback}
	if got := e.caps(); got&capsIPv6 != 0 {
		t.Fatalf("caps = %#x, want no v6 bit with the switch off", got)
	}
	if !e.directEnabled() {
		t.Fatal("a v4-only host must still punch")
	}
}

// TestIPv6OnProbesEveryRound: the switch is a standing permission, not a
// startup snapshot. An egress that appears later (DAD finishing, DHCPv6
// arriving, a laptop moving onto a v6 network) must be picked up by the next
// round without a restart, and one that disappears must be dropped.
func TestIPv6OnProbesEveryRound(t *testing.T) {
	e := newTestEngine(t)
	e.v6Enabled = true
	var calls atomic.Int32
	e.v6Probe = func() *net.UDPAddr {
		if calls.Add(1) == 1 {
			return nil
		}
		return &net.UDPAddr{IP: net.IPv6loopback}
	}
	if got := e.resolveV6(); got != nil {
		t.Fatalf("first round resolved %v, want no egress", got)
	}
	if e.v6Available {
		t.Fatal("v6Available = true after a round that found no egress")
	}
	if got := e.caps(); got&capsIPv6 != 0 {
		t.Fatalf("caps = %#x, want no v6 bit while no egress is usable", got)
	}
	if got := e.resolveV6(); got == nil || !got.IP.Equal(net.IPv6loopback) {
		t.Fatalf("second round resolved %v, want the egress that appeared", got)
	}
	if !e.v6Available {
		t.Fatal("v6Available = false after a round that found an egress")
	}
	if got := e.caps(); got&capsIPv6 == 0 {
		t.Fatalf("caps = %#x, want the v6 bit once the egress is usable", got)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("probe calls = %d, want one per round (2)", n)
	}
}

// TestIPv6OffDoesNotProbe: with the switch off the probe is never called — a
// host that opted out must not even look.
func TestIPv6OffDoesNotProbe(t *testing.T) {
	e := newTestEngine(t)
	var calls atomic.Int32
	e.v6Probe = func() *net.UDPAddr {
		calls.Add(1)
		return &net.UDPAddr{IP: net.IPv6loopback}
	}
	if got := e.resolveV6(); got != nil {
		t.Fatalf("resolveV6 = %v with the switch off, want nil", got)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("probe calls = %d, want 0 with the switch off", n)
	}
}

// TestDirectConfigIPv6States: the status tells "off" apart from "on but no
// egress", so a user is not left guessing which one they are running.
func TestDirectConfigIPv6States(t *testing.T) {
	cases := []struct {
		name            string
		enabled         bool
		v6Addr          *net.UDPAddr
		wantIPv6        bool
		wantIPv6Enabled bool
	}{
		{name: "off", enabled: false, v6Addr: nil, wantIPv6: false, wantIPv6Enabled: false},
		{name: "on without egress", enabled: true, v6Addr: nil, wantIPv6: false, wantIPv6Enabled: true},
		{name: "on with egress", enabled: true, v6Addr: &net.UDPAddr{IP: net.IPv6loopback}, wantIPv6: true, wantIPv6Enabled: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t)
			e.direct = true
			e.v6Enabled = tc.enabled
			e.v6Addr = tc.v6Addr
			c := e.directConfig()
			if c.IPv6 != tc.wantIPv6 {
				t.Fatalf("IPv6 = %v, want %v", c.IPv6, tc.wantIPv6)
			}
			if c.IPv6Enabled != tc.wantIPv6Enabled {
				t.Fatalf("IPv6Enabled = %v, want %v", c.IPv6Enabled, tc.wantIPv6Enabled)
			}
		})
	}
}

// TestIPv6ConfigDefaultsOff: a config that says nothing about IPv6 gets the
// off behaviour, and an explicit true reaches the engine.
func TestIPv6ConfigDefaultsOff(t *testing.T) {
	base := p2p.Config{Derp: "wss://127.0.0.1:1/derp", Key: strings.Repeat("cc", 32)}
	h, err := New(&base)
	if err != nil {
		t.Fatal(err)
	}
	if h.engine.v6Enabled {
		t.Fatal("ipv6 must default off")
	}
	on := base
	on.IPv6 = true
	h, err = New(&on)
	if err != nil {
		t.Fatal(err)
	}
	if !h.engine.v6Enabled {
		t.Fatal("ipv6: true did not reach the engine")
	}
}
