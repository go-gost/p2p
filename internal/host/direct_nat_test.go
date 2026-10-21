package host

// The peer's NAT shape, read off the seed handshake: a peer that answers from
// an endpoint it never announced is telling us its mapping varies by
// destination (a per-destination NAT) or changed since its own STUN probe.
// Both mean the announced candidate is not the endpoint to dial, and both are
// answered the same way — by using the endpoint that actually answered.
//
// The comparison must treat a v4-mapped v6 address as the v4 address it is,
// exactly as the underlay's source filter does (sameAddrPort): a mismatch here
// would report every healthy IPv4 direct path as a per-destination mapping.

import (
	"net/netip"
	"strings"
	"testing"
)

// TestContainsAddr: the membership test the shape verdict rests on.
func TestContainsAddr(t *testing.T) {
	tests := []struct {
		name string
		list []netip.AddrPort
		addr netip.AddrPort
		want bool
	}{
		{
			name: "the endpoint is in the list",
			list: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.4:3478")},
			addr: netip.MustParseAddrPort("203.0.113.4:3478"),
			want: true,
		},
		{
			name: "the endpoint is not in the list",
			list: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.4:3478")},
			addr: netip.MustParseAddrPort("203.0.113.9:51000"),
			want: false,
		},
		{
			name: "a v4-mapped v6 address equals the v4 address",
			list: []netip.AddrPort{netip.MustParseAddrPort("[::ffff:203.0.113.9]:51000")},
			addr: netip.MustParseAddrPort("203.0.113.9:51000"),
			want: true,
		},
		{
			// The hairpin shape: both peers share a NAT, so we dial the peer's
			// local address and it answers from its public one. The public
			// address is in the list it announced, so this is not a shape
			// mismatch — it is the ordinary same-NAT path.
			name: "the hairpin shape: the peer's public endpoint is in the list it announced",
			list: []netip.AddrPort{
				netip.MustParseAddrPort("203.0.113.4:3478"),   // the peer's local address
				netip.MustParseAddrPort("198.51.100.7:62000"), // the peer's public address
			},
			addr: netip.MustParseAddrPort("198.51.100.7:62000"),
			want: true,
		},
		{
			name: "an empty list holds nothing",
			list: nil,
			addr: netip.MustParseAddrPort("203.0.113.9:51000"),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAddr(tt.list, tt.addr); got != tt.want {
				t.Fatalf("containsAddr(%v, %s) = %v, want %v", tt.list, tt.addr, got, tt.want)
			}
		})
	}
}

// TestNotePeerEndpointRecordsMismatch: a peer that answered from an endpoint
// it never announced is recorded as such, together with how long ago that was
// seen. The endpoint it answered from is not kept here — the direct path
// registers it (markUp), and that is the value the report shows.
func TestNotePeerEndpointRecordsMismatch(t *testing.T) {
	dc := &directConn{}
	answered := netip.MustParseAddrPort("203.0.113.9:51000")

	dc.notePeerEndpoint(answered, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.4:3478")})

	differs, age := dc.natEndpoint()
	if !differs {
		t.Fatal("a peer that answered from an endpoint it did not announce read as a match")
	}
	if age <= 0 {
		t.Fatalf("observation age = %s, want a positive age", age)
	}
}

// TestNotePeerEndpointKeepsMatch: a peer that answered from one of the
// endpoints it announced is the ordinary case, and must not be reported as a
// shape mismatch.
func TestNotePeerEndpointKeepsMatch(t *testing.T) {
	dc := &directConn{}
	answered := netip.MustParseAddrPort("203.0.113.4:3478")

	dc.notePeerEndpoint(answered, []netip.AddrPort{answered})

	differs, _ := dc.natEndpoint()
	if differs {
		t.Fatal("a peer that answered from an announced endpoint read as a mismatch")
	}
}

// TestNotePeerEndpointOverwritesPrevious: the observation is the latest
// successful seed, so a later one replaces the earlier verdict entirely — a
// peer whose mapping changed back must not keep reading as a mismatch. A
// failed round produces no observation and leaves the previous one standing.
func TestNotePeerEndpointOverwritesPrevious(t *testing.T) {
	dc := &directConn{}
	announced := netip.MustParseAddrPort("203.0.113.4:3478")

	dc.notePeerEndpoint(netip.MustParseAddrPort("203.0.113.9:51000"), []netip.AddrPort{announced})
	_, first := dc.natEndpoint()
	if first <= 0 {
		t.Fatalf("the first observation carries no age: %s", first)
	}

	dc.notePeerEndpoint(announced, []netip.AddrPort{announced})

	differs, second := dc.natEndpoint()
	if differs {
		t.Fatal("the later observation did not replace the earlier verdict")
	}
	if second > first {
		t.Fatalf("observation age = %s, want no older than the first (%s)", second, first)
	}
}

// TestAnnouncedForKeepsOneFamily: the comparison is made against the
// announced endpoints of the family this round dialled. A regression that
// always compared against the v4 list would report every healthy IPv6 direct
// path as a mapping that differs from what the peer announced.
func TestAnnouncedForKeepsOneFamily(t *testing.T) {
	v4 := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.4:3478")}
	v6 := []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:3478")}

	if got := announcedFor(false, v4, v6); len(got) != 1 || got[0] != v4[0] {
		t.Fatalf("announcedFor(v4) = %v, want %v", got, v4)
	}
	if got := announcedFor(true, v4, v6); len(got) != 1 || got[0] != v6[0] {
		t.Fatalf("announcedFor(v6) = %v, want %v", got, v6)
	}
}

// TestNotePeerEndpointTracesMismatch: the mismatch reaches the punch trace, so
// it shows up on the wire (the trace rides the control plane) and can be
// grepped next to the seed line it explains. A match must not add the line —
// the trace is a ring, and a line on every healthy punch would push the
// history that matters out of it.
func TestNotePeerEndpointTracesMismatch(t *testing.T) {
	dc := &directConn{}

	dc.notePeerEndpoint(netip.MustParseAddrPort("203.0.113.9:51000"),
		[]netip.AddrPort{netip.MustParseAddrPort("203.0.113.4:3478")})

	lines := dc.traceLines()
	want := "peer answered from 203.0.113.9:51000 (not announced)"
	found := false
	for _, line := range lines {
		if line == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("trace = %v, want a line %q", lines, want)
	}

	// A peer that answers from an endpoint it announced leaves no such line.
	match := &directConn{}
	match.notePeerEndpoint(netip.MustParseAddrPort("203.0.113.4:3478"),
		[]netip.AddrPort{netip.MustParseAddrPort("203.0.113.4:3478")})
	for _, line := range match.traceLines() {
		if strings.Contains(line, "not announced") {
			t.Fatalf("trace = %v, want no mismatch line for a peer that answered as announced", match.traceLines())
		}
	}
}

// TestNotePeerEndpointComparesWithinOneFamily: the comparison is made against
// one address family, the one this round dialled. A v4 answer is never in the
// v6 list, so a cross-family comparison would read as a mismatch on every
// punch that dialled a v6 peer.
func TestNotePeerEndpointComparesWithinOneFamily(t *testing.T) {
	dc := &directConn{}

	dc.notePeerEndpoint(netip.MustParseAddrPort("203.0.113.9:51000"),
		[]netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:3478")})

	differs, _ := dc.natEndpoint()
	if !differs {
		t.Fatal("a v4 answer compared against a v6-only list read as a match")
	}
}
