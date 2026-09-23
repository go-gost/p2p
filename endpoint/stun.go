package endpoint

import (
	"context"
	"net"
	"net/netip"

	"github.com/go-gost/p2p/internal/stun"
)

// StunLookup reports the public UDP address a STUN server at addr (host:port)
// sees for this host — the mapping hole punching needs, so an embedder can
// check its STUN setting the way it checks its relay.
//
// The probe dials its own socket, so the port it reports belongs to that
// socket, not to the one a later punch will use (the punch collects its
// candidates from the socket it punches with). It is a reachability and
// address check, not a preview of the punch's endpoint.
func StunLookup(ctx context.Context, addr string) (netip.AddrPort, error) {
	// Bind the family the server resolves to, rather than a dual-stack socket:
	// the client accepts a reply only from the exact address it dialed, and a
	// v4-mapped source reported by a dual-stack socket (which Windows and some
	// stacks do) would not match it.
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	network := "udp6"
	if raddr.IP.To4() != nil {
		network = "udp4"
	}

	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer func() { _ = conn.Close() }()
	return stun.Lookup(ctx, addr, conn)
}
