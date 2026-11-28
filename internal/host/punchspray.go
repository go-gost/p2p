package host

import (
	"math/rand"
	"net"
	"net/netip"
)

// randomPortTargetsFn is the test seam for the port generator. Production uses
// randomPortTargets; tests substitute a controlled target set.
var randomPortTargetsFn = randomPortTargets

const (
	sprayPortMin   = 1024
	sprayPortCount = 65536 - sprayPortMin
)

// randomPortTargets returns n distinct endpoints on ip, with ports drawn from
// the whole unprivileged range. n is capped so one round cannot flood a network
// with an unbounded amount of UDP.
func randomPortTargets(ip netip.Addr, n int) []netip.AddrPort {
	if !ip.Is4() || n <= 0 {
		return nil
	}
	if n > maxPunchSprayPorts {
		n = maxPunchSprayPorts
	}
	if n > sprayPortCount {
		n = sprayPortCount
	}
	targets := make([]netip.AddrPort, 0, n)
	seen := make(map[uint16]struct{}, n)
	for len(targets) < n {
		port := uint16(rand.Intn(sprayPortCount) + sprayPortMin)
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		targets = append(targets, netip.AddrPortFrom(ip, port))
	}
	return targets
}

// punchSpray runs the seed handshake from the same socket that announced this
// side's IPv4 candidate, spraying the peer's public address across random ports.
// Peer stays the announced endpoint: its retransmits and any probe learned from
// an unexpected source still travel on the path the peer actually answers from.
func (dc *directConn) punchSpray(sock *net.UDPConn, peer netip.AddrPort, peerIP netip.Addr) (seedOutcome, error) {
	targets := randomPortTargetsFn(peerIP, dc.e.punch.sprayPorts)
	dc.e.log.Debug("direct punch: spray", "peer", keyName(dc.peer), "targets", len(targets))
	out, err := seedHandshakePlan(sock, seedPlan{
		Peer:       peer,
		Targets:    targets,
		Retransmit: seedRetransmit,
		SprayEvery: dc.e.punch.sprayEvery,
		Grace:      dc.e.punch.seedGrace,
	}, dc.e.punch.socketWindow)
	if err != nil {
		return out, err
	}
	dc.e.log.Debug("direct punch: spray up", "peer", keyName(dc.peer), "answer", out.Answer.String())
	return out, nil
}
