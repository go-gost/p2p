package main

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

// targetSpec is one bridge target: a network plus an address. A bare
// "host:port" is tcp; an explicit "udp://host:port" (or "tcp://…") names it.
type targetSpec struct {
	network string
	addr    string
}

// parseTarget parses a target spec, rejecting anything without a host and port
// and any scheme other than tcp/udp.
func parseTarget(v string) (targetSpec, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return targetSpec{}, fmt.Errorf("empty target")
	}
	network := "tcp"
	if i := strings.Index(v, "://"); i >= 0 {
		network, v = v[:i], v[i+len("://"):]
		if network != "tcp" && network != "udp" {
			return targetSpec{}, fmt.Errorf("target: unsupported scheme %q", network)
		}
	}
	if _, _, err := net.SplitHostPort(v); err != nil {
		return targetSpec{}, fmt.Errorf("target %q: %w", v, err)
	}
	return targetSpec{network: network, addr: v}, nil
}

// targetPool holds bridge targets grouped by network and hands them out
// round-robin (k8s-Service style, no health checking). Each network has its
// own cursor so consumers — inbound tcp tunnels, hub udp channels — never
// disturb one another's rotation.
type targetPool struct {
	byNetwork map[string][]string
	rr        map[string]*atomic.Uint64
}

func newTargetPool() *targetPool {
	return &targetPool{
		byNetwork: make(map[string][]string),
		rr:        make(map[string]*atomic.Uint64),
	}
}

// add appends one target to its network's pool.
func (p *targetPool) add(s targetSpec) {
	if p.rr[s.network] == nil {
		p.rr[s.network] = new(atomic.Uint64)
	}
	p.byNetwork[s.network] = append(p.byNetwork[s.network], s.addr)
}

// has reports whether the network has any target.
func (p *targetPool) has(network string) bool {
	return len(p.byNetwork[network]) > 0
}

// pick returns the next target for the network, round-robin, or ok=false when
// the network has none.
func (p *targetPool) pick(network string) (string, bool) {
	addrs := p.byNetwork[network]
	if len(addrs) == 0 {
		return "", false
	}
	i := p.rr[network].Add(1) - 1
	return addrs[i%uint64(len(addrs))], true
}
