package host

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// seedPlan describes one raw-UDP seed handshake. Peer gets this side's token
// every Retransmit; Targets get it as a whole every SprayEvery, with the first
// pass immediately. An empty Targets set or a zero SprayEvery disables spraying.
//
// Grace is the echo window after this side has already seen its own token
// return. A spray can hit a peer whose own retransmit has not fired yet: if the
// first side to succeed left the socket at once, the peer's late probe would be
// consumed as data by the installed underlay instead of echoed. Keeping the
// socket here for Grace lets that peer finish its own round trip.
type seedPlan struct {
	Peer       netip.AddrPort
	Targets    []netip.AddrPort
	Retransmit time.Duration
	SprayEvery time.Duration
	Grace      time.Duration
}

// seedHandshakePlan runs the symmetric token echo from one UDP socket toward a
// primary Peer and, optionally, a whole set of Targets. It returns the token
// this side sent, the source the peer's echo came from (the path the data
// underlay must follow), and the source of the last peer probe that arrived.
//
// Every outbound datagram carries seedProbeMagic and our 8-byte token. Only
// datagrams with the magic and a full token are considered, from any source:
// the token authenticates the peer and the source address cannot. A peer behind
// a per-destination NAT answers from an endpoint it never advertised, so a
// source filter would make that path untraversable; a probe from an unexpected
// source is echoed to that source and becomes the retransmit destination.
//
// A packet carrying our own token is success — a full own->peer->own round
// trip — and no half-open path can complete it. A peer's token is echoed on
// every probe, without dedupe, so a lost echo is recovered by the peer's next
// retransmit; an echo of our own token is never produced here, so the two sides
// cannot ping-pong. After success the same echoing continues for plan.Grace
// before the socket is handed back.
func seedHandshakePlan(sock *net.UDPConn, plan seedPlan, timeout time.Duration) (seedOutcome, error) {
	var out seedOutcome
	if !plan.Peer.IsValid() {
		return out, fmt.Errorf("seedHandshakePlan: invalid peer address")
	}
	if _, err := rand.Read(out.Token[:]); err != nil {
		return out, err
	}
	probe := make([]byte, 0, len(seedProbeMagic)+seedTokenLen)
	probe = append(probe, seedProbeMagic[:]...)
	probe = append(probe, out.Token[:]...)
	dst := net.UDPAddrFromAddrPort(plan.Peer)
	// The underlay that later owns this socket sets its own read deadline per
	// read, so clear ours on return: no stale short deadline may survive.
	defer sock.SetReadDeadline(time.Time{})

	retransmit := plan.Retransmit
	if retransmit <= 0 {
		retransmit = seedRetransmit
	}
	spraying := plan.SprayEvery > 0 && len(plan.Targets) > 0
	deadline := time.Now().Add(timeout)
	next := time.Now() // send immediately
	nextSpray := next
	buf := make([]byte, 2048)

	// readSeed consumes one datagram and echoes a peer's probe back to its
	// source. In the grace window our own token is a late duplicate echo and
	// must not be re-echoed; before success it completes the round trip.
	readSeed := func(deadline time.Time, grace bool) (bool, error) {
		if err := sock.SetReadDeadline(deadline); err != nil {
			return false, err
		}
		n, src, err := sock.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return false, nil // time to retransmit, spray, or give up
			}
			return false, err
		}
		if n < len(seedProbeMagic)+seedTokenLen ||
			!bytes.Equal(buf[:len(seedProbeMagic)], seedProbeMagic[:]) {
			return false, nil
		}
		var got [seedTokenLen]byte
		copy(got[:], buf[len(seedProbeMagic):len(seedProbeMagic)+seedTokenLen])
		if got == out.Token {
			if grace {
				return false, nil
			}
			out.Answer = src.AddrPort()
			return true, nil
		}
		// Remember where the peer's probe came from: a failed round still has
		// to say whether anything of the peer's reached us. Retargeting lets
		// our token travel to the endpoint that actually answers, so the peer
		// can echo it and complete this side's round trip too.
		out.ProbeFrom = src.AddrPort()
		if !grace && !sameAddrPort(src.AddrPort(), plan.Peer) {
			learned := *src
			dst = &learned
		}
		echo := make([]byte, 0, len(seedProbeMagic)+seedTokenLen)
		echo = append(echo, seedProbeMagic[:]...)
		echo = append(echo, got[:]...)
		// Echo to the probe's source, not the dialed address: that is the
		// path on which the peer is listening.
		_, _ = sock.WriteToUDP(echo, src)
		return false, nil
	}

	for {
		now := time.Now()
		if !now.Before(deadline) {
			return out, errSeedTimeout
		}
		if !now.Before(next) {
			if _, err := sock.WriteToUDP(probe, dst); err != nil {
				return out, err
			}
			next = now.Add(retransmit)
		}
		if spraying && !now.Before(nextSpray) {
			for _, target := range plan.Targets {
				if !target.IsValid() {
					continue
				}
				if _, err := sock.WriteToUDP(probe, net.UDPAddrFromAddrPort(target)); err != nil {
					return out, err
				}
			}
			nextSpray = now.Add(plan.SprayEvery)
		}
		// Wake for the sooner of the two send schedules so a spray can
		// interleave with waiting for replies.
		readBy := next
		if spraying && nextSpray.Before(readBy) {
			readBy = nextSpray
		}
		if readBy.After(deadline) {
			readBy = deadline
		}
		done, err := readSeed(readBy, false)
		if err != nil {
			return out, err
		}
		if !done {
			continue
		}
		if plan.Grace > 0 {
			graceUntil := time.Now().Add(plan.Grace)
			for time.Now().Before(graceUntil) {
				if _, err := readSeed(graceUntil, true); err != nil {
					return out, err
				}
			}
		}
		return out, nil
	}
}
