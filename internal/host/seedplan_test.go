package host

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// planSeedPacket builds the wire format both seed sides use: magic plus an
// 8-byte token. Keeping it in one place makes the tests' fake peers honest.
func planSeedPacket(tok [seedTokenLen]byte) []byte {
	pkt := make([]byte, 0, len(seedProbeMagic)+seedTokenLen)
	pkt = append(pkt, seedProbeMagic[:]...)
	pkt = append(pkt, tok[:]...)
	return pkt
}

// planSeedToken extracts a seed token, rejecting magic-only or malformed
// datagrams the way the handshake does.
func planSeedToken(pkt []byte) ([seedTokenLen]byte, bool) {
	var tok [seedTokenLen]byte
	if len(pkt) < len(seedProbeMagic)+seedTokenLen ||
		!bytes.Equal(pkt[:len(seedProbeMagic)], seedProbeMagic[:]) {
		return tok, false
	}
	copy(tok[:], pkt[len(seedProbeMagic):len(seedProbeMagic)+seedTokenLen])
	return tok, true
}

type planResult struct {
	label string
	out   seedOutcome
	err   error
}

func planSkipEPERM(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("sandbox denied a UDP send: %v", err)
	}
}

// planRecvSeed reads one seed packet from a spray target that must never answer.
func planRecvSeed(c *net.UDPConn, wait time.Duration) ([seedTokenLen]byte, error) {
	var zero [seedTokenLen]byte
	buf := make([]byte, 128)
	if err := c.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return zero, err
	}
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return zero, err
	}
	tok, ok := planSeedToken(buf[:n])
	if !ok {
		return zero, errors.New("spray target received a non-seed datagram")
	}
	return tok, nil
}

// TestSeedPlanSprayTargetsCompletes runs two real seed plans against each
// other. Our plan's Peer is a dead port; the peer's socket is only in the
// Targets set, so completion proves the set was actually sprayed.
func TestSeedPlanSprayTargetsCompletes(t *testing.T) {
	ours := mustListenUDP(t)
	peer := mustListenUDP(t)
	deadA := mustListenUDP(t)
	deadB := mustListenUDP(t)
	defer ours.Close()
	defer peer.Close()
	defer deadA.Close()
	defer deadB.Close()

	ourAddr := udpAddrPort(t, ours)
	peerAddr := udpAddrPort(t, peer)
	deadAAddr := udpAddrPort(t, deadA)
	deadBAddr := udpAddrPort(t, deadB)

	results := make(chan planResult, 2)
	go func() {
		out, err := seedHandshakePlan(ours, seedPlan{
			Peer:       deadAAddr,
			Targets:    []netip.AddrPort{deadBAddr, peerAddr, deadAAddr},
			Retransmit: 50 * time.Millisecond,
			SprayEvery: 25 * time.Millisecond,
			Grace:      300 * time.Millisecond,
		}, 2*time.Second)
		results <- planResult{label: "ours", out: out, err: err}
	}()
	go func() {
		out, err := seedHandshakePlan(peer, seedPlan{
			Peer:       ourAddr,
			Retransmit: 50 * time.Millisecond,
			Grace:      300 * time.Millisecond,
		}, 2*time.Second)
		results <- planResult{label: "peer", out: out, err: err}
	}()

	got := make(map[string]planResult, 2)
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			got[r.label] = r
		case <-time.After(3 * time.Second):
			t.Fatal("seedHandshakePlan did not complete on both sides")
		}
	}
	for _, label := range []string{"ours", "peer"} {
		r, ok := got[label]
		if !ok {
			t.Fatalf("missing %s seed result", label)
		}
		planSkipEPERM(t, r.err)
		if r.err != nil {
			t.Fatalf("%s seedHandshakePlan = %v, want success", label, r.err)
		}
	}
	if want := peerAddr; got["ours"].out.Answer != want {
		t.Fatalf("our Answer = %v, want the spraying peer %v", got["ours"].out.Answer, want)
	}
	if want := ourAddr; got["peer"].out.Answer != want {
		t.Fatalf("peer Answer = %v, want our address %v", got["peer"].out.Answer, want)
	}
	// deadB is reachable only through the Targets set: a packet there proves
	// the whole set was sprayed, not just the Peer retransmit.
	tok, err := planRecvSeed(deadB, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("spray target got no seed probe: %v", err)
	}
	if want := got["ours"].out.Token; tok != want {
		t.Fatalf("sprayed token = %x, want %x", tok, want)
	}
}

// TestSeedPlanResponderGraceEchoesAfterOwnSuccess proves the first side to
// succeed stays on the socket long enough to echo the other side's token.
// The fake peer echoes our token at once, waits 100ms, then probes with its
// own token; a plan that returns immediately on success cannot answer it.
func TestSeedPlanResponderGraceEchoesAfterOwnSuccess(t *testing.T) {
	ours := mustListenUDP(t)
	peer := mustListenUDP(t)
	defer ours.Close()
	defer peer.Close()

	ourAddr := udpAddrPort(t, ours)
	peerAddr := udpAddrPort(t, peer)
	ourUDPAddr := ours.LocalAddr().(*net.UDPAddr)

	type peerResult struct {
		err error
	}
	planDone := make(chan planResult, 1)
	go func() {
		out, err := seedHandshakePlan(ours, seedPlan{
			Peer:       peerAddr,
			Retransmit: 50 * time.Millisecond,
			Grace:      300 * time.Millisecond,
		}, time.Second)
		planDone <- planResult{label: "ours", out: out, err: err}
	}()

	peerDone := make(chan peerResult, 1)
	go func() {
		buf := make([]byte, 128)
		var ourToken [seedTokenLen]byte
		found := false
		readBy := time.Now().Add(600 * time.Millisecond)
		for !found && time.Now().Before(readBy) {
			if err := peer.SetReadDeadline(readBy); err != nil {
				peerDone <- peerResult{err}
				return
			}
			n, src, err := peer.ReadFromUDP(buf)
			if err != nil {
				peerDone <- peerResult{err}
				return
			}
			tok, ok := planSeedToken(buf[:n])
			if !ok {
				continue
			}
			ourToken = tok
			found = true
			if _, err := peer.WriteToUDP(buf[:n], src); err != nil {
				peerDone <- peerResult{err}
				return
			}
		}
		if !found {
			peerDone <- peerResult{errors.New("fake peer never saw our token")}
			return
		}

		var peerToken [seedTokenLen]byte
		peerToken[0] = ourToken[0] ^ 0xFF // distinct from our token
		probe := planSeedPacket(peerToken)
		time.Sleep(100 * time.Millisecond)
		until := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(until) {
			if err := peer.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
				peerDone <- peerResult{err}
				return
			}
			n, src, err := peer.ReadFromUDP(buf)
			if err == nil {
				if tok, ok := planSeedToken(buf[:n]); ok && tok == peerToken &&
					src.AddrPort() == ourAddr {
					peerDone <- peerResult{}
					return
				}
				continue
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if _, err := peer.WriteToUDP(probe, ourUDPAddr); err != nil {
					peerDone <- peerResult{err}
					return
				}
				continue
			}
			peerDone <- peerResult{err}
			return
		}
		peerDone <- peerResult{errors.New("our token was never echoed back during grace")}
	}()

	select {
	case r := <-planDone:
		planSkipEPERM(t, r.err)
		if r.err != nil {
			t.Fatalf("seedHandshakePlan = %v, want success", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("seedHandshakePlan never returned")
	}
	select {
	case r := <-peerDone:
		planSkipEPERM(t, r.err)
		if r.err != nil {
			t.Fatalf("fake peer = %v, want its token echoed during grace", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fake peer never saw its token echoed")
	}
}

// TestSeedPlanLearnsUnexpectedSource pins the learn-the-source behavior: a
// probe from a port we never dialed must become the retransmit destination,
// and its echo must let our own round trip complete on that path.
func TestSeedPlanLearnsUnexpectedSource(t *testing.T) {
	ours := mustListenUDP(t)
	advertised := mustListenUDP(t)
	responder := mustListenUDP(t)
	defer ours.Close()
	defer advertised.Close()
	defer responder.Close()

	advertisedAddr := udpAddrPort(t, advertised)
	responderAddr := udpAddrPort(t, responder)
	ourUDPAddr := ours.LocalAddr().(*net.UDPAddr)

	planDone := make(chan planResult, 1)
	go func() {
		out, err := seedHandshakePlan(ours, seedPlan{
			Peer:       advertisedAddr,
			Retransmit: 40 * time.Millisecond,
			Grace:      200 * time.Millisecond,
		}, time.Second)
		planDone <- planResult{label: "ours", out: out, err: err}
	}()

	type peerResult struct {
		err         error
		sawOurToken bool
		sawOwnEcho  bool
	}
	peerDone := make(chan peerResult, 1)
	go func() {
		var peerToken [seedTokenLen]byte
		peerToken[0] = 0x77
		probe := planSeedPacket(peerToken)
		buf := make([]byte, 128)
		until := time.Now().Add(900 * time.Millisecond)
		var got peerResult
		for time.Now().Before(until) && !(got.sawOurToken && got.sawOwnEcho) {
			if _, err := responder.WriteToUDP(probe, ourUDPAddr); err != nil {
				got.err = err
				break
			}
			if err := responder.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
				got.err = err
				break
			}
			for {
				n, src, err := responder.ReadFromUDP(buf)
				if err != nil {
					break
				}
				tok, ok := planSeedToken(buf[:n])
				if !ok {
					continue
				}
				if tok == peerToken {
					got.sawOwnEcho = true
					continue
				}
				// Our plan's token: echo it back from the socket we learned.
				if _, err := responder.WriteToUDP(buf[:n], src); err != nil {
					got.err = err
					break
				}
				got.sawOurToken = true
			}
		}
		if got.err == nil && !got.sawOurToken {
			got.err = errors.New("our token never reached the unexpected source")
		}
		if got.err == nil && !got.sawOwnEcho {
			got.err = errors.New("our plan never echoed the peer probe to its source")
		}
		peerDone <- got
	}()

	select {
	case r := <-planDone:
		planSkipEPERM(t, r.err)
		if r.err != nil {
			t.Fatalf("seedHandshakePlan = %v, want success", r.err)
		}
		if want := responderAddr; r.out.ProbeFrom != want {
			t.Fatalf("ProbeFrom = %v, want the unexpected source %v", r.out.ProbeFrom, want)
		}
		if want := responderAddr; r.out.Answer != want {
			t.Fatalf("Answer = %v, want the answering unexpected source %v", r.out.Answer, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("seedHandshakePlan never completed on the learned path")
	}
	select {
	case r := <-peerDone:
		planSkipEPERM(t, r.err)
		if r.err != nil {
			t.Fatalf("unexpected-source peer = %v", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unexpected-source peer never finished")
	}
}
