package host

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestSeedHandshakeReportsAnswerSource is the regression for the probe-pod
// blackhole (2026-10-14 live experiment): the seed handshake completes through
// a per-destination NAT by learning the peer's real source internally, but the
// learned address is discarded on success — markUp then registers the stale
// dialed candidate as the data underlay's peer, and the steady-state source
// filter (directunderlay.go readFrom) drops every data datagram on both sides.
// Seed ok, 0 bytes delivered, idle-retire every ~6.6s.
//
// We dial the address the peer advertised, but the peer answers from the
// address it is actually reachable at. The handshake must report that real
// source so the data path can follow the path that actually completed.
func TestSeedHandshakeReportsAnswerSource(t *testing.T) {
	a := mustListenUDP(t)
	advertised := mustListenUDP(t) // the address we dial; never answers
	defer a.Close()
	defer advertised.Close()

	// The peer as it is really reachable. It answers from its own socket, so
	// every reply arrives from a different source than the dialed address.
	peer := mustListenUDP(t)
	defer peer.Close()

	type res struct {
		tok  [seedTokenLen]byte
		addr netip.AddrPort
		err  error
	}
	done := make(chan res, 1)
	go func() {
		out, err := seedHandshakeUDPToken(a, udpAddrPort(t, advertised), 2*time.Second)
		done <- res{out.Token, out.Answer, err}
	}()

	// The peer behaves as a real one: it probes us and echoes what it gets.
	go func() {
		buf := make([]byte, 64)
		deadline := time.Now().Add(2500 * time.Millisecond)
		var tok [seedTokenLen]byte
		tok[0] = 0xC3
		probe := append(append([]byte(nil), seedProbeMagic[:]...), tok[:]...)
		for time.Now().Before(deadline) {
			_, _ = peer.WriteToUDP(probe, a.LocalAddr().(*net.UDPAddr))
			peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			for {
				n, src, err := peer.ReadFromUDP(buf)
				if err != nil {
					break
				}
				if bytes.HasPrefix(buf[:n], seedProbeMagic[:]) && n >= len(seedProbeMagic)+seedTokenLen {
					_, _ = peer.WriteToUDP(buf[:n], src)
				}
			}
		}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("seedHandshakeUDPToken = %v, want success", r.err)
		}
		// The data path must follow the path that completed, not the
		// address that was dialed: the peer answered from its own socket.
		if want := udpAddrPort(t, peer); r.addr != want {
			t.Fatalf("seedHandshakeUDPToken source = %v, want the answering source %v", r.addr, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("seedHandshakeUDPToken never completed")
	}
}
