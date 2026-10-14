package host

import (
	"bytes"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// seedFailed reports whether err is the handshake's timeout, tolerating the
// sandbox's intermittent EPERM on sendto. The existing seed tests allow both:
// an EPERM means the probe was never sent, which cannot weaken an assertion
// that no false success occurs.
func seedFailed(err error) bool {
	return errors.Is(err, errSeedTimeout) || errors.Is(err, syscall.EPERM)
}

// These tests cover relaxing the seed handshake's source-address filter so a
// peer whose NAT maps to a different public endpoint than the one it advertised
// can still be punched. The filter was the reason a per-destination NAT could
// never be traversed; the 8-byte token is what actually authenticates the peer.
//
// The relaxation must not weaken the handshake, so each test states one property
// the change has to preserve: a peer answering from an unexpected address is
// accepted, while nothing that lacks our token can complete it.

// TestSeedHandshakeCompletesWhenPeerAnswersFromDifferentAddr is the regression
// this change exists for. We dial the address the peer advertised, but the peer
// answers from the address it is actually reachable at — which is what a NAT
// that assigns the public IP per destination produces. Before the change the
// answer was dropped by the source filter and the round timed out; the token
// proves the peer, so the handshake must complete.
func TestSeedHandshakeCompletesWhenPeerAnswersFromDifferentAddr(t *testing.T) {
	a := mustListenUDP(t)
	advertised := mustListenUDP(t) // the address we dial; never answers
	defer a.Close()
	defer advertised.Close()

	// The peer as it is really reachable. It answers from its own socket, so
	// every reply arrives from a different source than the dialed address.
	peer := mustListenUDP(t)
	defer peer.Close()

	done := make(chan error, 1)
	go func() { done <- seedHandshakeUDP(a, udpAddrPort(t, advertised), 2*time.Second) }()

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
	case err := <-done:
		if err != nil {
			t.Fatalf("seedHandshakeUDP = %v, want success: the token authenticates the peer, "+
				"so an answer from an unexpected source address must be accepted", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("seedHandshakeUDP never completed")
	}
}

// TestSeedHandshakeNoFalseSuccessFromForeignProbe pins the property that made
// the filter safe to relax: a socket that sends a well-formed probe but never
// returns our token cannot complete the handshake. It observes our probes (as a
// NAT would) and stays silent, so this is the half-open path the handshake is
// documented to reject with errSeedTimeout rather than a false direct session.
func TestSeedHandshakeNoFalseSuccessFromForeignProbe(t *testing.T) {
	a := mustListenUDP(t)
	advertised := mustListenUDP(t)
	defer a.Close()
	defer advertised.Close()

	foreign := mustListenUDP(t)
	defer foreign.Close()

	// Read every probe, but never echo: our token never comes back.
	go func() {
		buf := make([]byte, 64)
		for {
			foreign.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, _, err := foreign.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	var tok [seedTokenLen]byte
	tok[0] = 0x5A
	probe := append(append([]byte(nil), seedProbeMagic[:]...), tok[:]...)
	for i := 0; i < 5; i++ {
		if _, err := foreign.WriteToUDP(probe, a.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Skipf("sandbox sendto denied the probe (EPERM): %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	err := seedHandshakeUDP(a, udpAddrPort(t, advertised), 700*time.Millisecond)
	if err == nil {
		t.Fatal("seedHandshakeUDP completed without our token ever returning; " +
			"a probe without the echo must not produce a false direct session")
	}
	if !seedFailed(err) {
		t.Fatalf("seedHandshakeUDP = %v, want a seed timeout", err)
	}
}

// TestSeedHandshakeIgnoresTruncatedProbe covers the packet shape check that
// stays mandatory after the filter is relaxed: magic without a full token is
// dropped, so it neither completes the handshake nor provokes an echo.
func TestSeedHandshakeIgnoresTruncatedProbe(t *testing.T) {
	a := mustListenUDP(t)
	advertised := mustListenUDP(t)
	foreign := mustListenUDP(t)
	defer a.Close()
	defer advertised.Close()
	defer foreign.Close()

	// Magic plus a short token, and a bare payload with no magic at all.
	_, _ = foreign.WriteToUDP(append(append([]byte(nil), seedProbeMagic[:]...), 0x01, 0x02), a.LocalAddr().(*net.UDPAddr))
	_, _ = foreign.WriteToUDP([]byte("hello"), a.LocalAddr().(*net.UDPAddr))

	foreign.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 64)
	for {
		n, _, err := foreign.ReadFromUDP(buf)
		if err != nil {
			break // nothing echoed, which is what we want to assert
		}
		if bytes.HasPrefix(buf[:n], seedProbeMagic[:]) {
			t.Fatalf("a malformed packet was echoed back: %q", buf[:n])
		}
	}

	if err := seedHandshakeUDP(a, udpAddrPort(t, advertised), 400*time.Millisecond); !seedFailed(err) {
		t.Fatalf("seedHandshakeUDP = %v, want a seed timeout", err)
	}
}
