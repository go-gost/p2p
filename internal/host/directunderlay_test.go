package host

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// mustListenUDP opens a loopback IPv4 UDP socket for a direct-underlay test.
func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return c
}

// udpAddrPort returns c's local address as a netip.AddrPort.
func udpAddrPort(t *testing.T, c *net.UDPConn) netip.AddrPort {
	t.Helper()
	a, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("local addr is %T, want *net.UDPAddr", c.LocalAddr())
	}
	return a.AddrPort()
}

// readOne runs one readFrom and delivers the payload (or an error string).
func readOne(u *directUnderlay) <-chan string {
	ch := make(chan string, 1)
	go func() {
		buf := make([]byte, 2048)
		n, err := u.readFrom(buf)
		if err != nil {
			ch <- "ERR:" + err.Error()
			return
		}
		ch <- string(buf[:n])
	}()
	return ch
}

// TestDirectUnderlayFiltersForeignSource: datagrams from a third socket must be
// dropped before they reach KCP; only the punched peer's packets are returned.
func TestDirectUnderlayFiltersForeignSource(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	c := mustListenUDP(t)
	u := newDirectUnderlay(a, udpAddrPort(t, b))
	defer u.close()
	defer b.Close()
	defer c.Close()

	first := readOne(u)
	if _, err := b.WriteToUDP([]byte("fromB"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("b write: %v", err)
	}
	select {
	case got := <-first:
		if got != "fromB" {
			t.Fatalf("first read = %q, want %q", got, "fromB")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the peer's datagram")
	}

	// A foreign datagram must not be returned: a subsequent read has to block
	// past a 200ms window instead of yielding "fromC".
	if _, err := c.WriteToUDP([]byte("fromC"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("c write: %v", err)
	}
	next := readOne(u)
	select {
	case got := <-next:
		t.Fatalf("foreign datagram was returned: %q", got)
	case <-time.After(200 * time.Millisecond):
		// dropped, as required
	}
}

// TestDirectUnderlayEchoesSeedMagic: a peer's seed probe is echoed back to the
// peer (late seed responder) and never handed to KCP, while this side's own
// token coming back is dropped, not echoed again — the H2 loop guard.
func TestDirectUnderlayEchoesSeedMagic(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	var mine [seedTokenLen]byte
	mine[0] = 1
	u := newDirectUnderlayToken(a, udpAddrPort(t, b), mine)
	defer u.close()
	defer b.Close()

	peerProbe := append(append([]byte(nil), seedProbeMagic[:]...), make([]byte, seedTokenLen)...)
	peerProbe[len(seedProbeMagic)] = 2 // a peer token, distinct from ours
	if _, err := b.WriteToUDP(peerProbe, a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("b seed write: %v", err)
	}
	if _, err := b.WriteToUDP([]byte("kcp"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("b kcp write: %v", err)
	}

	first := readOne(u)
	select {
	case got := <-first:
		if got != "kcp" {
			t.Fatalf("first read = %q, want %q (seed must not reach KCP)", got, "kcp")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the KCP datagram")
	}

	b.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, _, err := b.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer did not receive the seed echo: %v", err)
	}
	if !bytes.Equal(buf[:n], peerProbe) {
		t.Fatalf("seed echo = %q, want %q", buf[:n], peerProbe)
	}

	// Our own token coming back is our echo of the peer's probe: it must be
	// dropped, never re-echoed (or two registered underlays ping-pong).
	own := append(append([]byte(nil), seedProbeMagic[:]...), mine[:]...)
	if _, err := b.WriteToUDP(own, a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("b own-token write: %v", err)
	}
	if _, err := b.WriteToUDP([]byte("kcp2"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("b kcp2 write: %v", err)
	}
	second := readOne(u)
	select {
	case got := <-second:
		if got != "kcp2" {
			t.Fatalf("second read = %q, want %q", got, "kcp2")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the second KCP datagram")
	}
	b.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := b.ReadFromUDP(buf); err == nil {
		t.Fatalf("own-token seed packet was echoed back: %q", buf[:n])
	}
}

// TestDirectUnderlayWriteGoesToPeer: writeTo targets the punched peer address.
func TestDirectUnderlayWriteGoesToPeer(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	u := newDirectUnderlay(a, udpAddrPort(t, b))
	defer u.close()
	defer b.Close()

	n, err := u.writeTo([]byte("hello"))
	if err != nil {
		t.Fatalf("writeTo: %v", err)
	}
	if n != len("hello") {
		t.Fatalf("writeTo n = %d, want %d", n, len("hello"))
	}

	b.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	rn, _, err := b.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if string(buf[:rn]) != "hello" {
		t.Fatalf("peer got %q, want %q", buf[:rn], "hello")
	}
}

// TestDirectUnderlayReadEOFAfterClose: close unblocks a pending read with io.EOF.
func TestDirectUnderlayReadEOFAfterClose(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	u := newDirectUnderlay(a, udpAddrPort(t, b))
	defer b.Close()

	u.close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := u.readFrom(buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("readFrom after close = %v, want io.EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("readFrom did not return after close")
	}
}
