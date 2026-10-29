package host

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

// pipeAddr is the fixed address a pipePacketConn reports. The multi-path conn
// never uses a read result's own address: the underlay address is the QUIC
// path identity.
type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

// pipePacketConn is a net.PacketConn backed by two channels. send delivers a
// packet to ReadFrom; writes are collected on out. Close unblocks ReadFrom.
type pipePacketConn struct {
	in     chan []byte
	out    chan []byte
	local  net.Addr
	closed chan struct{}
	once   sync.Once
}

func newPipePacketConn(local net.Addr) *pipePacketConn {
	return &pipePacketConn{
		in:     make(chan []byte, 8192),
		out:    make(chan []byte, 64),
		local:  local,
		closed: make(chan struct{}),
	}
}

func (c *pipePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.in:
		return copy(p, pkt), c.local, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *pipePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	pkt := append([]byte(nil), p...)
	select {
	case c.out <- pkt:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *pipePacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *pipePacketConn) LocalAddr() net.Addr              { return c.local }
func (c *pipePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *pipePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipePacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *pipePacketConn) send(t *testing.T, pkt string) {
	t.Helper()
	select {
	case c.in <- []byte(pkt):
	case <-time.After(time.Second):
		t.Fatalf("pipe %s: send timeout", c.local)
	}
}

func (c *pipePacketConn) recv(t *testing.T) string {
	t.Helper()
	select {
	case pkt := <-c.out:
		return string(pkt)
	case <-time.After(time.Second):
		t.Fatalf("pipe %s: no write", c.local)
		return ""
	}
}

func (c *pipePacketConn) noWrite(t *testing.T) {
	t.Helper()
	select {
	case pkt := <-c.out:
		t.Fatalf("pipe %s: unexpected write %q", c.local, pkt)
	case <-time.After(20 * time.Millisecond):
	}
}

func testRelayAddr() quicPathAddr {
	return quicPathAddr{name: quicPathRelay}
}

func testDirectAddr() quicPathAddr {
	return quicPathAddr{name: quicPathDirect, addr: netip.MustParseAddrPort("198.51.100.7:4040")}
}

func addTestUnderlay(t *testing.T, c *multiPathConn, name string, addr net.Addr) *pipePacketConn {
	t.Helper()
	pc := newPipePacketConn(pipeAddr(name + "-local"))
	t.Cleanup(func() { _ = pc.Close() })
	c.addUnderlay(quicUnderlay{name: name, addr: addr, pc: pc})
	return pc
}

func TestMultiPathClientPreference(t *testing.T) {
	c := newMultiPathConn(quicRoleClient)
	t.Cleanup(func() { _ = c.Close() })

	relayPC := addTestUnderlay(t, c, quicPathRelay, testRelayAddr())
	directPC := addTestUnderlay(t, c, quicPathDirect, testDirectAddr())

	c.setPreferred(quicPathDirect)
	if got := c.preferredPath(); got != quicPathDirect {
		t.Fatalf("preferred = %q, want %q", got, quicPathDirect)
	}
	if n, err := c.WriteTo([]byte("via-direct"), testRelayAddr()); err != nil || n != len("via-direct") {
		t.Fatalf("WriteTo(direct) = %d, %v", n, err)
	}
	if got := directPC.recv(t); got != "via-direct" {
		t.Fatalf("direct got %q", got)
	}
	relayPC.noWrite(t)

	c.setPreferred(quicPathRelay)
	if got := c.preferredPath(); got != quicPathRelay {
		t.Fatalf("preferred = %q, want %q", got, quicPathRelay)
	}
	if _, err := c.WriteTo([]byte("via-relay"), testDirectAddr()); err != nil {
		t.Fatalf("WriteTo(relay): %v", err)
	}
	if got := relayPC.recv(t); got != "via-relay" {
		t.Fatalf("relay got %q", got)
	}
	directPC.noWrite(t)
}

func TestMultiPathClientFallsBackToRelay(t *testing.T) {
	c := newMultiPathConn(quicRoleClient)
	t.Cleanup(func() { _ = c.Close() })

	relayPC := addTestUnderlay(t, c, quicPathRelay, testRelayAddr())
	directPC := addTestUnderlay(t, c, quicPathDirect, testDirectAddr())

	// No preferred path yet.
	if _, err := c.WriteTo([]byte("unset"), nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if got := relayPC.recv(t); got != "unset" {
		t.Fatalf("relay got %q", got)
	}

	// A preferred path that no longer exists must fall back to relay too.
	c.setPreferred("gone")
	if _, err := c.WriteTo([]byte("missing"), nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if got := relayPC.recv(t); got != "missing" {
		t.Fatalf("relay got %q", got)
	}
	directPC.noWrite(t)
}

func TestMultiPathServerRoutesByAddr(t *testing.T) {
	c := newMultiPathConn(quicRoleServer)
	t.Cleanup(func() { _ = c.Close() })

	relayPC := addTestUnderlay(t, c, quicPathRelay, testRelayAddr())
	directPC := addTestUnderlay(t, c, quicPathDirect, testDirectAddr())

	if _, err := c.WriteTo([]byte("to-direct"), testDirectAddr()); err != nil {
		t.Fatalf("WriteTo(direct): %v", err)
	}
	if got := directPC.recv(t); got != "to-direct" {
		t.Fatalf("direct got %q", got)
	}
	relayPC.noWrite(t)

	if _, err := c.WriteTo([]byte("to-relay"), testRelayAddr()); err != nil {
		t.Fatalf("WriteTo(relay): %v", err)
	}
	if got := relayPC.recv(t); got != "to-relay" {
		t.Fatalf("relay got %q", got)
	}
	directPC.noWrite(t)
}

func TestMultiPathServerUnknownAddrFallsBackToRelay(t *testing.T) {
	c := newMultiPathConn(quicRoleServer)
	t.Cleanup(func() { _ = c.Close() })

	relayPC := addTestUnderlay(t, c, quicPathRelay, testRelayAddr())
	if _, err := c.WriteTo([]byte("unknown"), pipeAddr("nowhere")); err != nil {
		t.Fatalf("WriteTo(unknown): %v", err)
	}
	if got := relayPC.recv(t); got != "unknown" {
		t.Fatalf("relay got %q", got)
	}
}

func TestMultiPathDeadlineWake(t *testing.T) {
	c := newMultiPathConn(quicRoleClient)
	t.Cleanup(func() { _ = c.Close() })

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		_, _, err := c.ReadFrom(buf)
		errCh <- err
	}()

	// Give the reader a chance to block; if it has not started yet, the expired
	// deadline is still observed on entry.
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	if err := c.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("ReadFrom err = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetReadDeadline did not wake ReadFrom")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("deadline wake took %v", d)
	}

	// Clearing the deadline makes the conn readable again.
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	pc := addTestUnderlay(t, c, quicPathRelay, testRelayAddr())
	pc.send(t, "after-deadline")
	buf := make([]byte, 128)
	n, addr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom after deadline: %v", err)
	}
	if got := string(buf[:n]); got != "after-deadline" {
		t.Fatalf("got %q", got)
	}
	if addr.String() != quicPathRelay {
		t.Fatalf("addr = %q, want relay", addr)
	}
}

func TestMultiPathReplaceUnderlayIgnoresOldError(t *testing.T) {
	c := newMultiPathConn(quicRoleClient)
	t.Cleanup(func() { _ = c.Close() })

	relayPC := addTestUnderlay(t, c, quicPathRelay, testRelayAddr())
	oldDirect := addTestUnderlay(t, c, quicPathDirect, testDirectAddr())
	c.setPreferred(quicPathDirect)

	newDirect := addTestUnderlay(t, c, quicPathDirect, testDirectAddr())

	// addUnderlay closed the old pipe, so its reader must have exited without
	// publishing net.ErrClosed into the fan-in queue.
	_ = oldDirect.Close()

	// A short deadline proves the queue has no stale error: a leaked close error
	// would be returned instead.
	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 128)
	if _, _, err := c.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom after replace = %v, want deadline exceeded", err)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}

	// The relay reader still serves the replacement conn.
	relayPC.send(t, "relay-still-works")
	n, addr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom relay: %v", err)
	}
	if got := string(buf[:n]); got != "relay-still-works" {
		t.Fatalf("got %q", got)
	}
	if addr.String() != quicPathRelay {
		t.Fatalf("addr = %q, want relay", addr)
	}

	// The replacement direct underlay is used for both directions.
	if c.preferredPath() != quicPathDirect {
		t.Fatalf("preferred = %q after replace", c.preferredPath())
	}
	if _, err := c.WriteTo([]byte("new-direct"), nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if got := newDirect.recv(t); got != "new-direct" {
		t.Fatalf("new direct got %q", got)
	}
	newDirect.send(t, "new-direct-in")
	n, addr, err = c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom new direct: %v", err)
	}
	if got := string(buf[:n]); got != "new-direct-in" {
		t.Fatalf("got %q", got)
	}
	if addr.String() != testDirectAddr().String() {
		t.Fatalf("addr = %q, want %q", addr, testDirectAddr())
	}
}

func TestMultiPathRemoveUnderlay(t *testing.T) {
	c := newMultiPathConn(quicRoleClient)
	t.Cleanup(func() { _ = c.Close() })

	relayPC := addTestUnderlay(t, c, quicPathRelay, testRelayAddr())
	directPC := addTestUnderlay(t, c, quicPathDirect, testDirectAddr())
	c.setPreferred(quicPathDirect)

	c.removeUnderlay(quicPathDirect)
	if got := c.preferredPath(); got != "" {
		t.Fatalf("preferred = %q after removal, want empty", got)
	}
	if _, err := c.WriteTo([]byte("after-remove"), nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if got := relayPC.recv(t); got != "after-remove" {
		t.Fatalf("relay got %q", got)
	}

	// Removing a name that is not present is a no-op.
	c.removeUnderlay("absent")
	// The removed underlay was closed by removeUnderlay.
	if _, err := directPC.WriteTo([]byte("x"), testDirectAddr()); err == nil {
		t.Fatal("removed underlay is still open")
	}
}

func TestMultiPathQueueDropsWhenFull(t *testing.T) {
	c := newMultiPathConn(quicRoleClient)
	t.Cleanup(func() { _ = c.Close() })

	pc := addTestUnderlay(t, c, quicPathRelay, testRelayAddr())
	for i := 0; i < quicMultiPathReadQueue+512; i++ {
		pc.in <- []byte("packet")
	}

	deadline := time.Now().Add(5 * time.Second)
	for c.drops.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := c.drops.Load(); got == 0 {
		t.Fatal("full fan-in queue did not drop packets")
	}
}

func TestMultiPathCloseWakesRead(t *testing.T) {
	c := newMultiPathConn(quicRoleClient)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		_, _, err := c.ReadFrom(buf)
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReadFrom returned nil error after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake ReadFrom")
	}
}

func TestMultiPathAddrsAreDistinct(t *testing.T) {
	relay := testRelayAddr()
	direct := testDirectAddr()
	if relay.String() != "relay" {
		t.Fatalf("relay addr = %q", relay)
	}
	if direct.String() != "direct:198.51.100.7:4040" {
		t.Fatalf("direct addr = %q", direct)
	}
	if relay.String() == direct.String() {
		t.Fatal("relay and direct path addresses must differ")
	}
}

func TestZeroCIDGenerator(t *testing.T) {
	if (zeroCIDGenerator{}).ConnectionIDLen() != 0 {
		t.Fatal("want zero length")
	}
	id, err := zeroCIDGenerator{}.GenerateConnectionID()
	if err != nil || id.Len() != 0 {
		t.Fatalf("id=%v err=%v", id, err)
	}
}
