package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/go-gost/p2p/internal/derpclient"
)

// setPairRecency stamps both underlay recencies under p.mu. The relay idle
// watchdog's ticker reads them concurrently, so a bare field assignment
// races under -race even when it never overlapped a read before. Tests
// backdate through here (or the single-side variants below), never by direct
// assignment.
func setPairRecency(pair *relayKCPPair, relay, direct time.Time) {
	pair.mu.Lock()
	pair.lastRelayRecv = relay
	pair.lastDirectRecv = direct
	pair.mu.Unlock()
}

// setPairRelayRecency stamps only the relay recency, under p.mu (see
// setPairRecency).
func setPairRelayRecency(pair *relayKCPPair, at time.Time) {
	pair.mu.Lock()
	pair.lastRelayRecv = at
	pair.mu.Unlock()
}

// setPairDirectRecency stamps only the direct recency, under p.mu (see
// setPairRecency).
func setPairDirectRecency(pair *relayKCPPair, at time.Time) {
	pair.mu.Lock()
	pair.lastDirectRecv = at
	pair.mu.Unlock()
}

// TestRelayConvStableAndDistinct pins the deterministic conversation ID used
// for the relay KCP underlay: it must be symmetric, stable, and deliberately
// different from the direct-plane conv for the same key pair.
func TestRelayConvStableAndDistinct(t *testing.T) {
	_, pubA, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, pubB, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}

	ab := relayConv(pubA, pubB)
	ba := relayConv(pubB, pubA)
	if ab != ba {
		t.Fatalf("relayConv is not symmetric: ab=%d ba=%d", ab, ba)
	}
	if got := relayConv(pubA, pubB); got != ab {
		t.Fatalf("relayConv is not stable: first=%d second=%d", ab, got)
	}

	// The direct-plane conv for the same pair must differ, otherwise the two
	// KCP sessions could collide.
	a, b := pubA, pubB
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	h := sha256.Sum256(append(a[:], b[:]...))
	direct := binary.BigEndian.Uint32(h[:4])
	if ab == direct {
		t.Fatalf("relayConv equals direct conv for the same keys: %d", ab)
	}
}

// TestRelayPacketConnDatagramBoundary proves that the datagram adapter treats
// each queued packet as an independent datagram and that WriteTo maps to a
// single underlying send.
func TestRelayPacketConnDatagramBoundary(t *testing.T) {
	url, sendCount := startCountingDERPServer(t)

	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := derpclient.Dial(context.Background(), url, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	e := &engine{client: c}
	e.faults.Store(&faults{since: time.Now()})

	peer := derpclient.PublicKey{1}
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 2),
		closeCh: make(chan struct{}),
	}
	rpc := newRelayPacketConn(pc)

	packetA := []byte("first datagram")
	packetB := []byte("second datagram")
	pc.inbound <- packetA
	pc.inbound <- packetB

	buf := make([]byte, 256)
	n, addr, err := rpc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first ReadFrom: %v", err)
	}
	if n != len(packetA) {
		t.Fatalf("first ReadFrom n=%d, want %d", n, len(packetA))
	}
	if !bytes.Equal(buf[:n], packetA) {
		t.Fatalf("first ReadFrom returned %q, want %q", buf[:n], packetA)
	}
	if addr == nil {
		t.Fatal("first ReadFrom addr is nil")
	}

	n, addr, err = rpc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second ReadFrom: %v", err)
	}
	if n != len(packetB) {
		t.Fatalf("second ReadFrom n=%d, want %d", n, len(packetB))
	}
	if !bytes.Equal(buf[:n], packetB) {
		t.Fatalf("second ReadFrom returned %q, want %q", buf[:n], packetB)
	}
	if addr == nil {
		t.Fatal("second ReadFrom addr is nil")
	}

	payload := []byte("write once")
	wn, err := rpc.WriteTo(payload, nil)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if wn != len(payload) {
		t.Fatalf("WriteTo n=%d, want %d", wn, len(payload))
	}
	// The send is asynchronous from the server's read loop; give it a moment
	// to be counted.
	var got int64
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		got = sendCount.Load()
		if got == 1 {
			break
		}
	}
	if got != 1 {
		t.Fatalf("SendPacket called %d times, want 1", got)
	}
}

// TestRelayPacketConnReadFromTruncatesToBuffer pins the UDP-style truncation
// contract: a buffer smaller than the datagram receives the prefix and does not
// panic.
func TestRelayPacketConnReadFromTruncatesToBuffer(t *testing.T) {
	pc := &peerConn{
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	rpc := newRelayPacketConn(pc)

	large := make([]byte, 1024)
	for i := range large {
		large[i] = byte(i)
	}
	pc.inbound <- large

	small := make([]byte, 64)
	n, _, err := rpc.ReadFrom(small)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != len(small) {
		t.Fatalf("ReadFrom n=%d, want %d", n, len(small))
	}
	if !bytes.Equal(small, large[:len(small)]) {
		t.Fatal("ReadFrom did not copy the prefix of the oversized datagram")
	}
}

// TestRelayPacketConnDrainsAfterClose pins the closeCh branch of ReadFrom: a
// datagram queued before the close is still delivered, and only once the queue
// is drained does ReadFrom degrade to io.EOF. The pair-level endpoint
// forwarding (relayKCPPair) relies on exactly this contract.
func TestRelayPacketConnDrainsAfterClose(t *testing.T) {
	pc := &peerConn{
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	rpc := newRelayPacketConn(pc)
	pc.inbound <- []byte("queued before close")
	close(pc.closeCh)

	buf := make([]byte, 64)
	n, _, err := rpc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom after close: %v", err)
	}
	if got := string(buf[:n]); got != "queued before close" {
		t.Fatalf("ReadFrom after close = %q, want the queued datagram", got)
	}
	if _, _, err := rpc.ReadFrom(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadFrom on a drained adapter = %v, want io.EOF", err)
	}
}

// TestRelayKCPPairDrainsFinalEndpoint pins the pair-level drain contract: a
// pair shutdown does not cut the final endpoint short — its queued datagrams
// are still served before the proxy degrades to io.EOF, the same
// drain-once-then-EOF contract each endpoint follows. Queued datagrams dropped
// at shutdown are segments the peer will have to retransmit at best, and lost
// protocol state at worst.
func TestRelayKCPPairDrainsFinalEndpoint(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{2}
	pair := e.relayKCPPairFor(peer)
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 2),
		closeCh: make(chan struct{}),
	}
	pair.register(pc)
	pc.inbound <- []byte("first")
	pc.inbound <- []byte("second")

	// The pair ends with datagrams still queued on its endpoint.
	e.dropRelayKCP(peer, nil, errors.New("test: pair teardown"), 0)

	buf := make([]byte, 64)
	for _, want := range []string{"first", "second"} {
		n, _, err := pair.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom during the drain: %v", err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("ReadFrom during the drain = %q, want %q", got, want)
		}
	}
	if _, _, err := pair.ReadFrom(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadFrom after the drain = %v, want io.EOF", err)
	}
}

// TestPairReadFromFanInReturnsDummyAddr pins the fan-in contract Task 3 builds
// on: the pair's ReadFrom is fed by its buffered recv channel, which the relay
// pump fills from the registered endpoint (and, from Task 3, the direct pump
// fills from the punched socket). Every datagram — whether it arrived through
// the relay pump or was placed on the fan-in directly — must be delivered with
// the zero-value dummyAddr{} ("derp") that kcp-go locked its source to at
// NewConn4. Reporting dummyAddr{peer} ("derp:<key>") would make kcp-go's read
// loop silently drop every packet.
func TestPairReadFromFanInReturnsDummyAddr(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{6}
	pair := e.relayKCPPairFor(peer)
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	pair.register(pc)
	pc.inbound <- []byte("via the relay pump")

	buf := make([]byte, 64)
	n, addr, err := pair.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "via the relay pump" {
		t.Fatalf("ReadFrom = %q, want %q", got, "via the relay pump")
	}
	if addr == nil {
		t.Fatal("ReadFrom addr is nil")
	}
	if got := addr.String(); got != "derp" {
		t.Fatalf("ReadFrom addr = %q, want the zero dummyAddr %q", got, "derp")
	}

	// The fan-in channel is what Task 3's direct pump also feeds: a datagram
	// placed there must be delivered with the same zero address.
	pair.recv <- []byte("via the fan-in")
	n, addr, err = pair.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom (fan-in): %v", err)
	}
	if got := string(buf[:n]); got != "via the fan-in" {
		t.Fatalf("ReadFrom (fan-in) = %q, want %q", got, "via the fan-in")
	}
	if addr == nil || addr.String() != "derp" {
		t.Fatalf("ReadFrom (fan-in) addr = %v, want the zero dummyAddr %q", addr, "derp")
	}
}

// TestPairPreferredFollowsInboundRecency pins the preferred-path election: a
// freshly installed direct underlay is preferred immediately (seeded to now), a
// direct that has gone silent past directUnderlayIdle is not, and one inbound
// datagram re-elects it. This is the predicate WriteTo and Task 0's H1 guard
// share.
func TestPairPreferredFollowsInboundRecency(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{7}
	pair := e.relayKCPPairFor(peer)

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer b.Close()
	pair.setDirectUnderlay(newDirectUnderlay(a, udpAddrPort(t, b)))

	if !pair.preferredDirect() {
		t.Fatal("preferredDirect() = false immediately after setDirectUnderlay, want true")
	}
	if got := pair.pathName(); got != "direct" {
		t.Fatalf("pathName() = %q, want direct", got)
	}

	// Force the recency stamp past the idle bound: a direct that has gone silent
	// is no longer preferred.
	setPairDirectRecency(pair, time.Now().Add(-2*directUnderlayIdle))
	if pair.preferredDirect() {
		t.Fatal("preferredDirect() = true for a stale direct underlay, want false")
	}
	if got := pair.pathName(); got != "relay" {
		t.Fatalf("pathName() = %q for a stale direct, want relay", got)
	}

	// One inbound datagram re-seeds the recency and re-elects the direct path.
	if _, err := b.WriteToUDP([]byte("fresh"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	waitFor(t, time.Second, pair.preferredDirect)
}

// TestPairWriteToUsesPreferredPath pins the send-path election: with the direct
// underlay preferred, WriteTo lands on the punched socket (the peer reads it)
// and not on the relay adapter; once the direct goes stale, WriteTo falls back
// to the relay.
func TestPairWriteToUsesPreferredPath(t *testing.T) {
	url, sendCount := startCountingDERPServer(t)

	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := derpclient.Dial(context.Background(), url, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	e := &engine{client: c}
	e.faults.Store(&faults{since: time.Now()})
	peer := derpclient.PublicKey{8}
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	pair.register(pc)

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer b.Close()
	pair.setDirectUnderlay(newDirectUnderlay(a, udpAddrPort(t, b)))

	if _, err := pair.WriteTo([]byte("over direct"), nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, _, err := b.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer did not receive the direct write: %v", err)
	}
	if got := string(buf[:n]); got != "over direct" {
		t.Fatalf("direct peer got %q, want %q", got, "over direct")
	}
	if got := sendCount.Load(); got != 0 {
		t.Fatalf("relay SendPacket called %d times for a direct write, want 0", got)
	}

	// A stale direct falls back to the relay adapter.
	setPairDirectRecency(pair, time.Now().Add(-2*directUnderlayIdle))
	if _, err := pair.WriteTo([]byte("over relay"), nil); err != nil {
		t.Fatalf("WriteTo (relay): %v", err)
	}
	var got int64
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		got = sendCount.Load()
		if got == 1 {
			break
		}
	}
	if got != 1 {
		t.Fatalf("relay SendPacket called %d times after the direct went stale, want 1", got)
	}
}

// TestPairClearDirectUnderlayIdempotent pins clearDirectUnderlay's contract:
// it retires the underlay and closes its socket, a second call is a no-op, and
// the pair reports the relay path afterwards.
func TestPairClearDirectUnderlayIdempotent(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{9}
	pair := e.relayKCPPairFor(peer)

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer b.Close()
	u := newDirectUnderlay(a, udpAddrPort(t, b))
	pair.setDirectUnderlay(u)
	if !pair.preferredDirect() {
		t.Fatal("preferredDirect() = false after install")
	}

	pair.clearDirectUnderlay()
	pair.clearDirectUnderlay() // idempotent: must not panic or double-close

	if !u.closed() {
		t.Fatal("the underlay socket was not closed by clearDirectUnderlay")
	}
	pair.mu.Lock()
	installed := pair.direct
	pair.mu.Unlock()
	if installed != nil {
		t.Fatal("a direct underlay is still installed after clear")
	}
	if pair.preferredDirect() {
		t.Fatal("preferredDirect() = true after clear, want false")
	}
	if got := pair.pathName(); got != "relay" {
		t.Fatalf("pathName() = %q after clear, want relay", got)
	}
}

// appliedNC reads the congestion-control flag the pair last applied to its KCP
// session (the nc argument of SetNoDelay), under the pair's lock. It is the
// deterministic seam Task 14's test asserts on.
func appliedNC(p *relayKCPPair) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.appliedNC
}

// TestPairCongestionFollowsPreferredPath pins Task 14: the pair's KCP session
// switches congestion control with the preferred path — off (nc=1) on the relay,
// where a drop is a bounded-queue overflow rather than a congestion signal, and
// on (nc=0) on the direct path, which rides the public Internet and can
// genuinely congest. The test drives the real transition call sites (session
// creation, underlay install, idle watchdog, a fresh datagram, underlay clear)
// and asserts the nc last applied to the session. It is deterministic: it never
// waits on a real idle clock — the watchdog is invoked directly after forcing
// the recency stamp stale — and never asserts on window growth.
func TestPairCongestionFollowsPreferredPath(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{30}
	pair := e.relayKCPPairFor(peer)
	defer pair.shutdown()

	// A session built with no direct underlay starts on the relay: nc=1.
	if _, err := pair.session(); err != nil {
		t.Fatalf("session: %v", err)
	}
	if got := appliedNC(pair); got != 1 {
		t.Fatalf("initial applied nc = %d, want 1 (relay)", got)
	}

	// Installing a direct underlay flips the session to direct: nc=0.
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer b.Close()
	u := newDirectUnderlay(a, udpAddrPort(t, b))
	pair.setDirectUnderlay(u)
	if got := appliedNC(pair); got != 0 {
		t.Fatalf("applied nc after install = %d, want 0 (direct)", got)
	}

	// The idle watchdog observing the direct go stale flips it back to relay.
	// The watchdog is invoked directly so the assertion does not depend on the
	// 1s read-tick granularity.
	setPairDirectRecency(pair, time.Now().Add(-2*directUnderlayIdle))
	pair.reportDirectIdle(u)
	if got := appliedNC(pair); got != 1 {
		t.Fatalf("applied nc after idle = %d, want 1 (relay)", got)
	}

	// A fresh inbound datagram re-elects direct: nc=0 again.
	if _, err := b.WriteToUDP([]byte("fresh"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	waitFor(t, time.Second, func() bool { return appliedNC(pair) == 0 })

	// Clearing the underlay ends on the relay: nc=1.
	pair.clearDirectUnderlay()
	if got := appliedNC(pair); got != 1 {
		t.Fatalf("applied nc after clear = %d, want 1 (relay)", got)
	}
}

// TestPairDirectPumpStopsOnShutdown pins the symmetric pump-done contract: a
// shutdown stops the direct pump (closing directPumpDone) and a subsequent
// ReadFrom returns io.EOF instead of parking forever waiting on a pump that
// never exits.
func TestPairDirectPumpStopsOnShutdown(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{10}
	pair := e.relayKCPPairFor(peer)

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer b.Close()
	pair.setDirectUnderlay(newDirectUnderlay(a, udpAddrPort(t, b)))

	pair.mu.Lock()
	directDone := pair.directPumpDone
	pair.mu.Unlock()

	pair.shutdown()

	select {
	case <-directDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the direct pump did not exit after shutdown")
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, _, err := pair.ReadFrom(buf)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("ReadFrom after shutdown = %v, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not return io.EOF after shutdown")
	}
}

// TestPairDirectIdleFiresCallbackOnce pins the idle watchdog's callback
// contract: pumpDirect surfaces a silent direct underlay to onDirectIdle exactly
// once per idle episode, and a fresh inbound datagram re-arms it. The callback
// is invoked outside p.mu, so the test's callback may perform the engine's
// retirement (clearDirectUnderlay) synchronously; doing so must not deadlock the
// pump that invoked it (H4). The guard is the callback's second fire clearing
// the underlay: if clear self-joined the invoking pump, the callback would never
// signal and the test would time out.
func TestPairDirectIdleFiresCallbackOnce(t *testing.T) {
	oldIdle := directUnderlayIdle
	directUnderlayIdle = 150 * time.Millisecond
	defer func() { directUnderlayIdle = oldIdle }()

	e := newTestEngine(t)
	before := runtime.NumGoroutine()
	peer := derpclient.PublicKey{11}
	pair := e.relayKCPPairFor(peer)
	defer pair.shutdown()

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer b.Close()
	pair.setDirectUnderlay(newDirectUnderlay(a, udpAddrPort(t, b)))

	var fires atomic.Int64
	fired := make(chan int64, 8)
	pair.mu.Lock()
	pair.onDirectIdle = func(u *directUnderlay) {
		n := fires.Add(1)
		if n == 2 {
			// The engine's response to a dead direct: clear it (signal-only,
			// so this cannot join the pump that invoked us) and re-punch. The
			// callback runs in its own goroutine, so even a joining clear could
			// not deadlock the pump.
			pair.clearDirectUnderlay()
		}
		fired <- n
	}
	pair.mu.Unlock()

	// Deliver one packet, then go silent. Reading it back through the pair
	// proves the pump stamped lastDirectRecv before the idle clock starts.
	if _, err := b.WriteToUDP([]byte("alive"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	buf := make([]byte, 64)
	if n, _, err := pair.ReadFrom(buf); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	} else if got := string(buf[:n]); got != "alive" {
		t.Fatalf("ReadFrom = %q, want %q", got, "alive")
	}

	// First idle episode: the callback fires once.
	select {
	case n := <-fired:
		if n != 1 {
			t.Fatalf("first callback fire = %d, want 1", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onDirectIdle did not fire after the direct went silent")
	}

	// Still silent across another read tick: no second fire for one episode.
	time.Sleep(1500 * time.Millisecond)
	if got := fires.Load(); got != 1 {
		t.Fatalf("onDirectIdle fired %d times in one idle episode, want 1", got)
	}

	// A fresh datagram re-arms the watchdog.
	if _, err := b.WriteToUDP([]byte("again"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	if n, _, err := pair.ReadFrom(buf); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	} else if got := string(buf[:n]); got != "again" {
		t.Fatalf("ReadFrom = %q, want %q", got, "again")
	}
	select {
	case n := <-fired:
		if n != 2 {
			t.Fatalf("second callback fire = %d, want 2", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onDirectIdle did not re-arm after a fresh datagram")
	}

	// H4: the callback cleared the underlay; the pump it ran from must exit.
	pair.mu.Lock()
	directDone := pair.directPumpDone
	pair.mu.Unlock()
	select {
	case <-directDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the direct pump did not exit after its callback cleared the underlay")
	}

	// No goroutine leak: the pair's relay and direct pumps and the callback
	// goroutine are all gone, back to the pre-pair baseline.
	pair.shutdown()
	settleGoroutines(t, before)
}

// TestPairCloseReturnsEOF pins the pair-end contract: with both underlays
// installed, shutdown closes p.done and a blocked ReadFrom returns io.EOF after
// draining, so kcp-go's read loop ends and smux sees the pair end. It also
// guards the leak the watchdog could introduce: the direct pump must exit and
// the goroutine count must settle back.
func TestPairCloseReturnsEOF(t *testing.T) {
	e := newTestEngine(t)
	before := runtime.NumGoroutine()
	peer := derpclient.PublicKey{12}
	pair := e.relayKCPPairFor(peer)

	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	pair.register(pc)

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer b.Close()
	pair.setDirectUnderlay(newDirectUnderlay(a, udpAddrPort(t, b)))

	pair.mu.Lock()
	directDone := pair.directPumpDone
	pair.mu.Unlock()

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, _, err := pair.ReadFrom(buf)
		readErr <- err
	}()

	pair.shutdown()

	select {
	case err := <-readErr:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("ReadFrom after shutdown = %v, want io.EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a blocked ReadFrom did not return io.EOF after shutdown")
	}

	select {
	case <-directDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the direct pump did not exit after shutdown")
	}

	// No goroutine leak: the reader and both pumps have exited.
	settleGoroutines(t, before)
}

// TestPairDirectIdleSlowCallbackDoesNotAccumulate pins the dispatch bound: at
// most one onDirectIdle invocation may be in flight at a time, so a slow or
// blocking engine callback (e.g. a re-punch that stalls) cannot accumulate one
// goroutine per idle episode while traffic keeps re-arming the watchdog. The
// callback is held across three re-armed idle episodes; while it is held,
// exactly one invocation must have run and exactly one must be in flight.
func TestPairDirectIdleSlowCallbackDoesNotAccumulate(t *testing.T) {
	oldIdle := directUnderlayIdle
	directUnderlayIdle = 150 * time.Millisecond
	defer func() { directUnderlayIdle = oldIdle }()

	e := newTestEngine(t)
	before := runtime.NumGoroutine()
	peer := derpclient.PublicKey{13}
	pair := e.relayKCPPairFor(peer)
	defer pair.shutdown()

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	defer b.Close()
	pair.setDirectUnderlay(newDirectUnderlay(a, udpAddrPort(t, b)))

	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var inflight, calls atomic.Int64
	pair.mu.Lock()
	pair.onDirectIdle = func(u *directUnderlay) {
		calls.Add(1)
		inflight.Add(1)
		defer inflight.Add(-1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	pair.mu.Unlock()

	// The first idle episode dispatches a callback that blocks here.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the idle callback never entered")
	}

	// Re-arm the watchdog several times while the callback is held. Each
	// re-arm begins a new idle episode that would dispatch again if dispatch
	// were not bounded.
	buf := make([]byte, 64)
	for i := 0; i < 3; i++ {
		if _, err := b.WriteToUDP([]byte("rearm"), a.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("peer write: %v", err)
		}
		if _, _, err := pair.ReadFrom(buf); err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		time.Sleep(1200 * time.Millisecond) // let at least one idle tick pass
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("slow callback dispatched %d times while one was in flight, want 1", got)
	}
	if got := inflight.Load(); got != 1 {
		t.Fatalf("in-flight callbacks = %d, want exactly 1", got)
	}

	// Releasing the callback frees the dispatch slot.
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for inflight.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := inflight.Load(); got != 0 {
		t.Fatalf("in-flight callbacks = %d after release, want 0", got)
	}

	pair.shutdown()
	settleGoroutines(t, before)
}

// settleGoroutines waits (bounded) for the live goroutine count to fall back to
// the baseline captured before any test-created goroutine started (before the
// pair's pumps and any reader), and fails if it stays above it. Because the pair
// is shut down before the settle, a leaked relay/direct pump or callback
// goroutine keeps the count above the baseline instead of being masked by a
// pump that has already exited. The bound absorbs transient runtime goroutines.
func settleGoroutines(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before {
		t.Fatalf("goroutine leak: %d before, %d after settle", before, got)
	}
}

// TestCloseRelayKCPsKeepsLiveDirectPairs pins the pair-level half of the H1
// guard: when the relay connection goes away, a pair kept alive by a live direct
// path is left running (only its relay half is unregistered), while a pair with
// no direct path is shut down as before.
func TestCloseRelayKCPsKeepsLiveDirectPairs(t *testing.T) {
	e := newTestEngine(t)
	kept := derpclient.PublicKey{21}
	closed := derpclient.PublicKey{22}

	keptPair := e.relayKCPPairFor(kept)
	closedPair := e.relayKCPPairFor(closed)
	liveDirectFor(t, e, kept)

	e.closeRelayKCPs(errors.New("test: relay lost"))

	if got := e.relayKCPPairGet(kept); got != keptPair {
		t.Fatal("a pair with a live direct path was dropped on relay loss")
	}
	keptPair.mu.Lock()
	keptClosed := keptPair.closed
	keptPair.mu.Unlock()
	if keptClosed {
		t.Fatal("a pair with a live direct path was shut down on relay loss")
	}
	if got := e.relayKCPPairGet(closed); got != nil {
		t.Fatal("a pair with no direct path survived relay loss")
	}
	closedPair.mu.Lock()
	closedWasClosed := closedPair.closed
	closedPair.mu.Unlock()
	if !closedWasClosed {
		t.Fatal("a pair with no direct path was not shut down on relay loss")
	}
}

// TestRelayKCPStreamRetiredViewWritesNothing pins the write half of the stream
// handoff: once a view is retired, it writes nothing. A record from a dead mux
// session landing after its successor's would reorder the nonce sequence the
// pair's record stream is built on.
func TestRelayKCPStreamRetiredViewWritesNothing(t *testing.T) {
	e := newTestEngine(t)
	e.faults.Store(&faults{since: time.Now()})
	peer := derpclient.PublicKey{3}
	pair := e.relayKCPPairFor(peer)
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	pair.register(pc)
	if _, err := pair.session(); err != nil {
		t.Fatal(err)
	}
	s1 := pair.newStream()
	s2 := pair.newStream() // retires s1
	if _, err := s1.Write([]byte("from the retired view")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retired view Write = %v, want net.ErrClosed", err)
	}
	if _, err := s2.Write([]byte("from the current view")); err != nil {
		t.Fatalf("current view Write: %v", err)
	}
}

// TestRelayKCPStreamRetirementWaitsForWrites pins that a claim cannot cross an
// in-flight write: retiring a view waits for its outstanding write to land, so
// a retired view's bytes can never reach the pair's stream after its
// successor's. The parked write is real: with nothing ACKing the pair's
// segments, a stream write blocks inside the KCP session once the send window
// is full.
func TestRelayKCPStreamRetirementWaitsForWrites(t *testing.T) {
	e := newTestEngine(t)
	e.faults.Store(&faults{since: time.Now()})
	peer := derpclient.PublicKey{4}
	pair := e.relayKCPPairFor(peer)
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	pair.register(pc)
	if _, err := pair.session(); err != nil {
		t.Fatal(err)
	}
	s1 := pair.newStream()

	// Fill the pair session's send window: nothing ACKs the segments, so a
	// stream write eventually parks inside the KCP session — the in-flight
	// write a retirement must cover. The writer stalls once the window is full.
	buf := make([]byte, 4096)
	var writes atomic.Int64
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			if _, err := s1.Write(buf); err != nil {
				return
			}
			writes.Add(1)
		}
	}()
	last, stalled := writes.Load(), 0
	for stalled < 4 {
		time.Sleep(50 * time.Millisecond)
		if now := writes.Load(); now == last && now > 0 {
			stalled++
		} else {
			last, stalled = writes.Load(), 0
		}
	}

	// With the write in flight, retiring the view must not complete.
	claimed := make(chan struct{})
	go func() {
		pair.newStream()
		close(claimed)
	}()
	select {
	case <-claimed:
		t.Fatal("the claim completed while a write was still in flight")
	case <-time.After(150 * time.Millisecond):
	}

	// Ending the pair releases the parked write, and the claim then completes.
	pair.shutdown()
	select {
	case <-writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the parked write never returned after the pair ended")
	}
	select {
	case <-claimed:
	case <-time.After(2 * time.Second):
		t.Fatal("the claim never completed once the write landed")
	}
}

// TestRelayKCPStreamConcurrentClaimsSerialize pins that builds racing from
// different adapter generations cannot both hold the pair: every claim retires
// its predecessor before installing, so exactly one view stays live.
func TestRelayKCPStreamConcurrentClaimsSerialize(t *testing.T) {
	e := newTestEngine(t)
	e.faults.Store(&faults{since: time.Now()})
	peer := derpclient.PublicKey{5}
	pair := e.relayKCPPairFor(peer)
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	pair.register(pc)
	if _, err := pair.session(); err != nil {
		t.Fatal(err)
	}

	views := make([]*relayKCPStream, 8)
	var wg sync.WaitGroup
	for i := range views {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			views[i] = pair.newStream()
		}(i)
	}
	wg.Wait()

	pair.mu.Lock()
	cur := pair.stream
	pair.mu.Unlock()
	live := 0
	for _, v := range views {
		if v != nil && !v.closed.Load() {
			live++
		}
	}
	if live != 1 || cur == nil {
		t.Fatalf("after concurrent claims: %d live views, pair.stream %v — want exactly one", live, cur != nil)
	}
}

// startCountingDERPServer starts a minimal DERP server that counts FrameSendPacket
// frames. It exists only so tests can verify WriteTo maps to a single underlying
// send without building a full relayServer or engine.
func startCountingDERPServer(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	var sends atomic.Int64

	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()

	mux := http.NewServeMux()
	mux.HandleFunc("/derp", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:    []string{"derp"},
			OriginPatterns:  []string{"*"},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer ws.Close(websocket.StatusInternalError, "bye")

		ctx := r.Context()
		conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
		br := bufio.NewReader(conn)
		bw := bufio.NewWriter(conn)

		// FrameServerKey: magic + server public key.
		var greet [8 + 32]byte
		copy(greet[:], derpclient.Magic)
		copy(greet[8:], pub[:])
		if err := writeTestFrame(bw, 0x01, greet[:]); err != nil {
			return
		}
		if err := bw.Flush(); err != nil {
			return
		}

		// FrameClientInfo: client pub + sealed box.
		ft, body, err := readTestFrame(br)
		if err != nil || ft != 0x02 || len(body) < 32 {
			return
		}
		var clientPub derpclient.PublicKey
		copy(clientPub[:], body[:32])

		// FrameServerInfo: sealed server info.
		sealed := priv.SealTo(clientPub, []byte("{}"))
		if err := writeTestFrame(bw, 0x03, sealed); err != nil {
			return
		}
		if err := bw.Flush(); err != nil {
			return
		}

		// Count every FrameSendPacket.
		for {
			ft, body, err := readTestFrame(br)
			if err != nil {
				return
			}
			if ft == 0x04 && len(body) >= 32 {
				sends.Add(1)
			}
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return "ws://" + srv.Listener.Addr().String() + "/derp", &sends
}

func writeTestFrame(bw *bufio.Writer, ft byte, body []byte) error {
	var hdr [5]byte
	hdr[0] = ft
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(body)))
	if _, err := bw.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := bw.Write(body); err != nil {
		return err
	}
	return nil
}

func readTestFrame(br *bufio.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return 0, nil, err
	}
	l := binary.BigEndian.Uint32(hdr[1:])
	body := make([]byte, l)
	if _, err := io.ReadFull(br, body); err != nil {
		return 0, nil, err
	}
	return hdr[0], body, nil
}
