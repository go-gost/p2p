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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/go-gost/p2p/internal/derpclient"
)

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
