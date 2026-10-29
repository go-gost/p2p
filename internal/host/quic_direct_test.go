package host

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestDirectPacketConnFiltersAndEchoes covers the net.PacketConn view quic-go
// gets of a direct underlay: only the punched peer's data is returned, seed
// magic is echoed and kept out of the data plane, and the underlay's 1s idle
// deadline is swallowed instead of surfacing as a read timeout.
func TestDirectPacketConnFiltersAndEchoes(t *testing.T) {
	a := mustListenUDP(t)
	b := mustListenUDP(t)
	foreign := mustListenUDP(t)
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
		_ = foreign.Close()
	})

	var mine [seedTokenLen]byte
	mine[0] = 1
	peerAddr := udpAddrPort(t, b)
	u := newDirectUnderlayToken(a, peerAddr, mine)
	pc := &directPacketConn{u: u}
	t.Cleanup(func() { _ = pc.Close() })

	if got, want := pc.LocalAddr().String(), a.LocalAddr().String(); got != want {
		t.Fatalf("LocalAddr = %q, want %q", got, want)
	}
	if got, want := pc.RemoteAddr().String(), b.LocalAddr().String(); got != want {
		t.Fatalf("RemoteAddr = %q, want %q", got, want)
	}

	type result struct {
		data string
		addr net.Addr
		err  error
	}
	results := make(chan result, 8)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			results <- result{data: string(buf[:n]), addr: addr, err: err}
			if err != nil {
				return
			}
		}
	}()

	// A foreign source must be dropped before it can reach quic-go.
	if _, err := foreign.WriteToUDP([]byte("foreign"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("foreign write: %v", err)
	}
	if _, err := b.WriteToUDP([]byte("hello"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	select {
	case r := <-results:
		if r.err != nil {
			t.Fatalf("ReadFrom: %v", r.err)
		}
		if r.data != "hello" {
			t.Fatalf("ReadFrom = %q, want %q", r.data, "hello")
		}
		if r.addr == nil || r.addr.String() != b.LocalAddr().String() {
			t.Fatalf("ReadFrom addr = %v, want %v", r.addr, b.LocalAddr())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the peer's datagram")
	}

	// A peer seed probe is echoed to the peer, never surfaced to quic-go.
	peerProbe := append(append([]byte(nil), seedProbeMagic[:]...), make([]byte, seedTokenLen)...)
	peerProbe[len(seedProbeMagic)] = 2 // a peer token, distinct from ours
	if _, err := b.WriteToUDP(peerProbe, a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := b.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer did not receive the seed echo: %v", err)
	}
	if !bytes.Equal(buf[:n], peerProbe) {
		t.Fatalf("seed echo = %q, want %q", buf[:n], peerProbe)
	}

	// The underlay read deadline fires after 1s by design; directPacketConn
	// must absorb that tick rather than report a timeout to quic-go.
	select {
	case r := <-results:
		t.Fatalf("ReadFrom returned during an idle tick: %+v", r)
	case <-time.After(1200 * time.Millisecond):
	}
	if _, err := b.WriteToUDP([]byte("after-tick"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("peer write after tick: %v", err)
	}
	select {
	case r := <-results:
		if r.err != nil {
			t.Fatalf("ReadFrom after tick: %v", r.err)
		}
		if r.data != "after-tick" {
			t.Fatalf("ReadFrom after tick = %q, want %q", r.data, "after-tick")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle tick was not swallowed: ReadFrom never resumed")
	}

	if err := pc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case r := <-results:
		if !errors.Is(r.err, io.EOF) {
			t.Fatalf("ReadFrom after Close = %v, want io.EOF", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not return io.EOF after Close")
	}
}

// directSeqSentinel ends a numbered stream once the test stops the writers.
// Real sequence numbers start at 1, so zero is unused and all-ones is free.
const directSeqSentinel = ^uint64(0)

// seqOutcome is one direction's numbered-stream result.
type seqOutcome struct {
	n   uint64
	err error
}

// writeDirectSeq writes incrementing 8-byte records until stop is closed, then
// writes the sentinel and returns. The pause keeps packets flowing through
// every migration phase without flooding the stream.
func writeDirectSeq(stop <-chan struct{}, w io.Writer, pause time.Duration) error {
	buf := make([]byte, 8)
	var seq uint64
	for {
		select {
		case <-stop:
			binary.BigEndian.PutUint64(buf, directSeqSentinel)
			n, err := w.Write(buf)
			if err == nil && n != len(buf) {
				err = io.ErrShortWrite
			}
			return err
		default:
		}

		seq++
		binary.BigEndian.PutUint64(buf, seq)
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n != len(buf) {
			return io.ErrShortWrite
		}
		time.Sleep(pause)
	}
}

// readDirectSeq reads numbered records until the sentinel, rejecting loss and
// reordering. It publishes progress so the test can wait for a path to carry
// traffic before moving to the next migration phase.
func readDirectSeq(r io.Reader, progress *atomic.Uint64) (uint64, error) {
	buf := make([]byte, 8)
	var want uint64 = 1
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return want - 1, err
		}
		seq := binary.BigEndian.Uint64(buf)
		if seq == directSeqSentinel {
			return want - 1, nil
		}
		if seq != want {
			return want - 1, fmt.Errorf("record %d, want %d", seq, want)
		}
		want++
		progress.Store(want - 1)
	}
}

// waitDirectProgress waits until both directions have carried at least want
// records.
func waitDirectProgress(t *testing.T, phase string, client, server *atomic.Uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if client.Load() >= want && server.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: client=%d server=%d records, want >= %d", phase, client.Load(), server.Load(), want)
}

// waitQUICRemoteAddr waits for p's QUIC connection to report want as its
// remote address, which is how a server observes a path migration.
func waitQUICRemoteAddr(t *testing.T, p *quicPair, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.mu.Lock()
		conn := p.conn
		p.mu.Unlock()
		if conn != nil && conn.RemoteAddr().String() == want {
			return
		}
		if time.Now().After(deadline) {
			got := "<nil>"
			if conn != nil {
				got = conn.RemoteAddr().String()
			}
			t.Fatalf("server remote addr = %q, want %q", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestQUICPairMigratesRelayDirectRelay is the product-level migration spike:
// one QUIC pair carries a numbered stream in both directions while it migrates
// relay -> direct -> relay -> a fresh direct path. The server's RemoteAddr is
// the observable, and every record must arrive in order with none lost.
func TestQUICPairMigratesRelayDirectRelay(t *testing.T) {
	clientStop := make(chan struct{})
	serverStop := make(chan struct{})
	var clientProgress, serverProgress atomic.Uint64
	serverDone := make(chan seqOutcome, 1)

	serverOnStream := func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		readDone := make(chan seqOutcome, 1)
		go func() {
			n, err := readDirectSeq(c, &serverProgress)
			readDone <- seqOutcome{n: n, err: err}
		}()
		writeErr := writeDirectSeq(serverStop, c, time.Millisecond)
		r := <-readDone
		serverDone <- seqOutcome{n: r.n, err: errors.Join(writeErr, r.err)}
	}

	client, server := newQUICPairTestPair(t, nil, serverOnStream)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := client.openStream(ctx)
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if err := stream.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	clientDone := make(chan seqOutcome, 1)
	go func() {
		n, err := readDirectSeq(stream, &clientProgress)
		clientDone <- seqOutcome{n: n, err: err}
	}()
	clientWrite := make(chan error, 1)
	go func() { clientWrite <- writeDirectSeq(clientStop, stream, time.Millisecond) }()

	// Traffic must be flowing before the first migration proves anything.
	waitDirectProgress(t, "relay", &clientProgress, &serverProgress, 100)

	clientSock := mustListenUDP(t)
	serverSock := mustListenUDP(t)
	t.Cleanup(func() {
		_ = clientSock.Close()
		_ = serverSock.Close()
	})
	clientAddr, serverAddr := udpAddrPort(t, clientSock), udpAddrPort(t, serverSock)
	var clientToken, serverToken [seedTokenLen]byte
	clientToken[0] = 1
	serverToken[0] = 2

	// Install the server's receiving side first: the client prefers direct as
	// soon as addDirect returns, and no datagram should be sent into a path
	// that is not installed yet.
	if err := server.addDirect(serverSock, clientAddr, serverToken); err != nil {
		t.Fatalf("server addDirect: %v", err)
	}
	if err := client.addDirect(clientSock, serverAddr, clientToken); err != nil {
		t.Fatalf("client addDirect: %v", err)
	}
	directAddr := "direct:" + clientAddr.String()
	waitQUICRemoteAddr(t, server, directAddr)
	if got := client.pathName(); got != quicPathDirect {
		t.Fatalf("client path after addDirect = %q, want %q", got, quicPathDirect)
	}
	waitDirectProgress(t, "direct", &clientProgress, &serverProgress, 500)

	// Retire the first direct path. The server keeps its own direct underlay
	// until the client is back on relay, so the return migration has a live
	// path to follow.
	client.removeDirect(clientSock)
	waitQUICRemoteAddr(t, server, quicPathRelay)
	server.removeDirect(serverSock)
	if got := server.pathName(); got != quicPathRelay {
		t.Fatalf("server path after relay migration = %q, want %q", got, quicPathRelay)
	}
	waitDirectProgress(t, "relay-again", &clientProgress, &serverProgress, 750)

	// A fresh punch gets a new socket pair and a new direct underlay.
	clientSock2 := mustListenUDP(t)
	serverSock2 := mustListenUDP(t)
	t.Cleanup(func() {
		_ = clientSock2.Close()
		_ = serverSock2.Close()
	})
	clientAddr2, serverAddr2 := udpAddrPort(t, clientSock2), udpAddrPort(t, serverSock2)
	if err := server.addDirect(serverSock2, clientAddr2, serverToken); err != nil {
		t.Fatalf("server addDirect (fresh): %v", err)
	}
	if err := client.addDirect(clientSock2, serverAddr2, clientToken); err != nil {
		t.Fatalf("client addDirect (fresh): %v", err)
	}
	directAddr2 := "direct:" + clientAddr2.String()
	waitQUICRemoteAddr(t, server, directAddr2)
	waitDirectProgress(t, "direct-again", &clientProgress, &serverProgress, 1000)

	// A delayed retire from the old punch must not tear down the fresh
	// underlay: removeDirect only acts on the socket it recorded last.
	client.removeDirect(clientSock)
	server.removeDirect(serverSock)
	if got := client.pathName(); got != quicPathDirect {
		t.Fatalf("client path after stale retire = %q, want %q", got, quicPathDirect)
	}
	if got := server.pathName(); got != quicPathDirect {
		t.Fatalf("server path after stale retire = %q, want %q", got, quicPathDirect)
	}
	waitDirectProgress(t, "after-stale-retire", &clientProgress, &serverProgress, 1100)

	close(clientStop)
	close(serverStop)
	select {
	case err := <-clientWrite:
		if err != nil {
			t.Fatalf("client writer: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("client writer did not finish")
	}
	var clientRead, serverRead seqOutcome
	select {
	case clientRead = <-clientDone:
	case <-time.After(15 * time.Second):
		t.Fatal("client reader did not finish")
	}
	select {
	case serverRead = <-serverDone:
	case <-time.After(15 * time.Second):
		t.Fatal("server stream handler did not finish")
	}
	if clientRead.err != nil {
		t.Fatalf("client read: %v", clientRead.err)
	}
	if serverRead.err != nil {
		t.Fatalf("server read: %v", serverRead.err)
	}
	if clientRead.n < 500 || serverRead.n < 500 {
		t.Fatalf("records client->server=%d server->client=%d, want >= 500 each", serverRead.n, clientRead.n)
	}
}
