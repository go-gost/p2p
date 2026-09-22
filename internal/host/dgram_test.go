package host

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// startUDPStub is the "tun server" side: a plain UDP socket the edge dials.
// It returns the server socket plus the edge, and the edge is closed on
// cleanup.
func startUDPStub(t *testing.T) (*net.UDPConn, net.Conn) {
	t.Helper()
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	edge := newDgramEdge(client)
	t.Cleanup(func() { edge.Close() })
	return server, edge
}

// recvDatagram reads one datagram from the stub within a short window.
func recvDatagram(t *testing.T, server *net.UDPConn) ([]byte, error) {
	t.Helper()
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, maxFrame)
	n, _, err := server.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// TestDgramEdgeWriteSplitsFramesAcrossWrites: one frame arriving in two byte
// chunks yields exactly one datagram, and nothing is emitted until the frame
// is whole.
func TestDgramEdgeWriteSplitsFramesAcrossWrites(t *testing.T) {
	server, edge := startUDPStub(t)
	frame := appendFrame(nil, []byte("hello"))

	if _, err := edge.Write(frame[:3]); err != nil {
		t.Fatal(err)
	}
	// The stub must not have received anything yet: the frame is incomplete.
	server.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, err := server.ReadFromUDP(make([]byte, maxFrame)); err == nil {
		t.Fatal("a partial frame was emitted as a datagram")
	}

	if _, err := edge.Write(frame[3:]); err != nil {
		t.Fatal(err)
	}
	got, err := recvDatagram(t, server)
	if err != nil {
		t.Fatalf("no datagram after the frame completed: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("datagram = %q, want hello", got)
	}
}

// TestDgramEdgeWriteTwoFrames: one write carrying two whole frames yields two
// datagrams, in order.
func TestDgramEdgeWriteTwoFrames(t *testing.T) {
	server, edge := startUDPStub(t)
	var buf []byte
	buf = appendFrame(buf, []byte("ab"))
	buf = appendFrame(buf, []byte("cde"))

	if _, err := edge.Write(buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ab", "cde"} {
		got, err := recvDatagram(t, server)
		if err != nil {
			t.Fatalf("datagram %q: %v", want, err)
		}
		if string(got) != want {
			t.Fatalf("datagram = %q, want %q", got, want)
		}
	}
}

// TestDgramEdgeWriteSkipsEmptyFrame: a zero-length frame is not forwarded (the
// GOST side would discard an empty payload anyway).
func TestDgramEdgeWriteSkipsEmptyFrame(t *testing.T) {
	server, edge := startUDPStub(t)
	if _, err := edge.Write(appendFrame(nil, nil)); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, err := server.ReadFromUDP(make([]byte, maxFrame)); err == nil {
		t.Fatal("a zero-length frame was emitted as a datagram")
	}
}

// TestDgramEdgeReadFramesDatagram: a datagram from the stub comes back as its
// 2-byte-prefixed frame.
func TestDgramEdgeReadFramesDatagram(t *testing.T) {
	server, edge := startUDPStub(t)
	clientAddr := edge.(*dgramEdge).conn.LocalAddr().(*net.UDPAddr)
	payload := []byte("world")
	if _, err := server.WriteToUDP(payload, clientAddr); err != nil {
		t.Fatal(err)
	}

	want := appendFrame(nil, payload)
	got := make([]byte, len(want))
	edge.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(edge, got); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("frame = %x, want %x", got, want)
	}
}

// TestDgramEdgeReadSpansReads: a frame larger than the caller's buffer is
// delivered across several Reads, bytes intact and in order.
func TestDgramEdgeReadSpansReads(t *testing.T) {
	server, edge := startUDPStub(t)
	clientAddr := edge.(*dgramEdge).conn.LocalAddr().(*net.UDPAddr)
	payload := bytes.Repeat([]byte{0x7e}, 4000)
	if _, err := server.WriteToUDP(payload, clientAddr); err != nil {
		t.Fatal(err)
	}

	want := appendFrame(nil, payload)
	var got []byte
	edge.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64) // small on purpose: forces multiple Read calls
	for len(got) < len(want) {
		n, err := edge.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("assembled frame = %d bytes, mismatch (want %d)", len(got), len(want))
	}
}

// TestServeTargetStreamBridgesFramesToTarget: a tagged inbound stream is served
// purely from the udp pool -- frames on the stream become datagrams at the
// target, and a target datagram comes back as frames on the stream. No channel
// and no per-peer state is involved.
func TestServeTargetStreamBridgesFramesToTarget(t *testing.T) {
	e := newTestEngine(t)
	stub, spec := startHubStub(t)
	if err := e.addTargets([]string{spec}); err != nil {
		t.Fatal(err)
	}
	target, _ := e.targets.pick("udp")

	stream, peerSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		e.serveTargetStream(stream, target)
		close(done)
	}()

	// stream -> target: one framed datagram comes out as one datagram; echo a
	// datagram back to the source the stub sees.
	go peerSide.Write(appendFrame(nil, []byte("hello")))
	stub.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, maxFrame)
	n, from, err := stub.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("target got %q, %v; want hello", buf[:n], err)
	}
	if _, err := stub.WriteToUDP([]byte("world"), from); err != nil {
		t.Fatal(err)
	}

	// target -> stream: that datagram comes back framed.
	want := appendFrame(nil, []byte("world"))
	if got := readN(t, peerSide, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("stream got %x, want %x", got, want)
	}

	peerSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveTargetStream did not return after the stream closed")
	}
}

// TestDgramEdgeCloseWakesRead: Close unblocks a parked Read.
func TestDgramEdgeCloseWakesRead(t *testing.T) {
	_, edge := startUDPStub(t)
	errc := make(chan error, 1)
	go func() {
		_, err := edge.Read(make([]byte, 16))
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	edge.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Read returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake the parked Read")
	}
	// Close is idempotent.
	if err := edge.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}
