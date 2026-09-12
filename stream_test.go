package main

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// startTestServer runs svr over a real gRPC listener and returns a connected
// P2P client.
func startTestServer(t *testing.T, svr *server, opts ...grpc.ServerOption) proto.P2PClient {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(opts...)
	proto.RegisterP2PServer(gs, svr)
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return proto.NewP2PClient(conn)
}

// startTCPEcho runs a loopback echo server and returns its address.
func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// dialStream runs the two-RPC setup and returns the client-side data conn.
func dialStream(t *testing.T, c proto.P2PClient, peer string) (net.Conn, *proto.OpenTunnelReply) {
	t.Helper()
	reply, err := c.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: peer, Network: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if !reply.Ok {
		t.Fatalf("OpenTunnel not ok: %s", reply.Error)
	}
	sctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sctx = metadata.AppendToOutgoingContext(sctx, "id", reply.Id)
	stream, err := c.Tunnel(sctx)
	if err != nil {
		t.Fatal(err)
	}
	return newStreamConn(stream, cancel), reply
}

func tunnelCount(s *server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tunnels)
}

func waitTunnelCount(t *testing.T, s *server, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if tunnelCount(s) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("tunnel count = %d, want %d", tunnelCount(s), want)
}

func TestTunnelRoundTrip(t *testing.T) {
	svr := newServer(nil)
	c := startTestServer(t, svr)
	echo := startTCPEcho(t)

	conn, reply := dialStream(t, c, echo)
	if len(reply.Id) < 22 {
		t.Fatalf("tunnel id %q is too short to be 16 random bytes", reply.Id)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}

	// Close ends the stream: the handler returns and the record is dropped.
	conn.Close()
	waitTunnelCount(t, svr, 0)

	// Ids are random, not sequential.
	reply2, err := c.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: echo})
	if err != nil {
		t.Fatal(err)
	}
	if reply2.Id == reply.Id {
		t.Fatal("two OpenTunnel calls returned the same id")
	}
}

func TestTunnelUnknownID(t *testing.T) {
	svr := newServer(nil)
	c := startTestServer(t, svr)

	sctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sctx = metadata.AppendToOutgoingContext(sctx, "id", "bogus")
	stream, err := c.Tunnel(sctx)
	if err != nil {
		t.Fatal(err)
	}
	// The handler rejects before any data flows, so the first Recv carries
	// the status error.
	if _, err := stream.Recv(); status.Code(err) != codes.NotFound {
		t.Fatalf("Recv err = %v, want NotFound", err)
	}
	if n := tunnelCount(svr); n != 0 {
		t.Fatalf("tunnel count = %d, want 0", n)
	}
}

func TestOpenTunnelValidation(t *testing.T) {
	svr := newServer(nil)
	c := startTestServer(t, svr)

	// udp needs the DERP engine (a peer key); stub mode rejects it.
	if _, err := c.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: "127.0.0.1:9999", Network: "udp"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("udp OpenTunnel err = %v, want InvalidArgument", err)
	}
	// Unknown network is a request error.
	if _, err := c.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: "127.0.0.1:9999", Network: "sctp"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("sctp OpenTunnel err = %v, want InvalidArgument", err)
	}
	// Stub mode validates the peer as host:port.
	if _, err := c.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: "foo"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("peer=foo OpenTunnel err = %v, want InvalidArgument", err)
	}
	if n := tunnelCount(svr); n != 0 {
		t.Fatalf("tunnel count = %d, want 0", n)
	}
}

// TestPendingGC covers the record lifecycle around the GC: a record whose
// stream never arrives is reclaimed, an attached record survives the TTL, and
// ending the stream drops it.
func TestPendingGC(t *testing.T) {
	oldTTL, oldInterval := pendingTTL, gcInterval
	pendingTTL, gcInterval = 50*time.Millisecond, 10*time.Millisecond
	defer func() { pendingTTL, gcInterval = oldTTL, oldInterval }()

	svr := newServer(nil)
	c := startTestServer(t, svr)

	// Abandoned setup: OpenTunnel without a stream must not leak.
	if _, err := c.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: "127.0.0.1:9999"}); err != nil {
		t.Fatal(err)
	}
	if n := tunnelCount(svr); n != 1 {
		t.Fatalf("tunnel count = %d, want 1", n)
	}
	waitTunnelCount(t, svr, 0)

	// A claimed record survives well past the TTL while its stream is live.
	conn, _ := dialStream(t, c, startTCPEcho(t))
	time.Sleep(150 * time.Millisecond) // > TTL: several sweeps must skip it
	if n := tunnelCount(svr); n != 1 {
		t.Fatalf("live tunnel was reclaimed: count = %d, want 1", n)
	}
	conn.Close()
	waitTunnelCount(t, svr, 0)
}

// TestPeerEOFEndsTunnel covers the host-initiated teardown: when the peer end
// closes first, the handler returns, the RPC finishes, and the client's
// parked Recv must come back (grpc-go finishStream cancels the stream) — the
// client conn must not hang after the peer goes away.
func TestPeerEOFEndsTunnel(t *testing.T) {
	svr := newServer(nil)
	c := startTestServer(t, svr)

	// A target that greets once, then closes: the peer end goes away first.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("bye"))
		conn.Close()
	}()

	conn, _ := dialStream(t, c, ln.Addr().String())
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "bye" {
		t.Fatalf("greeting = %q, %v; want bye", buf, err)
	}
	// The peer end is gone: the next read must see the tunnel end, not hang.
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("Read after peer EOF returned data, want the tunnel to end")
	}
	waitTunnelCount(t, svr, 0)
}

// TestTunnelIDSingleUse proves the id is a single-use credential: a second
// stream presenting a live tunnel's id is rejected and leaves the first
// stream working.
func TestTunnelIDSingleUse(t *testing.T) {
	svr := newServer(nil)
	c := startTestServer(t, svr)
	echo := startTCPEcho(t)

	conn, reply := dialStream(t, c, echo)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// A round trip first: it proves the handler has attached the record, so
	// the duplicate attempt below is deterministic.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}

	sctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sctx = metadata.AppendToOutgoingContext(sctx, "id", reply.Id)
	stream2, err := c.Tunnel(sctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream2.Recv(); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second stream Recv err = %v, want AlreadyExists", err)
	}

	// The first tunnel is untouched.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
}

// dialUDPStream runs the two-RPC setup for a udp tunnel and returns the
// client-side data conn.
func dialUDPStream(t *testing.T, c proto.P2PClient, peer string) (net.Conn, *proto.OpenTunnelReply) {
	t.Helper()
	reply, err := c.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: peer, Network: "udp"})
	if err != nil {
		t.Fatal(err)
	}
	if !reply.Ok {
		t.Fatalf("OpenTunnel not ok: %s", reply.Error)
	}
	sctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sctx = metadata.AppendToOutgoingContext(sctx, "id", reply.Id)
	stream, err := c.Tunnel(sctx)
	if err != nil {
		t.Fatal(err)
	}
	return newStreamConn(stream, cancel), reply
}

// TestUDPTunnelEndToEnd wires two servers and engines through the test relay:
// a udp tunnel on each side, then bytes written on one Tunnel stream come out
// of the other — the datagram channel paired each peer edge with its local
// edge and pipes bytes through untouched.
func TestUDPTunnelEndToEnd(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, "", privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// Create both channels up front (the OpenTunnels below reuse them), so the
	// opener's very first peer-edge attempt finds the responder's channel.
	chA := engineA.openChannel(pubB)
	defer chA.release()
	chB := engineB.openChannel(pubA)
	defer chB.release()

	svrA := newServer(engineA)
	svrB := newServer(engineB)
	cA := startTestServer(t, svrA)
	cB := startTestServer(t, svrB)

	keyA := base64.RawURLEncoding.EncodeToString(pubA[:])
	keyB := base64.RawURLEncoding.EncodeToString(pubB[:])

	connA, _ := dialUDPStream(t, cA, keyB)
	defer connA.Close()
	connB, _ := dialUDPStream(t, cB, keyA)
	defer connB.Close()

	// Both channels must have their peer edge up before data flows.
	waitStream(t, engineA.channel(pubB))
	waitStream(t, engineB.channel(pubA))

	connA.SetDeadline(time.Now().Add(5 * time.Second))
	connB.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connA.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(connB, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "one" {
		t.Fatalf("A->B = %q, want one", buf)
	}
	if _, err := connB.Write([]byte("back")); err != nil {
		t.Fatal(err)
	}
	buf2 := make([]byte, 4)
	if _, err := io.ReadFull(connA, buf2); err != nil {
		t.Fatal(err)
	}
	if string(buf2) != "back" {
		t.Fatalf("B->A = %q, want back", buf2)
	}

	// Closing one side tears its record (and channel reference) down.
	connA.Close()
	waitTunnelCount(t, svrA, 0)
}

// TestStreamTokenCheck covers the defense-in-depth stream interceptor: the
// token check gates Tunnel while the unary OpenTunnel stays open (its own
// interceptor is a separate concern).
func TestStreamTokenCheck(t *testing.T) {
	svr := newServer(nil)
	c := startTestServer(t, svr, grpc.StreamInterceptor(streamAuthInterceptor("secret")))
	echo := startTCPEcho(t)

	reply, err := c.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: echo})
	if err != nil || !reply.Ok {
		t.Fatalf("OpenTunnel = %v, %v", reply, err)
	}

	// Without the token the stream is rejected before the handler runs.
	sctx := metadata.AppendToOutgoingContext(context.Background(), "id", reply.Id)
	stream, err := c.Tunnel(sctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Recv err = %v, want Unauthenticated", err)
	}
	if n := tunnelCount(svr); n != 1 {
		t.Fatalf("rejected stream consumed the record: count = %d, want 1", n)
	}

	// With it, the tunnel works end to end.
	sctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sctx = metadata.AppendToOutgoingContext(sctx, "id", reply.Id, "token", "secret")
	stream, err = c.Tunnel(sctx)
	if err != nil {
		t.Fatal(err)
	}
	conn := newStreamConn(stream, cancel)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
}
