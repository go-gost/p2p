package grpc

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/endpoint"
	pb "github.com/go-gost/plugin/p2p/proto"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// newTestEndpoint builds an endpoint from cfg and closes it when the test ends.
func newTestEndpoint(t *testing.T, cfg *p2p.Config) *endpoint.Endpoint {
	t.Helper()
	if cfg == nil {
		cfg = &p2p.Config{}
	}
	ep, err := endpoint.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ep.Close() })
	return ep
}

// newTestServer wires an endpoint and its gRPC transport on an ephemeral
// address, so a test that starts it never collides with a real service.
func newTestServer(t *testing.T, cfg *p2p.Config) (*Server, *endpoint.Endpoint) {
	t.Helper()
	ep := newTestEndpoint(t, cfg)
	srv, err := New(ep, WithAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, ep
}

// startTestServer runs srv over a real gRPC listener and returns a connected
// P2P client.
func startTestServer(t *testing.T, srv *Server, opts ...ggrpc.ServerOption) pb.P2PClient {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := ggrpc.NewServer(opts...)
	pb.RegisterP2PServer(gs, srv)
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)

	conn, err := ggrpc.NewClient(ln.Addr().String(), ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewP2PClient(conn)
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

// openStream runs the two-RPC setup — OpenTunnel, then the Tunnel stream bound
// to its id — and returns the client-side stream. The stream carries raw chunks
// exactly as GOST's client does; the deadline keeps a broken tunnel from
// hanging the test.
func openStream(t *testing.T, c pb.P2PClient, peer, network string, md ...string) (pb.P2P_TunnelClient, *pb.OpenTunnelReply) {
	t.Helper()
	reply, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: peer, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	if !reply.Ok {
		t.Fatalf("OpenTunnel not ok: %s", reply.Error)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	ctx = metadata.AppendToOutgoingContext(ctx, append([]string{"id", reply.Id}, md...)...)
	stream, err := c.Tunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return stream, reply
}

// send writes one chunk to the stream and reads one back, asserting the echo.
func roundTripStream(t *testing.T, stream pb.P2P_TunnelClient, payload string) {
	t.Helper()
	if err := stream.Send(&pb.Chunk{Data: []byte(payload)}); err != nil {
		t.Fatal(err)
	}
	chunk, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.GetData()) != payload {
		t.Fatalf("echo = %q, want %q", chunk.GetData(), payload)
	}
}

func waitTunnelCount(t *testing.T, ep *endpoint.Endpoint, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ep.Status().Tunnels == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("tunnel count = %d, want %d", ep.Status().Tunnels, want)
}

func TestTunnelRoundTrip(t *testing.T) {
	srv, ep := newTestServer(t, nil)
	c := startTestServer(t, srv)

	stream, reply := openStream(t, c, startTCPEcho(t), "tcp")
	if len(reply.Id) < 22 {
		t.Fatalf("tunnel id %q is too short to be 16 random bytes", reply.Id)
	}
	roundTripStream(t, stream, "ping")

	// Ending the stream ends the tunnel: the handler returns and the record is
	// dropped.
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	waitTunnelCount(t, ep, 0)

	// Ids are random, not sequential.
	reply2, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: startTCPEcho(t)})
	if err != nil {
		t.Fatal(err)
	}
	if reply2.Id == reply.Id {
		t.Fatal("two OpenTunnel calls returned the same id")
	}
}

func TestTunnelUnknownID(t *testing.T) {
	srv, ep := newTestServer(t, nil)
	c := startTestServer(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "id", "bogus")
	stream, err := c.Tunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The handler rejects before any data flows, so the first Recv carries
	// the status error.
	if _, err := stream.Recv(); status.Code(err) != codes.NotFound {
		t.Fatalf("Recv err = %v, want NotFound", err)
	}
	if n := ep.Status().Tunnels; n != 0 {
		t.Fatalf("tunnel count = %d, want 0", n)
	}
}

func TestOpenTunnelValidation(t *testing.T) {
	srv, ep := newTestServer(t, nil)
	c := startTestServer(t, srv)

	// udp needs the relay engine (a peer key); stub mode rejects it.
	if _, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: "127.0.0.1:9999", Network: "udp"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("udp OpenTunnel err = %v, want InvalidArgument", err)
	}
	// Unknown network is a request error.
	if _, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: "127.0.0.1:9999", Network: "sctp"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("sctp OpenTunnel err = %v, want InvalidArgument", err)
	}
	// Stub mode validates the peer as host:port.
	if _, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: "foo"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("peer=foo OpenTunnel err = %v, want InvalidArgument", err)
	}
	if n := ep.Status().Tunnels; n != 0 {
		t.Fatalf("tunnel count = %d, want 0", n)
	}
}

// TestPeerEOFEndsTunnel covers the endpoint-initiated teardown: when the peer
// end closes first, the handler returns and the RPC finishes, so the client's
// parked Recv must come back (grpc-go finishStream cancels the stream) — the
// client must not hang after the peer goes away.
func TestPeerEOFEndsTunnel(t *testing.T) {
	srv, ep := newTestServer(t, nil)
	c := startTestServer(t, srv)

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

	stream, _ := openStream(t, c, ln.Addr().String(), "tcp")
	chunk, err := stream.Recv()
	if err != nil || string(chunk.GetData()) != "bye" {
		t.Fatalf("greeting = %q, %v; want bye", chunk.GetData(), err)
	}
	// The peer end is gone: the next Recv must see the tunnel end, not hang.
	if _, err := stream.Recv(); err == nil {
		t.Fatal("Recv after peer EOF returned data, want the tunnel to end")
	}
	waitTunnelCount(t, ep, 0)
}

// TestTunnelIDSingleUse proves the id is a single-use credential: a second
// stream presenting a live tunnel's id is rejected and leaves the first
// stream working.
func TestTunnelIDSingleUse(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	c := startTestServer(t, srv)

	stream, reply := openStream(t, c, startTCPEcho(t), "tcp")
	// A round trip first: it proves the handler has attached the record, so
	// the duplicate attempt below is deterministic.
	roundTripStream(t, stream, "ping")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "id", reply.Id)
	stream2, err := c.Tunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream2.Recv(); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second stream Recv err = %v, want AlreadyExists", err)
	}

	// The first tunnel is untouched.
	roundTripStream(t, stream, "pong")
}

// TestStreamTokenCheck covers the defense-in-depth stream interceptor: the
// token check gates Tunnel while the unary OpenTunnel stays open (its own
// interceptor is a separate concern).
func TestStreamTokenCheck(t *testing.T) {
	srv, ep := newTestServer(t, nil)
	c := startTestServer(t, srv, ggrpc.StreamInterceptor(streamAuthInterceptor("secret")))

	reply, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: startTCPEcho(t)})
	if err != nil || !reply.Ok {
		t.Fatalf("OpenTunnel = %v, %v", reply, err)
	}

	// Without the token the stream is rejected before the handler runs.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "id", reply.Id)
	stream, err := c.Tunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Recv err = %v, want Unauthenticated", err)
	}
	if n := ep.Status().Tunnels; n != 1 {
		t.Fatalf("rejected stream consumed the record: count = %d, want 1", n)
	}

	// With it, the tunnel works end to end.
	stream, _ = openStream(t, c, startTCPEcho(t), "tcp", "token", "secret")
	roundTripStream(t, stream, "ping")
}

// TestStartFailsOnBadForward pins the CLI-visible behavior: a forward that
// cannot be registered is a configuration error, so Start returns it instead
// of serving without the forward. A stub-mode endpoint cannot hold a forward.
func TestStartFailsOnBadForward(t *testing.T) {
	srv, _ := newTestServer(t, &p2p.Config{Forwards: []p2p.ForwardConfig{{Listen: "127.0.0.1:0", Peer: "abc"}}})
	if _, err := srv.Start(); err == nil {
		t.Fatal("Start with a stub-mode forward = nil error, want the registration failure")
	}
}

// TestStartServesWhenRelayUnreachable is the other half of the split: an
// unreachable relay is transient (the engine retries), so Start still listens
// and returns the address; only a forward failure is fatal.
func TestStartServesWhenRelayUnreachable(t *testing.T) {
	srv, _ := newTestServer(t, &p2p.Config{
		Derp:   "wss://127.0.0.1:1/derp", // refused: nothing listens on port 1
		KeyHex: strings.Repeat("11", 32), // in-memory key: no key file is written
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("Start with an unreachable relay = %v, want serve anyway", err)
	}
	if addr == "" {
		t.Fatal("Start returned an empty addr")
	}
	if srv.Addr() != addr {
		t.Fatalf("Addr() = %q, want %q", srv.Addr(), addr)
	}
	if srv.PublicKey() == "" {
		t.Fatal("PublicKey() is empty in relay mode")
	}
}

// TestTransportCloseLeavesEndpointServing pins the ownership rule: the
// transport owns its listener, the endpoint owns the engine, so closing the
// server stops the control plane and nothing else.
func TestTransportCloseLeavesEndpointServing(t *testing.T) {
	srv, ep := newTestServer(t, nil)
	addr, err := srv.Start()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ggrpc.NewClient(addr, ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := pb.NewP2PClient(conn)

	// The control plane serves before the close, and refuses after it.
	if _, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: startTCPEcho(t)}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: startTCPEcho(t)}); err == nil {
		t.Fatal("OpenTunnel after Server.Close = nil error, want a transport failure")
	}

	// The endpoint still dials in-process.
	pc, err := ep.Dial(context.Background(), "tcp", startTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(pc, buf); err != nil {
		t.Fatal(err)
	}
}

// TestEndpointCloseStopsTransport is the other half: closing the endpoint closes
// the transports attached to it — listener included, so the control-plane port
// does not outlive the endpoint.
func TestEndpointCloseStopsTransport(t *testing.T) {
	srv, ep := newTestServer(t, nil)
	addr, err := srv.Start()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ggrpc.NewClient(addr, ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := pb.NewP2PClient(conn)
	if _, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: startTCPEcho(t)}); err != nil {
		t.Fatal(err)
	}

	if err := ep.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.OpenTunnel(context.Background(), &pb.OpenTunnelRequest{Peer: "127.0.0.1:9"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("OpenTunnel after Endpoint.Close = %v, want Unavailable", err)
	}
	// The port must be free again: the endpoint closed the transport's listener
	// (and the test's cleanup closes the transport a second time, which the
	// Transport contract requires to be safe).
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("control-plane address still bound after Endpoint.Close: %v", err)
	}
	ln.Close()

	// A transport cannot be built against a dead endpoint, so the old "refuse to
	// bind against a stopped host" guard survives at construction time.
	if _, err := New(ep); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("New on a closed endpoint = %v, want net.ErrClosed", err)
	}
}

// TestPeerOpenFailureMapsToUnavailable pins the classification a client sees
// when the tunnel's peer end cannot be opened: unavailable (retry-shaped), not
// an internal error.
func TestPeerOpenFailureMapsToUnavailable(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	c := startTestServer(t, srv)

	// Port 1 on loopback refuses connections: the peer end cannot be opened.
	stream, _ := openStream(t, c, "127.0.0.1:1", "tcp")
	if _, err := stream.Recv(); status.Code(err) != codes.Unavailable {
		t.Fatalf("Recv err = %v, want Unavailable", err)
	}
}
