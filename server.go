package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// server is the stub P2P service. Each OpenTunnel creates a local listener
// whose accepted connections are bridged to the peer target.
//
// Two data-plane modes:
//   - stub mode (default): bridge() dials the peer host:port directly. Only
//     meaningful on loopback / trusted networks.
//   - DERP engine mode (engine != nil): bridge() opens a mux stream to the
//     peer through the DERP relay; "peer" is the peer host's base64 public
//     key instead of a host:port.
//
// Trust boundary: the control channel is unauthenticated — any process that
// can reach the gRPC address can make this plugin dial arbitrary host:port
// (SSRF surface). Unlike other plugin hosts this one dials *out*, so bind the
// gRPC address to loopback (the default) unless authentication is added
// (--token). Cross-machine deployment additionally needs control TLS; the
// token travels over a plaintext channel today.
type server struct {
	proto.UnimplementedP2PServer
	bind    string
	engine  *Engine // DERP engine mode; nil = stub mode
	mu      sync.Mutex
	seq     atomic.Int64
	tunnels map[string]*tunnel
}

func newServer(bind string, engine *Engine) *server {
	return &server{
		bind:    bind,
		engine:  engine,
		tunnels: make(map[string]*tunnel),
	}
}

type tunnel struct {
	id     string
	target string  // stub mode: peer host:port
	engine *Engine // derp mode: stream source
	peer   string  // derp mode: peer public key (base64)
	ln     net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
}

func (s *server) OpenTunnel(ctx context.Context, req *proto.OpenTunnelRequest) (*proto.OpenTunnelReply, error) {
	peer := req.Peer
	if s.engine != nil {
		// DERP mode: the peer is a public key; validate its shape now and
		// fail fast with a clear error.
		if _, err := parsePeerKey(peer); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid peer %q: %v", peer, err)
		}
	} else {
		host, port, err := net.SplitHostPort(req.Peer)
		if err != nil || host == "" || port == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid peer %q", req.Peer)
		}
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(s.bind, "0"))
	if err != nil {
		return &proto.OpenTunnelReply{Ok: false, Error: err.Error()}, nil
	}
	t := &tunnel{
		id:     fmt.Sprintf("tunnel-%d", s.seq.Add(1)),
		target: peer,
		ln:     ln,
		conns:  make(map[net.Conn]struct{}),
	}
	if s.engine != nil {
		t.engine = s.engine
		t.peer = peer
	}
	s.mu.Lock()
	s.tunnels[t.id] = t
	s.mu.Unlock()
	go t.serve()
	return &proto.OpenTunnelReply{Ok: true, Id: t.id, Endpoint: ln.Addr().String()}, nil
}

// CloseTunnel is idempotent: closing an unknown or already-closed id is ok.
func (s *server) CloseTunnel(ctx context.Context, req *proto.CloseTunnelRequest) (*proto.CloseTunnelReply, error) {
	s.mu.Lock()
	t, ok := s.tunnels[req.Id]
	delete(s.tunnels, req.Id)
	s.mu.Unlock()
	if ok {
		t.close()
	}
	return &proto.CloseTunnelReply{Ok: true}, nil
}

func (s *server) Status(ctx context.Context, req *proto.StatusRequest) (*proto.StatusReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &proto.StatusReply{Tunnels: int32(len(s.tunnels))}, nil
}

// serve accepts connections until the tunnel is closed, bridging each one
// to the peer target.
func (t *tunnel) serve() {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return // listener closed
		}
		t.trackConn(conn)
		go t.bridge(conn)
	}
}

// bridge copies bytes in both directions between conn and the target: in
// stub mode the peer host:port dialed directly; in DERP engine mode a mux
// stream to the peer opened through the relay. When one direction ends, the
// peer side is half-closed (CloseWrite) so the other side can still drain;
// both ends are closed only after both directions are done.
// bridge logs each tunnel in gost style: "<src> <-> <dst>" on connect and
// ">-<" with the duration on disconnect.
func (t *tunnel) bridge(conn net.Conn) {
	var up net.Conn
	var err error
	if t.engine != nil {
		up, err = t.engine.OpenStream(t.peer)
	} else {
		up, err = net.DialTimeout("tcp", t.target, 5*time.Second)
	}
	if err != nil {
		slog.Debug("bridge dial failed", "tunnel", t.id, "target", t.target, "error", err)
		conn.Close()
		return
	}
	defer t.untrackConn(conn)
	t.trackConn(up)
	defer func() {
		up.Close()
		conn.Close()
	}()

	// t.target names the far end of the tunnel in both modes: the peer's
	// public key (DERP) or the peer host:port (stub). t.ln.Addr() is the local
	// endpoint handed to the gost client.
	endpoint := t.ln.Addr().String()
	transport := ""
	peerAddr := ""
	if tw, ok := up.(interface{ Transport() string }); ok {
		transport = tw.Transport()
	}
	if pa, ok := up.(interface{ PeerAddr() string }); ok {
		peerAddr = pa.PeerAddr()
	}
	attrs := []any{"peer", t.target, "endpoint", endpoint}
	if transport != "" {
		attrs = append(attrs, "transport", transport)
	}
	if peerAddr != "" {
		attrs = append(attrs, "peerAddr", peerAddr)
	}
	start := time.Now()
	slog.Info(fmt.Sprintf("%s <-> %s", endpoint, t.target), attrs...)
	defer func() {
		slog.Info(fmt.Sprintf("%s >-< %s", endpoint, t.target),
			append(append([]any{}, attrs...), "duration", time.Since(start).String())...)
	}()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, conn)
		halfCloseWrite(up)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, up)
		halfCloseWrite(conn)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// halfCloseWrite closes the write side of dst when the opposite direction
// has ended, so the remaining direction can still deliver data. Falls back
// to a full close when the connection type is not TCP.
func halfCloseWrite(dst net.Conn) {
	if tcp, ok := dst.(*net.TCPConn); ok {
		tcp.CloseWrite()
	} else {
		dst.Close()
	}
}

func (t *tunnel) trackConn(conn net.Conn) {
	t.mu.Lock()
	t.conns[conn] = struct{}{}
	t.mu.Unlock()
}

func (t *tunnel) untrackConn(conn net.Conn) {
	t.mu.Lock()
	delete(t.conns, conn)
	t.mu.Unlock()
}

func (t *tunnel) close() {
	t.ln.Close() // stops accept; no new conns
	t.mu.Lock()
	defer t.mu.Unlock()
	for conn := range t.conns {
		conn.Close()
	}
}
