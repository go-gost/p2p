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
// Trust boundary: the control channel is unauthenticated — any process that
// can reach the gRPC address can make this plugin dial arbitrary host:port
// (SSRF surface). Unlike other plugin hosts this one dials *out*, so bind the
// gRPC address to loopback (the default) unless authentication is added.
type server struct {
	proto.UnimplementedP2PServer
	bind    string
	mu      sync.Mutex
	seq     atomic.Int64
	tunnels map[string]*tunnel
}

func newServer(bind string) *server {
	return &server{
		bind:    bind,
		tunnels: make(map[string]*tunnel),
	}
}

type tunnel struct {
	id     string
	target string
	ln     net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
}

func (s *server) OpenTunnel(ctx context.Context, req *proto.OpenTunnelRequest) (*proto.OpenTunnelReply, error) {
	host, port, err := net.SplitHostPort(req.Peer)
	if err != nil || host == "" || port == "" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid peer %q", req.Peer)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(s.bind, "0"))
	if err != nil {
		return &proto.OpenTunnelReply{Ok: false, Error: err.Error()}, nil
	}
	t := &tunnel{
		id:     fmt.Sprintf("tunnel-%d", s.seq.Add(1)),
		target: req.Peer,
		ln:     ln,
		conns:  make(map[net.Conn]struct{}),
	}
	s.mu.Lock()
	s.tunnels[t.id] = t
	s.mu.Unlock()
	go t.serve()
	slog.Debug("tunnel opened", "id", t.id, "peer", req.Peer, "endpoint", ln.Addr().String())
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

// bridge copies bytes in both directions between conn and the peer target.
// When one direction ends, the peer side is half-closed (CloseWrite) so the
// other side can still drain; both ends are closed only after both
// directions are done.
func (t *tunnel) bridge(conn net.Conn) {
	defer t.untrackConn(conn)
	up, err := net.DialTimeout("tcp", t.target, 5*time.Second)
	if err != nil {
		slog.Debug("bridge dial failed", "tunnel", t.id, "target", t.target, "error", err)
		conn.Close()
		return
	}
	t.trackConn(up)
	defer func() {
		up.Close()
		conn.Close()
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
	slog.Debug("tunnel closed", "id", t.id)
}