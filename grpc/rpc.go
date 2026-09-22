package grpc

import (
	"context"
	"errors"
	"net"

	"github.com/go-gost/p2p"
	pb "github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// OpenTunnel authorizes a tunnel and allocates its id; the client presents that
// id as the "id" metadata key on the Tunnel stream. No endpoint is returned —
// the stream is the data plane. A record whose stream never arrives is
// reclaimed by the endpoint's pending GC.
func (s *Server) OpenTunnel(ctx context.Context, req *pb.OpenTunnelRequest) (*pb.OpenTunnelReply, error) {
	id, err := s.ep.Host().OpenTunnel(req.GetNetwork(), req.GetPeer())
	if err != nil {
		return nil, mapError(err)
	}
	return &pb.OpenTunnelReply{Ok: true, Id: id}, nil
}

// Status reports the endpoint's live tunnel count and transport stats.
func (s *Server) Status(ctx context.Context, req *pb.StatusRequest) (*pb.StatusReply, error) {
	st := s.ep.Status()
	return &pb.StatusReply{
		Tunnels:       int32(st.Tunnels),
		DirectPeers:   int32(st.DirectPeers),
		DerpPeers:     int32(st.DerpPeers),
		PunchAttempts: st.PunchAttempts,
		PunchSuccess:  st.PunchSuccess,
		StreamsDirect: st.StreamsDirect,
		StreamsDerp:   st.StreamsDerp,
	}, nil
}

// Tunnel serves a tunnel's data stream. The stream is authorized by the id
// issued in OpenTunnel; the record pins the peer and target, so the client
// cannot spoof them. The stream's lifetime IS the tunnel's lifetime: when this
// handler returns — client EOF/abort, peer EOF, or endpoint shutdown — the
// record is dropped.
//
// The handler must return promptly once the pipe ends and must not wait for the
// streamconn pump goroutine: returning ends the RPC, which cancels the stream
// (grpc-go finishStream -> s.cancel) and unblocks the parked Recv.
func (s *Server) Tunnel(stream pb.P2P_TunnelServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	var id string
	if v := md.Get("id"); len(v) > 0 {
		id = v[0]
	}
	// No abort: a server stream is aborted by this handler returning.
	if err := s.ep.Host().AttachTunnel(id, &streamAdapter{stream}, nil); err != nil {
		return mapError(err)
	}
	return nil
}

// streamAdapter presents the gRPC Tunnel stream as the seam's byte Stream: the
// wire chunk type stays in this package.
type streamAdapter struct {
	stream pb.P2P_TunnelServer
}

func (a *streamAdapter) Send(b []byte) error {
	return a.stream.Send(&pb.Chunk{Data: b})
}

func (a *streamAdapter) Recv() ([]byte, error) {
	chunk, err := a.stream.Recv()
	if err != nil {
		return nil, err
	}
	return chunk.GetData(), nil
}

func (a *streamAdapter) Context() context.Context {
	return a.stream.Context()
}

// mapError maps the endpoint's sentinel errors to gRPC codes: the endpoint
// never learns a protocol, the transport never inspects the endpoint's
// internals.
func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, net.ErrClosed):
		// The endpoint is shutting down.
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, p2p.ErrInvalidNetwork), errors.Is(err, p2p.ErrInvalidPeer):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, p2p.ErrUnknownTunnel):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, p2p.ErrTunnelAttached):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, p2p.ErrPeerUnreachable):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
