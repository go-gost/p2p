package main

import (
	"log/slog"

	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Tunnel serves a tunnel's data stream. The stream is authorized by the id
// issued in OpenTunnel (presented as the "id" metadata key); the record pins
// the peer and target, so the client cannot spoof them. The stream's lifetime
// IS the tunnel's lifetime: when this handler returns — client EOF/abort,
// peer EOF, or engine shutdown — the record is dropped. A record whose stream
// never arrives is reclaimed by the pending GC.
//
// The handler must return promptly once the pipe ends and must not wait for
// the streamconn pump goroutine: returning ends the RPC, which cancels the
// stream (grpc-go finishStream -> s.cancel) and unblocks the parked Recv.
func (s *server) Tunnel(stream proto.P2P_TunnelServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	var id string
	if v := md.Get("id"); len(v) > 0 {
		id = v[0]
	}

	s.mu.Lock()
	t, ok := s.tunnels[id]
	attached := ok && t.attached
	if ok && !attached {
		t.attached = true // claimed: the GC stops considering it
	}
	s.mu.Unlock()
	if !ok {
		return status.Errorf(codes.NotFound, "unknown tunnel %q", shortID(id))
	}
	if attached {
		// The id is single-use: a second stream must not attach to a live
		// tunnel (the two would fight over the record's teardown).
		return status.Error(codes.AlreadyExists, "tunnel already attached")
	}
	defer s.dropTunnel(t)

	// The host side of the stream stays a raw byte pipe in every network
	// mode: for udp the framing travels through as bytes (GOST side frames,
	// the peer's GOST side parses), so the host never touches it.
	// No abort: a server stream is aborted by this handler returning.
	conn := newStreamConn(stream, nil)

	if t.network == "udp" {
		// A udp tunnel's stream is the datagram channel's local edge: the
		// channel pumps bytes between it and the peer edge. The handler parks
		// until the channel is done with this edge — a newer dial replaced
		// it, the channel was torn down, or the gost closed the stream (the
		// edge's read fails and its pump exits, closing done).
		<-t.ch.attachLocal(conn)
		return nil
	}

	up, err := t.openPeer()
	if err != nil {
		slog.Debug("tunnel open peer failed", "tunnel", shortID(t.id), "target", t.target, "error", err)
		return status.Errorf(codes.Unavailable, "open peer: %v", err)
	}
	t.pipe(conn, up, "stream:"+shortID(t.id), t.target)
	return nil
}
