package host

import (
	"fmt"

	"github.com/go-gost/p2p"
)

// claimTunnel resolves the id issued by OpenTunnel and marks the record
// attached. The id is single-use: a second carrier must not attach to a live
// tunnel (the two would fight over the record's teardown).
func (s *server) claimTunnel(id string) (*tunnelRecord, error) {
	s.mu.Lock()
	t, ok := s.tunnels[id]
	attached := ok && t.attached
	if ok && !attached {
		t.attached = true // claimed: the GC stops considering it
	}
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w %q", p2p.ErrUnknownTunnel, shortID(id))
	}
	if attached {
		return nil, fmt.Errorf("%w %q", p2p.ErrTunnelAttached, shortID(id))
	}
	return t, nil
}

// attach serves t over stream until it ends, then drops the record: the stream's
// lifetime IS the tunnel's lifetime, whichever carrier holds it.
func (s *server) attach(t *tunnelRecord, stream Stream, abort func()) error {
	defer s.dropTunnel(t)
	return s.serveTunnel(t, stream, abort)
}

// serveTunnel runs one tunnel over stream, whichever carrier holds it: the gRPC
// Tunnel RPC or an in-process pipe. It is the single shared data-plane body, so
// both carriers behave identically.
//
// abort ends the stream on teardown: nil on the gRPC path (the handler
// returning ends the RPC) and the pipe's cancel for in-process tunnels.
//
// The host side of the stream stays a raw byte pipe in every network mode: for
// udp the framing travels through as bytes (GOST side frames, the peer's GOST
// side parses), so the host never touches it.
func (s *server) serveTunnel(t *tunnelRecord, stream Stream, abort func()) error {
	conn := newStreamConn(stream, abort)

	if t.network == "udp" {
		// A udp tunnel's stream is its link's local edge: the link pumps bytes
		// between it and the peer edge. The handler parks until the link is
		// torn down — the local pump's exit (the gost closed the stream) closes
		// it, and so does the record's drop.
		<-t.link.attach(conn)
		return nil
	}

	up, err := t.openPeer()
	if err != nil {
		t.log.Debug("tunnel open peer failed", "tunnel", shortID(t.id), "target", t.target, "error", err)
		return fmt.Errorf("%w: %w", p2p.ErrPeerUnreachable, err)
	}
	t.pipe(conn, up, "stream:"+shortID(t.id), t.target)
	return nil
}
