package p2p

import (
	"context"
	"io"
	"net"
	"sync/atomic"
)

// Provider implements the in-process tunnel provider contract
// (OpenTunnelStream + Close). p2p does not import the consumer that defines
// that contract, so the match is structural; the embedding caller asserts it
// against the real interface.
var _ io.Closer = (*Provider)(nil)

// Provider exposes a Host as a tunnel provider for in-process use: it opens
// tunnels without a loopback gRPC control plane.
//
// Close stops the provider from accepting new tunnels; it does not tear down
// the Host or any already-open tunnel. Those end with their own connections,
// exactly as the gRPC path's streams do.
type Provider struct {
	h      *Host
	closed atomic.Bool
}

// Provider returns an in-process tunnel provider backed by h.
func (h *Host) Provider() *Provider {
	return &Provider{h: h}
}

// OpenTunnelStream opens a tunnel to peer and returns its local end. network is
// normalized here (udp/udp4/udp6 -> udp), so callers may pass any dialer
// network. peer carries the same meaning as on the gRPC path: a base64 public
// key in DERP mode, a host:port in stub mode.
//
// ctx only bounds the call itself (allocation); the tunnel outlives it. The
// peer dial runs in the tunnel's serve goroutine, so the returned conn — not
// ctx — is the cancellation handle: closing it tears the tunnel down.
func (p *Provider) OpenTunnelStream(ctx context.Context, network, peer string) (net.Conn, error) {
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	return p.h.openTunnelStream(ctx, normalizeNetwork(network), peer)
}

// Close stops accepting new tunnels. It is safe to call more than once.
func (p *Provider) Close() error {
	p.closed.Store(true)
	return nil
}

// openTunnelStream allocates a tunnel and serves it over an in-memory stream,
// returning the caller's end. It is the in-process equivalent of the OpenTunnel
// RPC followed by the Tunnel stream: both paths run the same serveTunnel, so
// only the stream carrier differs.
func (h *Host) openTunnelStream(ctx context.Context, network, peer string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.isClosed() {
		return nil, net.ErrClosed
	}
	// attached: the stream is served immediately, so the pending GC must not
	// reclaim the record while the caller is still using it.
	t, err := h.server.allocateTunnel(network, peer, true)
	if err != nil {
		return nil, err
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	clientSide, serverSide := newPipePair(streamCtx)
	go func() {
		defer cancel() // stream end == RPC end
		defer h.server.dropTunnel(t)
		_ = h.server.serveTunnel(t, serverSide, cancel)
	}()
	conn := newStreamConn(clientSide, cancel)
	// Synthetic addresses: the tunnel has no socket, but connectors read
	// LocalAddr/RemoteAddr and call String on them.
	conn.local = streamAddr{network: network, addr: "p2p"}
	conn.remote = streamAddr{network: network, addr: peer}
	return conn, nil
}

// normalizeNetwork maps a dialer network to the two the tunnel protocol
// defines, so a udp4/udp6 dialer still asks for a datagram stream. The p2p
// library normalizes regardless of whether the caller already did, so the
// in-process path never depends on the consumer's normalization.
func normalizeNetwork(network string) string {
	switch network {
	case "udp", "udp4", "udp6":
		return "udp"
	default:
		return "tcp"
	}
}
