package p2p

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
)

// Tunnel implements the in-process tunnel endpoint contract (Dial + Listen +
// Close). p2p does not import the consumer that defines that contract, so the
// match is structural; the embedding caller asserts it against the real
// interface.
var _ io.Closer = (*Tunnel)(nil)

// Tunnel exposes a Host as a tunnel endpoint for in-process use: it dials
// tunnels and takes inbound ones without a loopback gRPC control plane.
//
// Close stops the endpoint from accepting new tunnels and closes an inbound
// listener opened by Listen; it does not tear down the Host or any already-open
// tunnel. Those end with their own connections, exactly as the gRPC path's
// streams do.
type Tunnel struct {
	h      *Host
	closed atomic.Bool
}

// Tunnel returns an in-process tunnel endpoint backed by h.
func (h *Host) Tunnel() *Tunnel {
	return &Tunnel{h: h}
}

// Dial opens a tunnel to peer and returns its local end. network is
// normalized here (udp/udp4/udp6 -> udp), so callers may pass any dialer
// network. peer carries the same meaning as on the gRPC path: a base64 public
// key in DERP mode, a host:port in stub mode.
//
// ctx only bounds the call itself (allocation); the tunnel outlives it. The
// peer dial runs in the tunnel's serve goroutine, so the returned conn — not
// ctx — is the cancellation handle: closing it tears the tunnel down.
func (t *Tunnel) Dial(ctx context.Context, network, peer string) (net.Conn, error) {
	if t.closed.Load() {
		return nil, net.ErrClosed
	}
	return t.h.openTunnelStream(ctx, normalizeNetwork(network), peer)
}

// Listen returns a listener over inbound peer tunnel streams. Each accepted
// conn's RemoteAddr() carries the peer's base64 public key; the conn's bytes
// are the peer's tunnel exactly as they arrived (no framing on tcp). Streams
// arriving before Listen is called, or while the backlog is full, are closed
// and dropped. It is mutually exclusive with Config.Targets: with targets
// configured the host bridges inbound tunnels internally (the CLI behaviour).
// Single consumer: calling it twice returns the same listener. Call it before
// Connect so no inbound stream is missed.
func (t *Tunnel) Listen() (net.Listener, error) {
	if t.h.engine == nil {
		return nil, errors.New("p2p: Listen requires derp mode")
	}
	if len(t.h.cfg.TargetList()) > 0 {
		return nil, errors.New("p2p: Listen and Config.Targets are mutually exclusive")
	}
	t.h.listenOnce.Do(func() {
		q := newInboundQueue()
		t.h.engine.inbound.Store(q)
		t.h.listener = &inboundListener{q: q, host: t.h.PublicKey()}
	})
	return t.h.listener, nil
}

// Close stops the endpoint from accepting new tunnels and closes the inbound
// listener (Accept then returns net.ErrClosed). It is safe to call more than
// once.
func (t *Tunnel) Close() error {
	t.closed.Store(true)
	if t.h.listener != nil {
		t.h.listener.Close()
	}
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
	// Re-check: a Close racing the check above would leave this record out of
	// server.close()'s teardown, and unlike the gRPC path there is no second
	// RPC to fail — the serve goroutine would dial the peer after Close.
	if h.isClosed() {
		h.server.dropTunnel(t)
		return nil, net.ErrClosed
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
	if network == "udp" {
		// A udp tunnel carries datagrams, so the GOST-side conn owns the
		// 2-byte framing (frame.go) exactly as x/p2p/streamconn's conn does on
		// the gRPC carrier: both carriers then hand the inner dialer the same
		// conn shape. Without it the outlet's frame parser never sees a frame.
		return newFrameConn(conn), nil
	}
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
