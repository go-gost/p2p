package host

import (
	"context"
	"errors"
	"net"
)

// This file is the seam: the carrier-neutral surface the in-process API and the
// transports sit on. A transport separates authorize (OpenTunnel) from carry
// (AttachTunnel); the in-process path dials and listens directly (Dial,
// Listen).

// errListenWithTargets rejects Listen on a host configured with inbound
// targets: the two are mutually exclusive (with targets the host bridges
// inbound tunnels internally, the CLI behaviour).
var errListenWithTargets = errors.New("p2p: Listen and Config.Targets are mutually exclusive")

// errNotDerpMode rejects an operation that needs the relay engine (Listen, a
// udp tunnel) on a stub-mode host.
var errNotDerpMode = errors.New("p2p: requires derp mode")

// OpenTunnel validates a tunnel request and allocates its pending record,
// returning the id its carrier must present. The record is reclaimed by the
// pending GC if no carrier attaches within the TTL.
//
// Validation failures return p2p.ErrInvalidNetwork or p2p.ErrInvalidPeer
// (wrapping the cause), so a transport can map them without knowing the host's
// error shape.
func (h *Host) OpenTunnel(network, peer string) (string, error) {
	if h.Closed() {
		return "", errClosed
	}
	t, err := h.server.allocateTunnel(network, peer, false)
	if err != nil {
		return "", err
	}
	return t.id, nil
}

// AttachTunnel claims a pending record (single use) and serves the tunnel over
// s until it ends. abort, when non-nil, ends the carrier on teardown; a carrier
// whose stream the handler itself ends (gRPC) passes nil.
//
// An unknown or reclaimed id returns p2p.ErrUnknownTunnel, a second carrier
// p2p.ErrTunnelAttached, and a peer that cannot be opened
// p2p.ErrPeerUnreachable (wrapping the cause).
func (h *Host) AttachTunnel(id string, s Stream, abort func()) error {
	if h.Closed() {
		return errClosed
	}
	t, err := h.server.claimTunnel(id)
	if err != nil {
		return err
	}
	return h.server.attach(t, s, abort)
}

// Dial opens a tunnel to peer and returns its local end. network is normalized
// here (udp/udp4/udp6 -> udp), so callers may pass any dialer network. peer
// carries the same meaning as on the gRPC path: a base64 public key in DERP
// mode, a host:port in stub mode.
//
// ctx only bounds the call itself (allocation); the tunnel outlives it. The
// peer dial runs in the tunnel's serve goroutine, so the returned conn — not
// ctx — is the cancellation handle: closing it tears the tunnel down.
func (h *Host) Dial(ctx context.Context, network, peer string) (net.Conn, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if h.Closed() {
		return nil, errClosed
	}
	network = normalizeNetwork(network)
	// attached: the stream is served immediately, so the pending GC must not
	// reclaim the record while the caller is still using it.
	t, err := h.server.allocateTunnel(network, peer, true)
	if err != nil {
		return nil, err
	}
	// Re-check: a Close racing the check above would leave this record out of
	// server.close()'s teardown, and unlike the gRPC path there is no second
	// RPC to fail — the serve goroutine would dial the peer after Close.
	if h.Closed() {
		h.server.dropTunnel(t)
		return nil, errClosed
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	clientSide, serverSide := newPipePair(streamCtx)
	go func() {
		defer cancel() // stream end == carrier end
		_ = h.server.attach(t, serverSide, cancel)
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

// Listen returns a listener over inbound peer tunnel streams. Each accepted
// conn's RemoteAddr() carries the peer's base64 public key; the conn's bytes
// are the peer's tunnel exactly as they arrived (no framing on tcp). Streams
// arriving before Listen is called, or while the backlog is full, are closed
// and dropped. It is mutually exclusive with Config.Targets: with targets
// configured the host bridges inbound tunnels internally (the CLI behaviour).
// Single consumer: calling it twice returns the same listener. Call it before
// Connect so no inbound stream is missed.
func (h *Host) Listen() (net.Listener, error) {
	if h.engine == nil {
		return nil, errNotDerpMode
	}
	if len(h.cfg.TargetList()) > 0 {
		return nil, errListenWithTargets
	}
	h.listenOnce.Do(func() {
		q := newInboundQueue()
		h.engine.inbound.Store(q)
		ln := &inboundListener{q: q, host: h.PublicKey()}
		h.mu.Lock()
		h.listener = ln
		h.mu.Unlock()
	})
	// Read under the same lock Close reads it with: Listen may race a Close.
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.listener, nil
}

// normalizeNetwork maps a dialer network to the two the tunnel protocol
// defines, so a udp4/udp6 dialer still asks for a datagram stream. The library
// normalizes regardless of whether the caller already did, so the in-process
// path never depends on the consumer's normalization.
func normalizeNetwork(network string) string {
	switch network {
	case "udp", "udp4", "udp6":
		return "udp"
	default:
		return "tcp"
	}
}
