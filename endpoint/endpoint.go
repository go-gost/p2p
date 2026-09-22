package endpoint

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"sync"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/host"
)

// Endpoint is a p2p endpoint. It owns the host behind it — the engine, the
// tunnel registry and the data planes are implementation details a caller never
// holds — and exposes the two halves a consumer uses as one object: the
// endpoint-level half (identity, forwards) and the tunnel-level half
// (Dial/Listen).
type Endpoint struct {
	h   *host.Host
	log *slog.Logger

	mu         sync.Mutex
	transports []Transport
}

// Transport is a transport serving this endpoint — the thing a protocol needs
// on top of it (github.com/go-gost/p2p/grpc is one). Attach registers one so
// that closing the endpoint closes it too: a transport's listener must not
// outlive the endpoint it serves.
type Transport interface {
	// Close stops the transport, listener included. It must be safe to call
	// more than once.
	Close() error
}

// Option configures an Endpoint.
type Option func(*Endpoint)

// WithLogger sets the logger used by the endpoint and its engine. A transport
// sets its own (grpc.WithLogger); the default there is slog.Default().
func WithLogger(log *slog.Logger) Option {
	return func(e *Endpoint) {
		if log != nil {
			e.log = log
		}
	}
}

// New builds an Endpoint from cfg. It performs no network I/O: the relay
// connection is deferred to Connect and the inbound listener is bound by
// Listen.
func New(cfg *p2p.Config, opts ...Option) (*Endpoint, error) {
	e := &Endpoint{log: slog.Default()}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	h, err := host.New(cfg, host.WithLogger(e.log))
	if err != nil {
		return nil, err
	}
	e.h = h
	return e, nil
}

// Attach registers a transport to be closed with the endpoint. Transports call
// it from their constructor; an embedder does not need it. It fails with
// net.ErrClosed on an endpoint that is already closed, so a transport cannot be
// built against a dead endpoint (its listener would never be closed).
func (e *Endpoint) Attach(t Transport) error {
	if t == nil {
		return nil
	}
	if e.h.Closed() {
		return net.ErrClosed
	}
	e.mu.Lock()
	e.transports = append(e.transports, t)
	e.mu.Unlock()
	return nil
}

// Connect establishes the relay connection and applies the configured static
// forwards. It is idempotent. A failed relay connection is not fatal — the
// engine retries in the background and inbound tunnels stay unreachable until
// it connects — so a caller that only wants to serve may log it and continue;
// a failed forward registration wraps p2p.ErrForward and is fatal.
func (e *Endpoint) Connect() error {
	return e.h.Connect()
}

// Close shuts the endpoint down: its transports (listener included), the
// inbound listener, the static forward listeners, the relay engine and the
// pending-tunnel GC. Close is idempotent.
func (e *Endpoint) Close() error {
	e.mu.Lock()
	transports := e.transports
	e.mu.Unlock()
	// Transports first: their listeners must not outlive the endpoint they
	// serve. Closing is idempotent, so a transport the caller already closed is
	// unaffected.
	for _, t := range slices.Backward(transports) {
		_ = t.Close()
	}
	return e.h.Close()
}

// PublicKey returns the endpoint's base64 relay public key, or "" in stub mode
// (no relay configured). This is the string a peer puts in its own
// configuration to reach this endpoint.
func (e *Endpoint) PublicKey() string {
	return e.h.PublicKey()
}

// AddForward binds a local endpoint and bridges every accepted connection to
// peer (relay mode only). listen is a local address, peerKey a base64 public
// key.
func (e *Endpoint) AddForward(listen, peerKey string) error {
	return e.h.AddForward(listen, peerKey)
}

// Dial opens a tunnel to peer and returns its local end. network selects the
// tunnel's semantics: "udp" (any udp variant) asks for a datagram tunnel, and
// anything else for a byte stream. peer is a base64 public key in relay mode, a
// host:port in stub mode.
//
// ctx only bounds the call itself; the returned conn is the cancellation
// handle — closing it tears the tunnel down.
func (e *Endpoint) Dial(ctx context.Context, network, peer string) (net.Conn, error) {
	return e.h.Dial(ctx, network, peer)
}

// Listen returns a listener over inbound peer tunnels. Each accepted conn's
// RemoteAddr() carries the peer's base64 public key, and its bytes are the
// peer's tunnel exactly as they arrived. It requires relay mode and is mutually
// exclusive with Config.Targets (which makes the endpoint bridge inbound
// tunnels internally instead). Calling it twice returns the same listener; call
// it before Connect so no inbound tunnel is missed.
func (e *Endpoint) Listen() (net.Listener, error) {
	return e.h.Listen()
}

// Status reports the endpoint's tunnel count and transport stats.
func (e *Endpoint) Status() p2p.Status {
	return e.h.Status()
}

// Host returns the internal host a transport serves. It is exported for the
// transports in this module: the returned type lives in p2p/internal/host, so
// outside the module it cannot be named. Its exported methods are still
// callable there (Go resolves the selector without naming the type) — a caller
// that reaches past this API is unsupported: the seam is not a stable contract
// and changes without notice.
func (e *Endpoint) Host() *host.Host {
	return e.h
}
