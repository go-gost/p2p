package host

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/go-gost/p2p"
)

// Host is the engine side of a p2p endpoint: the relay engine (when one is
// configured), the tunnel registry, the data planes, and the seam that the
// in-process API and the transports drive. It is internal to the module — a
// caller reaches it through endpoint.Endpoint or through a transport such as
// p2p/grpc, never directly.
type Host struct {
	cfg *p2p.Config
	log *slog.Logger

	engine *engine // nil = stub mode
	server *server

	mu     sync.Mutex
	closed bool

	// listenOnce/listener hold the inbound listener Listen hands the caller
	// (nil until Listen runs).
	listenOnce sync.Once
	listener   net.Listener

	prepareOnce sync.Once
	prepareErr  error
	closeOnce   sync.Once
}

// Option configures a Host.
type Option func(*Host)

// WithLogger sets the logger used by the host and its engine. Defaults to
// slog.Default().
func WithLogger(log *slog.Logger) Option {
	return func(h *Host) {
		if log != nil {
			h.log = log
		}
	}
}

// New builds a Host from cfg. It performs no network I/O: the DERP connection
// is deferred to Connect, and the inbound listener is bound by Listen.
func New(cfg *p2p.Config, opts ...Option) (*Host, error) {
	if cfg == nil {
		cfg = &p2p.Config{}
	}
	h := &Host{cfg: cfg, log: slog.Default()}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
	applyDefaults(cfg)

	if err := applyTimeouts(cfg.Timeouts); err != nil {
		return nil, err
	}

	if cfg.Derp != "" {
		priv, _, err := loadOrCreateKey(cfg.Key, cfg.KeyHex)
		if err != nil {
			return nil, err
		}
		h.engine = newEngine(cfg.Derp, "", priv, h.log)
		if err := h.engine.addTargets(cfg.TargetList()); err != nil {
			return nil, err
		}
		h.engine.direct = *cfg.Direct
		h.engine.stunAddr = cfg.Stun
		h.engine.tlsCfg = buildTLSConfig(*cfg.TLS.Secure, cfg.TLS.CAFile, h.log)
	}

	h.server = newServer(h.engine)
	h.server.log = h.log
	return h, nil
}

// Connect establishes the DERP engine connection and applies the configured
// static forwards. It is idempotent: only the first call performs work and its
// error is remembered.
//
// A failed DERP connection is not fatal — the engine retries in the background
// and inbound tunnels stay unreachable until it connects — so a caller that
// only wants to serve may log it and continue (cmd/p2p does). Callers that
// need strict startup return the error.
func (h *Host) Connect() error {
	h.prepareOnce.Do(func() {
		if h.engine != nil {
			if *h.cfg.Direct {
				// Probe once to gate direct; each punch round re-probes, so a
				// changed egress does not require a restart.
				h.engine.v6Available = v6Egress() != nil
			}
			h.prepareErr = h.engine.Connect()
		}
		for _, f := range h.cfg.Forwards {
			if err := h.server.addForwardAddr(f.Listen, f.Peer); err != nil {
				h.prepareErr = fmt.Errorf("%w: %w", p2p.ErrForward, err)
				return
			}
		}
	})
	return h.prepareErr
}

// PublicKey returns the host's base64 DERP public key, or "" in stub mode.
func (h *Host) PublicKey() string {
	if h.engine == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(h.engine.pub[:])
}

// AddForward binds a static endpoint and bridges it to peer (DERP mode only).
// listen is the local address, peerKey a base64 public key.
func (h *Host) AddForward(listen, peerKey string) error {
	return h.server.addForwardAddr(listen, peerKey)
}

// Warm connects to the peer's relay session and starts a hole punch for it,
// without opening a tunnel stream. It is for a caller that knows which peer it
// will talk to (an entrypoint's configured peer): the path is then being
// arranged — and visible in Status' PeerTransports — before the first stream
// needs it, instead of the punch starting only when traffic arrives.
//
// It returns as soon as the session and the punch are launched: the punch runs
// in the background and retries on its own. Warming a peer is idempotent, and
// in stub mode (no relay) it is a no-op.
func (h *Host) Warm(peerB64 string) error {
	if h.engine == nil {
		return nil // stub mode: peers are host:port, there is no relay session to warm
	}
	peer, err := parsePeerKey(peerB64)
	if err != nil {
		return err
	}
	return h.engine.warm(peer)
}

// Status reports transport stats and the live tunnel count.
func (h *Host) Status() p2p.Status {
	return h.server.status()
}

// Close shuts the host down: the inbound listener, the static forward
// listeners, the DERP engine, and the pending-tunnel GC. It is idempotent.
// A transport's own listener is the transport's to close, not the host's.
func (h *Host) Close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		ln := h.listener
		h.mu.Unlock()

		if ln != nil {
			ln.Close() // the inbound listener: Accept -> net.ErrClosed
		}
		h.server.close()
		if h.engine != nil {
			h.engine.Close()
		}
	})
	return nil
}

// Closed reports whether Close has run, so callers fail fast instead of
// binding against a stopped engine.
func (h *Host) Closed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

// errClosed is the error a seam call returns after Close: net.ErrClosed, so
// callers can match it the same way they match a closed socket.
var errClosed = net.ErrClosed

// contextErr keeps the ctx check of an allocating call in one place.
func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
