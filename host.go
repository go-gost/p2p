package p2p

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// defaultAddr is the gRPC control-plane listen address when Config.Addr is
// empty: loopback, so the unauthenticated default cannot be reached off-host.
const defaultAddr = "127.0.0.1:8003"

// Host is a p2p endpoint. It owns the DERP engine (when a relay URL is
// configured), the gRPC control plane, and the tunnel bookkeeping. It can run
// standalone as the CLI does (Start + Close) or be embedded in-process
// (Connect + Provider).
type Host struct {
	cfg *Config
	log *slog.Logger

	engine *engine // nil = stub mode
	server *server

	mu     sync.Mutex
	ln     net.Listener
	grpc   *grpc.Server
	addr   string
	closed bool

	prepareOnce sync.Once
	prepareErr  error
	// forwardErr is set when a static forward fails to register. That is a
	// configuration error (bad listen address, no --derp, port in use), unlike
	// a transient DERP connect failure, so Start/Serve return it instead of
	// serving without the forward.
	forwardErr error
	closeOnce  sync.Once
}

// Option configures a Host.
type Option func(*Host)

// WithLogger sets the logger used by the host, its engine, and its server.
// Defaults to slog.Default().
func WithLogger(log *slog.Logger) Option {
	return func(h *Host) {
		if log != nil {
			h.log = log
		}
	}
}

// New builds a Host from cfg. It performs no network I/O: the DERP connection
// is deferred to Connect, and all listeners are bound by Connect/Start.
func New(cfg *Config, opts ...Option) (*Host, error) {
	if cfg == nil {
		cfg = &Config{}
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

// applyDefaults fills in place the Config defaults the CLI and the library
// share, so New behaves identically whether cfg came from a YAML file, flags,
// or a caller. It mutates the caller's *Config (Addr, TLS, Direct).
func applyDefaults(cfg *Config) {
	if cfg.Addr == "" {
		cfg.Addr = defaultAddr
	}
	if cfg.TLS == nil {
		cfg.TLS = &TLSConfig{}
	}
	if cfg.TLS.Secure == nil {
		def := true
		cfg.TLS.Secure = &def
	}
	if cfg.Direct == nil {
		def := true
		cfg.Direct = &def
	}
}

// Connect establishes the DERP engine connection and applies the configured
// static forwards. It is idempotent: only the first call performs work and its
// error is remembered.
//
// A failed DERP connection is not fatal — the engine retries in the background
// and inbound tunnels stay unreachable until it connects — so Start logs it and
// continues. Embedding callers that need strict startup can check the error.
// A failed forward registration is a configuration error, not a transient one:
// Start/Serve return it (see forwardErr) rather than serve without the forward.
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
				h.forwardErr = err
				h.prepareErr = err
				return
			}
		}
	})
	return h.prepareErr
}

// Start connects the engine and begins serving the gRPC control plane on
// Config.Addr in the background. It returns the resolved listen address, which
// is useful with ":0". A DERP connect failure is only logged (the engine
// retries); a forward registration failure is returned.
func (h *Host) Start() (string, error) {
	if h.isClosed() {
		return "", net.ErrClosed
	}
	if err := h.Connect(); err != nil {
		if h.forwardErr != nil {
			return "", err
		}
		h.log.Warn("derp connect", "error", err)
	}
	ln, err := net.Listen("tcp", h.cfg.Addr)
	if err != nil {
		return "", err
	}
	h.recordListener(ln)
	go func() {
		if err := h.serveOn(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			h.log.Error("serve", "error", err)
		}
	}()
	return ln.Addr().String(), nil
}

// Serve connects the engine and blocks, serving the gRPC control plane on ln.
// Forward registration failures are returned; a DERP connect failure is only
// logged (the engine retries).
func (h *Host) Serve(ln net.Listener) error {
	if h.isClosed() {
		return net.ErrClosed
	}
	if err := h.Connect(); err != nil {
		if h.forwardErr != nil {
			return err
		}
		h.log.Warn("derp connect", "error", err)
	}
	h.recordListener(ln)
	return h.serveOn(ln)
}

func (h *Host) recordListener(ln net.Listener) {
	h.mu.Lock()
	h.ln = ln
	h.addr = ln.Addr().String()
	h.mu.Unlock()
}

func (h *Host) serveOn(ln net.Listener) error {
	gs := grpc.NewServer(
		grpc.UnaryInterceptor(authInterceptor(h.cfg.Token)),
		grpc.StreamInterceptor(streamAuthInterceptor(h.cfg.Token)),
	)
	proto.RegisterP2PServer(gs, h.server)
	// Reflection lets an operator query Status with grpcurl without shipping
	// the .proto. With Token set it also needs -H 'token: ...'.
	reflection.Register(gs)
	h.mu.Lock()
	h.grpc = gs
	h.mu.Unlock()
	h.log.Info("p2p listening", "addr", ln.Addr().String(),
		"auth", h.cfg.Token != "", "derp", h.cfg.Derp != "")
	return gs.Serve(ln)
}

// Addr returns the resolved gRPC listen address, or "" before Start/Serve.
func (h *Host) Addr() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.addr
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

// Status reports transport stats and the live tunnel count.
func (h *Host) Status(ctx context.Context) (*proto.StatusReply, error) {
	return h.server.Status(ctx, &proto.StatusRequest{})
}

// Close shuts the host down: the gRPC server and listener, the static forward
// listeners, the DERP engine, and the pending-tunnel GC. It is idempotent.
func (h *Host) Close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		gs, ln := h.grpc, h.ln
		h.closed = true
		h.mu.Unlock()

		if gs != nil {
			gs.Stop()
		}
		if ln != nil {
			ln.Close()
		}
		h.server.close()
		if h.engine != nil {
			h.engine.Close()
		}
	})
	return nil
}

// isClosed reports whether Close has run, so Start/Serve and in-process tunnel
// opens fail fast instead of binding against a stopped engine.
func (h *Host) isClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}
