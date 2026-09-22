package grpc

import (
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/endpoint"
	pb "github.com/go-gost/plugin/p2p/proto"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// defaultAddr is the control-plane listen address when WithAddr is not given:
// loopback, so the unauthenticated default cannot be reached off-host.
const defaultAddr = "127.0.0.1:8003"

// Server serves one endpoint over the p2p plugin protocol. It implements the
// protocol's three RPCs (OpenTunnel, Tunnel, Status) on top of the endpoint's
// seam; the endpoint's identity, engine and tunnels are shared with any other
// transport attached to it.
type Server struct {
	pb.UnimplementedP2PServer

	ep    *endpoint.Endpoint
	log   *slog.Logger
	addr  string
	token string

	mu     sync.Mutex
	ln     net.Listener
	gs     *ggrpc.Server
	closed bool
}

// Option configures a Server.
type Option func(*Server)

// WithAddr sets the control-plane listen address (default 127.0.0.1:8003).
func WithAddr(addr string) Option {
	return func(s *Server) {
		if addr != "" {
			s.addr = addr
		}
	}
}

// WithToken enables the control-plane token check: every RPC must present the
// token in the "token" metadata key. An empty token disables checking, which is
// only safe on a loopback address.
func WithToken(token string) Option {
	return func(s *Server) { s.token = token }
}

// WithLogger sets the logger used by the server. Defaults to slog.Default().
func WithLogger(log *slog.Logger) Option {
	return func(s *Server) {
		if log != nil {
			s.log = log
		}
	}
}

// New builds a Server that serves ep. It performs no network I/O: the listener
// is bound by Start or Serve.
func New(ep *endpoint.Endpoint, opts ...Option) (*Server, error) {
	if ep == nil {
		return nil, errors.New("p2p/grpc: nil endpoint")
	}
	s := &Server{ep: ep, log: slog.Default(), addr: defaultAddr}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if s.addr == "" {
		s.addr = defaultAddr
	}
	// The endpoint outlives its transports: closing it closes this one, so its
	// listener cannot be left bound to a dead endpoint. A closed endpoint
	// refuses the attachment instead.
	if err := ep.Attach(s); err != nil {
		return nil, err
	}
	return s, nil
}

// PublicKey returns the served endpoint's base64 relay public key.
func (s *Server) PublicKey() string {
	return s.ep.PublicKey()
}

// Start connects the endpoint and begins serving in the background, returning
// the resolved listen address (useful with ":0"). A relay connect failure is
// only logged — the engine retries — while a forward registration failure is
// returned.
func (s *Server) Start() (string, error) {
	if s.isClosed() {
		return "", net.ErrClosed
	}
	if err := s.connect(); err != nil {
		return "", err
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return "", err
	}
	s.recordListener(ln)
	go func() {
		err := s.serveOn(ln)
		// A listener closed under Serve is the normal shutdown path, not an
		// error to report.
		if err != nil && !errors.Is(err, ggrpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
			s.log.Error("serve", "error", err)
		}
	}()
	return ln.Addr().String(), nil
}

// Serve connects the endpoint and blocks, serving on ln. Forward registration
// failures are returned; a relay connect failure is only logged.
func (s *Server) Serve(ln net.Listener) error {
	if s.isClosed() {
		return net.ErrClosed
	}
	if err := s.connect(); err != nil {
		return err
	}
	s.recordListener(ln)
	return s.serveOn(ln)
}

// Addr returns the resolved listen address, or "" before Start/Serve.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Close stops this server's listener and gRPC server. It does not touch the
// endpoint: a shared endpoint outlives the transports attached to it.
func (s *Server) Close() error {
	s.mu.Lock()
	gs, ln := s.gs, s.ln
	s.closed = true
	s.mu.Unlock()

	if gs != nil {
		gs.Stop()
	}
	if ln != nil {
		ln.Close()
	}
	return nil
}

func (s *Server) recordListener(ln net.Listener) {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
}

func (s *Server) serveOn(ln net.Listener) error {
	gs := ggrpc.NewServer(
		ggrpc.UnaryInterceptor(authInterceptor(s.token)),
		ggrpc.StreamInterceptor(streamAuthInterceptor(s.token)),
	)
	pb.RegisterP2PServer(gs, s)
	// Reflection lets an operator query Status with grpcurl without shipping
	// the .proto. With a token set it also needs -H 'token: ...'.
	reflection.Register(gs)
	s.mu.Lock()
	s.gs = gs
	s.mu.Unlock()
	s.log.Info("p2p listening", "addr", ln.Addr().String(), "auth", s.token != "")
	return gs.Serve(ln)
}

// connect connects the endpoint, tolerating a relay connect failure (the engine
// retries in the background) and returning a forward registration failure.
func (s *Server) connect() error {
	err := s.ep.Connect()
	if err == nil {
		return nil
	}
	if errors.Is(err, p2p.ErrForward) {
		// A configuration error: serving without the forward would hide it.
		return err
	}
	s.log.Warn("derp connect", "error", err)
	return nil
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
