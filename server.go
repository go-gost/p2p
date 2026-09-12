package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// server is the P2P service. OpenTunnel authorizes a tunnel and allocates its
// id; the tunnel's data travels on the Tunnel stream bound to that id (see
// stream.go) — there is no local endpoint.
//
// Two data-plane modes:
//   - stub mode (default): the peer end of a tunnel is the peer host:port
//     dialed directly. Only meaningful on loopback / trusted networks.
//   - DERP engine mode (engine != nil): the peer end is a mux stream to the
//     peer through the DERP relay; "peer" is the peer host's base64 public
//     key instead of a host:port.
//
// --forward static port forwards keep a local listener (startTunnel) and are
// the only tunnels with one.
//
// Trust boundary: the control channel is unauthenticated — any process that
// can reach the gRPC address can make this plugin dial arbitrary host:port
// (SSRF surface). Unlike other plugin hosts this one dials *out*, so bind the
// gRPC address to loopback (the default) unless authentication is added
// (--token). Cross-machine deployment additionally needs control TLS; the
// token travels over a plaintext channel today.
type server struct {
	proto.UnimplementedP2PServer
	engine  *Engine // DERP engine mode; nil = stub mode
	mu      sync.Mutex
	seq     atomic.Int64
	tunnels map[string]*tunnel
}

// pendingTTL bounds how long an OpenTunnel record may wait for its Tunnel
// stream before the GC reclaims it: a client can die between the two RPCs,
// and there is no CloseTunnel to clean up after it. gcInterval is the sweep
// cadence. Vars so tests can shorten them.
var (
	pendingTTL = 10 * time.Second
	gcInterval = 5 * time.Second
)

func newServer(engine *Engine) *server {
	s := &server{
		engine:  engine,
		tunnels: make(map[string]*tunnel),
	}
	go s.gcPending(gcInterval)
	return s
}

type tunnel struct {
	id     string
	target string   // far end as passed to OpenTunnel: peer host:port (stub) or public key (DERP)
	engine *Engine  // derp mode: stream source
	peer   string   // derp mode: peer public key (base64)
	ch     *channel // udp tunnels: the peer channel this tunnel holds a reference on
	ln     net.Listener

	// network, createdAt, attached describe stream-backed records; they are
	// guarded by the server lock (the GC reads them there).
	network   string
	createdAt time.Time
	attached  bool // the Tunnel handler has claimed the record

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// newTunnelID returns a cryptographically random tunnel id: it is the
// credential of the Tunnel stream, so it must be unguessable (the old
// guessable tunnel-%d scheme must not be reused for it).
func newTunnelID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read is documented to always succeed; a fallback here
		// would mint a predictable credential.
		panic(fmt.Sprintf("p2p: tunnel id: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// shortID is the id prefix used in logs; the full id is a credential and must
// never be logged.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// OpenTunnel authorizes a tunnel and allocates its id; the client presents
// the id as the "id" metadata key on the Tunnel stream. No endpoint is
// returned — the stream is the data plane. A record whose stream never
// arrives is reclaimed by the pending GC.
func (s *server) OpenTunnel(ctx context.Context, req *proto.OpenTunnelRequest) (*proto.OpenTunnelReply, error) {
	network := req.Network
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "udp" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid network %q", req.Network)
	}
	if network == "udp" && s.engine == nil {
		return nil, status.Errorf(codes.InvalidArgument, "udp tunnel requires derp mode (peer key)")
	}

	peer := req.Peer
	if s.engine != nil {
		// DERP mode: the peer is a public key; validate its shape now and
		// fail fast with a clear error.
		key, err := parsePeerKey(peer)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid peer %q: %v", peer, err)
		}
		if network == "udp" {
			// A datagram tunnel is one channel per peer, shared by every gost
			// dial to it: the channel pairs the peer edge with the latest
			// tunnel's local edge and outlives individual dials; the record's
			// release is what drops its reference.
			t := &tunnel{
				id:        newTunnelID(),
				target:    peer,
				peer:      peer,
				engine:    s.engine,
				network:   "udp",
				ch:        s.engine.openChannel(key),
				createdAt: time.Now(),
				conns:     make(map[net.Conn]struct{}),
			}
			s.mu.Lock()
			s.tunnels[t.id] = t
			s.mu.Unlock()
			return &proto.OpenTunnelReply{Ok: true, Id: t.id}, nil
		}
	} else {
		host, port, err := net.SplitHostPort(peer)
		if err != nil || host == "" || port == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid peer %q", req.Peer)
		}
	}

	t := &tunnel{
		id:        newTunnelID(),
		target:    peer,
		network:   network,
		createdAt: time.Now(),
		conns:     make(map[net.Conn]struct{}),
	}
	if s.engine != nil {
		t.engine = s.engine
		t.peer = peer
	}
	s.mu.Lock()
	s.tunnels[t.id] = t
	s.mu.Unlock()
	return &proto.OpenTunnelReply{Ok: true, Id: t.id}, nil
}

// gcPending reclaims records whose Tunnel stream never arrived — the only
// cleanup for an abandoned setup, now that CloseTunnel is gone; the other
// teardown path is the Tunnel handler returning.
func (s *server) gcPending(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		var stale []*tunnel
		s.mu.Lock()
		for id, tn := range s.tunnels {
			// Only stream-backed records are GC candidates: a --forward tunnel
			// has a listener and lives for the process's lifetime.
			if tn.ln == nil && !tn.attached && now.Sub(tn.createdAt) > pendingTTL {
				stale = append(stale, tn)
				delete(s.tunnels, id)
			}
		}
		s.mu.Unlock()
		for _, tn := range stale {
			slog.Info("pending tunnel reclaimed", "tunnel", shortID(tn.id), "ttl", pendingTTL.String())
			s.dropTunnel(tn)
		}
	}
}

// dropTunnel removes t from the registry and tears it down. A channel-holding
// record releases its channel reference — release is refcounted, so a channel
// shared with another live tunnel to the same peer survives; never teardown()
// a channel here. Everything else closes its listener (--forward only) and
// tracked connections.
//
// dropTunnel replaces CloseTunnel: it runs when a Tunnel handler returns
// (stream end IS the teardown) and from the pending GC.
func (s *server) dropTunnel(t *tunnel) {
	s.mu.Lock()
	if s.tunnels[t.id] == t {
		delete(s.tunnels, t.id)
	}
	s.mu.Unlock()

	if t.ch != nil {
		t.ch.release()
		return
	}
	t.close()
}

// startTunnel binds a listener on addr and registers a tunnel bridging to
// peer (a host:port in stub mode, a base64 public key in DERP mode). The
// returned tunnel is already serving. Only --forward uses this path.
func (s *server) startTunnel(addr, peer string) (*tunnel, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	t := &tunnel{
		id:        fmt.Sprintf("tunnel-%d", s.seq.Add(1)),
		target:    peer,
		network:   "tcp",
		createdAt: time.Now(),
		ln:        ln,
		conns:     make(map[net.Conn]struct{}),
	}
	if s.engine != nil {
		t.engine = s.engine
		t.peer = peer
	}
	s.mu.Lock()
	s.tunnels[t.id] = t
	s.mu.Unlock()
	go t.serve()
	return t, nil
}

// addForward binds a pre-configured endpoint and bridges it to peer. The spec
// is the --forward flag form "listen-addr=peer-key".
func (s *server) addForward(spec string) error {
	addr, key, ok := strings.Cut(spec, "=")
	if !ok || addr == "" || key == "" {
		return fmt.Errorf("want \"listen-addr=peer-key\", got %q", spec)
	}
	return s.addForwardAddr(addr, key)
}

// addForwardAddr binds a pre-configured endpoint and bridges it to peer. DERP
// mode only — a stub-mode host:port forward is just what gost's own
// port-forwarding already does.
func (s *server) addForwardAddr(addr, key string) error {
	if s.engine == nil {
		return errors.New("static port forward requires --derp (peer key)")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("invalid listen addr %q: %v", addr, err)
	}
	peer, err := parsePeerKey(key)
	if err != nil {
		return err
	}
	if _, err := s.startTunnel(addr, key); err != nil {
		return err
	}
	// Eagerly warm the direct path so the first connection doesn't pay the
	// punch latency. No-op when --stun is unset; a peer that isn't up yet just
	// backoff-retries like any failed punch.
	s.engine.maybeStartDirect(peer)
	return nil
}

func (s *server) Status(ctx context.Context, req *proto.StatusRequest) (*proto.StatusReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &proto.StatusReply{Tunnels: int32(len(s.tunnels))}, nil
}

// serve accepts connections until the tunnel is closed, bridging each one
// to the peer target.
func (t *tunnel) serve() {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return // listener closed
		}
		t.trackConn(conn)
		go t.bridge(conn)
	}
}

// openPeer connects the tunnel's far end: a mux stream to the peer through
// the relay (DERP engine mode) or a direct dial of the peer host:port (stub
// mode).
func (t *tunnel) openPeer() (net.Conn, error) {
	if t.engine != nil {
		return t.engine.OpenStream(t.peer)
	}
	return net.DialTimeout("tcp", t.target, 5*time.Second)
}

// bridge copies bytes in both directions between an accepted --forward
// connection and the tunnel's peer end.
func (t *tunnel) bridge(conn net.Conn) {
	up, err := t.openPeer()
	if err != nil {
		slog.Debug("bridge dial failed", "tunnel", t.id, "target", t.target, "error", err)
		conn.Close()
		return
	}
	t.pipe(conn, up, t.ln.Addr().String(), t.target)
}

// pipe copies bytes in both directions between conn (the local edge: an
// --forward connection or a Tunnel stream) and up (the peer end). When one
// direction ends, the destination is half-closed (CloseWrite) so the other
// side can still drain, falling back to a full close for conn types without
// CloseWrite (mux and stream-backed conns) — that matches the previous
// tunnelConn semantics, so a peer EOF truncates the reverse direction as it
// does today. Both ends are closed only after both directions are done.
// pipe logs each tunnel in gost style: "<src> <-> <dst>" on connect and
// ">-<" with the duration on disconnect.
func (t *tunnel) pipe(conn, up net.Conn, endpoint, target string) {
	defer t.untrackConn(conn)
	t.trackConn(up)
	defer func() {
		t.untrackConn(up)
		up.Close()
		conn.Close()
	}()

	transport := ""
	peerAddr := ""
	if tw, ok := up.(interface{ Transport() string }); ok {
		transport = tw.Transport()
	}
	if pa, ok := up.(interface{ PeerAddr() string }); ok {
		peerAddr = pa.PeerAddr()
	}
	attrs := []any{"peer", target, "endpoint", endpoint}
	if transport != "" {
		attrs = append(attrs, "transport", transport)
	}
	if peerAddr != "" {
		attrs = append(attrs, "peerAddr", peerAddr)
	}
	start := time.Now()
	slog.Info(fmt.Sprintf("%s <-> %s", endpoint, target), attrs...)
	defer func() {
		slog.Info(fmt.Sprintf("%s >-< %s", endpoint, target),
			append(append([]any{}, attrs...), "duration", time.Since(start).String())...)
	}()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, conn)
		halfCloseWrite(up)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, up)
		halfCloseWrite(conn)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// halfCloseWrite closes the write side of dst when the opposite direction
// has ended, so the remaining direction can still deliver data. Falls back
// to a full close when the connection type is not TCP.
func halfCloseWrite(dst net.Conn) {
	if tcp, ok := dst.(*net.TCPConn); ok {
		tcp.CloseWrite()
	} else {
		dst.Close()
	}
}

func (t *tunnel) trackConn(conn net.Conn) {
	t.mu.Lock()
	t.conns[conn] = struct{}{}
	t.mu.Unlock()
}

func (t *tunnel) untrackConn(conn net.Conn) {
	t.mu.Lock()
	delete(t.conns, conn)
	t.mu.Unlock()
}

// close stops the tunnel: the listener (--forward only; nil for stream
// records), then every tracked connection.
func (t *tunnel) close() {
	if t.ln != nil {
		t.ln.Close() // stops accept; no new conns
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for conn := range t.conns {
		conn.Close()
	}
}
