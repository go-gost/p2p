package host

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"

	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/quic-go/quic-go"
)

// Incoming stream limits. Tunnels are bidirectional streams, so unidirectional
// streams are disabled (-1 is quic-go's "advertise zero"): nothing in the data
// plane ever opens one, and accepting them would only widen the surface.
const (
	quicMaxIncomingStreams    = 1024
	quicMaxIncomingUniStreams = -1
)

var (
	errQUICPairClosed      = errors.New("host: quic pair closed")
	errQUICPairEstablished = errors.New("host: quic pair already established")
	errQUICPairNoConn      = errors.New("host: quic pair is not established")
	errQUICUnderlayNil     = errors.New("host: quic underlay is nil")
)

// quicPair is one QUIC connection to one peer. The connection rides a
// multiPathConn, which starts with the relay underlay and may gain a direct
// one later; QUIC connection migration moves every stream together when the
// preferred path changes. One Transport serves exactly one connection because
// zero-length connection IDs cannot tell connections apart.
type quicPair struct {
	e        *engine
	peer     derpclient.PublicKey
	role     quicRole
	mp       *multiPathConn
	tlsCfg   *tls.Config
	qcfg     *quic.Config
	onStream func(net.Conn)

	// ctx is the pair's lifetime. close cancels it, which unblocks a pending
	// AcceptStream or OpenStreamSync without waiting for the connection close
	// to propagate.
	ctx    context.Context
	cancel context.CancelFunc

	// mu guards the establishment state and conn, which status readers and
	// close can reach from other goroutines. The transport callbacks must never
	// hold it.
	mu     sync.Mutex
	tr     *quic.Transport
	conn   *quic.Conn
	ln     *quic.Listener
	closed bool

	closeOnce sync.Once
	// acceptDone is closed when the accept loop returns, so a test (or a
	// future engine teardown) can prove a close did not leave AcceptStream
	// parked. It is only closed once acceptStreams starts.
	acceptDone chan struct{}
}

// quicStreamConn adapts a QUIC stream to net.Conn. The embedded stream
// provides Read, Write and the deadline methods.
type quicStreamConn struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

var _ net.Conn = (*quicStreamConn)(nil)

// newQUICPair builds the per-peer transport state. No packets flow until the
// caller installs an underlay and establish succeeds.
func newQUICPair(e *engine, peer derpclient.PublicKey, role quicRole, tlsCfg *tls.Config, qcfg *quic.Config, onStream func(net.Conn)) *quicPair {
	ctx, cancel := context.WithCancel(context.Background())
	return &quicPair{
		e:          e,
		peer:       peer,
		role:       role,
		mp:         newMultiPathConn(role),
		tlsCfg:     tlsCfg,
		qcfg:       qcfg,
		onStream:   onStream,
		ctx:        ctx,
		cancel:     cancel,
		acceptDone: make(chan struct{}),
	}
}

// addRelayUnderlay installs the relay path. The relay address is synthetic and
// shared by both ends: QUIC uses it as the path identity, not as a routable
// destination.
func (p *quicPair) addRelayUnderlay(pc net.PacketConn) error {
	if pc == nil {
		return errQUICUnderlayNil
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		_ = pc.Close()
		return errQUICPairClosed
	}
	p.mp.addUnderlay(quicUnderlay{
		name: quicPathRelay,
		addr: quicPathAddr{name: quicPathRelay},
		pc:   pc,
	})
	return nil
}

// establish creates the transport and performs the QUIC/TLS handshake. The
// client dials the synthetic relay address; the server listens and accepts.
// Both then run an accept loop, because either end may open tunnels.
//
// Transport.Dial (not DialEarly) and a nil TLS ClientSessionCache keep the
// connection out of 0-RTT: a replayed early-data flight would be accepted by
// the relay path before the peer's identity was pinned.
//
// A failed establish closes the whole pair: a half-built transport owns
// goroutines and a partially installed underlay, and the caller must retry
// with a fresh pair rather than reuse this one.
func (p *quicPair) establish(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errQUICPairClosed
	}
	if p.tr != nil {
		p.mu.Unlock()
		return errQUICPairEstablished
	}
	tr := &quic.Transport{
		Conn:                  p.mp,
		ConnectionIDGenerator: zeroCIDGenerator{},
	}
	p.tr = tr
	p.mu.Unlock()

	ctx, cancel := quicPairContext(ctx, p.ctx)
	defer cancel()

	var (
		conn *quic.Conn
		ln   *quic.Listener
		err  error
	)
	if p.role == quicRoleClient {
		conn, err = tr.Dial(ctx, quicPathAddr{name: quicPathRelay}, p.tlsCfg, p.qcfg)
	} else {
		ln, err = tr.Listen(p.tlsCfg, p.qcfg)
		if err == nil {
			p.mu.Lock()
			if p.closed {
				err = errQUICPairClosed
			} else {
				p.ln = ln
			}
			p.mu.Unlock()
			if err == nil {
				conn, err = ln.Accept(ctx)
			}
		}
	}
	if err != nil {
		p.close()
		return fmt.Errorf("host: quic pair establish: %w", err)
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "pair closed")
		p.close()
		return errQUICPairClosed
	}
	p.conn = conn
	p.mu.Unlock()

	go p.acceptStreams()
	return nil
}

// openStream opens one bidirectional stream, bounded by ctx. A stream and its
// addresses are snapshots: QUIC may migrate the connection underneath it, but
// the stream itself survives.
func (p *quicPair) openStream(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	conn := p.conn
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, errQUICPairClosed
	}
	if conn == nil {
		return nil, errQUICPairNoConn
	}

	ctx, cancel := quicPairContext(ctx, p.ctx)
	defer cancel()
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("host: quic open stream: %w", err)
	}
	return &quicStreamConn{
		Stream: s,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
	}, nil
}

// acceptStreams hands every inbound stream to onStream. It exits on the first
// accept error: quic-go reports one only when the connection or the pair's
// lifetime context is done, and neither can recover.
func (p *quicPair) acceptStreams() {
	defer close(p.acceptDone)

	p.mu.Lock()
	conn := p.conn
	p.mu.Unlock()
	if conn == nil {
		return
	}

	for {
		s, err := conn.AcceptStream(p.ctx)
		if err != nil {
			return
		}
		c := &quicStreamConn{
			Stream: s,
			local:  conn.LocalAddr(),
			remote: conn.RemoteAddr(),
		}
		if p.onStream == nil {
			_ = c.Close()
			continue
		}
		// A stream handler reads and bridges for the stream's whole lifetime;
		// running it on the accept goroutine would let the first silent stream
		// stall every later tunnel.
		go p.onStream(c)
	}
}

// close tears the pair down exactly once. Connections close first so the peer
// sees a clean CONNECTION_CLOSE, then the transport, then the packet path; the
// transport's reader runs on the multiPathConn and is unblocked by the
// transport's own read-deadline wakeup.
func (p *quicPair) close() {
	p.closeOnce.Do(func() {
		p.cancel()

		p.mu.Lock()
		p.closed = true
		conn, ln, tr := p.conn, p.ln, p.tr
		p.mu.Unlock()

		if conn != nil {
			_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "pair closed")
		}
		if ln != nil {
			_ = ln.Close()
		}
		if tr != nil {
			_ = tr.Close()
		}
		_ = p.mp.Close()
	})
}

// pathName names the path the pair is currently using: the client's preferred
// underlay, or the server's most recently validated remote address. Both fall
// back to relay before the connection has migrated.
func (p *quicPair) pathName() string {
	if p.role == quicRoleClient {
		if name := p.mp.preferredPath(); name != "" {
			return name
		}
		return quicPathRelay
	}

	p.mu.Lock()
	conn := p.conn
	p.mu.Unlock()
	if conn != nil {
		if name := quicPathName(conn.RemoteAddr()); name != "" {
			return name
		}
	}
	return quicPathRelay
}

// quicConfigFromSettings maps the resolved host settings onto quic-go's
// config. Path MTU discovery stays off because the relay path's datagram size
// is not under this host's control.
func quicConfigFromSettings(s quicSettings) *quic.Config {
	// InitialPacketSize is a uint16; an absurd MTU must not wrap to a small
	// packet size. quic-go clamps the result to its own maximum.
	mtu := s.MTU
	if mtu > math.MaxUint16 {
		mtu = math.MaxUint16
	}
	return &quic.Config{
		HandshakeIdleTimeout:    s.HandshakeTimeout,
		MaxIdleTimeout:          s.Idle,
		KeepAlivePeriod:         s.KeepAlive,
		InitialPacketSize:       uint16(mtu),
		DisablePathMTUDiscovery: true,
		MaxIncomingStreams:      quicMaxIncomingStreams,
		MaxIncomingUniStreams:   quicMaxIncomingUniStreams,
		Allow0RTT:               false,
	}
}

// quicPairContext ties one operation to both its caller's context and the
// pair's lifetime, so close unblocks a handshake or stream open that a caller
// context alone would leave parked until its deadline.
func quicPairContext(parent, lifetime context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(lifetime, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }

// Close shuts both directions. Stream.Close alone only sends FIN; without
// CancelRead the peer's data would keep filling the receive window of a stream
// nobody reads anymore.
func (c *quicStreamConn) Close() error {
	c.CancelRead(0)
	return c.Stream.Close()
}
