package host

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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

	// quicMaxInitialPacketSize is quic-go's maximum packet buffer size.
	// validateConfig clamps InitialPacketSize to this value in place; applying
	// the same clamp here keeps the resolved config equal to what the
	// handshake actually uses.
	quicMaxInitialPacketSize = 1452
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
	mu   sync.Mutex
	tr   *quic.Transport
	conn *quic.Conn
	ln   *quic.Listener
	// relay is the installed relay underlay. It is the inbound sink for
	// frameData payloads while the pair is alive, including during the
	// handshake before conn exists.
	relay  *relayQUICConn
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
//
// The config is cloned: quic-go's validateConfig mutates the struct it is given
// (clamping InitialPacketSize), so a caller-shared config would be written by
// every pair concurrently.
func newQUICPair(e *engine, peer derpclient.PublicKey, role quicRole, tlsCfg *tls.Config, qcfg *quic.Config, onStream func(net.Conn)) *quicPair {
	if qcfg != nil {
		qcfg = qcfg.Clone()
	}
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
	if !closed {
		// Install the inbound sink before the reader starts, so a handshake
		// packet that arrives immediately after addUnderlay is not dropped.
		if r, ok := pc.(*relayQUICConn); ok {
			p.relay = r
		}
	}
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

// deliverRelay hands one inbound DERP data payload to the relay underlay's
// batching decoder. It is called from the relay pump and never blocks: a full
// queue drops the payload and QUIC retransmits the packets it carried. It
// reports whether the payload was accepted.
func (p *quicPair) deliverRelay(pkt []byte) bool {
	p.mu.Lock()
	relay, closed := p.relay, p.closed
	p.mu.Unlock()
	if relay == nil || closed {
		return false
	}
	return relay.deliver(pkt)
}

// established reports whether the QUIC connection has completed its handshake.
func (p *quicPair) established() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn != nil && !p.closed
}

// establish creates the transport and performs the QUIC/TLS handshake. The
// client dials the synthetic relay address; the server listens and accepts.
// Both then run an accept loop, because either end may open tunnels.
//
// Transport.Dial (not DialEarly) and a nil TLS ClientSessionCache keep the
// connection out of 0-RTT: a replayed early-data flight would be accepted by
// the relay path before the peer's identity was pinned.
//
// A failed handshake tears down only the conn, listener and transport of that
// attempt. The pair's multiPathConn and lifetime stay intact, so the caller may
// retry establish on the same relay underlay (with a fresh transport).
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

	conn, ln, err := p.handshake(ctx, tr)

	p.mu.Lock()
	if err == nil && p.closed {
		err = errQUICPairClosed
	}
	if err == nil {
		p.conn = conn
	}
	p.mu.Unlock()

	if err == nil {
		go p.acceptStreams()
		return nil
	}

	// Discard this attempt's resources, not the pair. A half-built transport
	// owns goroutines and a listener, but the relay underlay must survive for a
	// retry.
	if conn != nil {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "pair closed")
	}
	if ln != nil {
		_ = ln.Close()
	}
	_ = tr.Close()

	p.mu.Lock()
	if p.tr == tr {
		p.tr = nil
	}
	if p.ln == ln {
		p.ln = nil
	}
	p.mu.Unlock()

	return fmt.Errorf("host: quic pair establish: %w", err)
}

// handshake performs the role-specific exchange. The server closes its
// listener as soon as the single connection is accepted: one Transport serves
// exactly one connection, and a zero-length CID cannot tell a second connection
// apart from the established one. Closing a listener does not affect
// connections it already accepted.
func (p *quicPair) handshake(ctx context.Context, tr *quic.Transport) (*quic.Conn, *quic.Listener, error) {
	if p.role == quicRoleClient {
		conn, err := tr.Dial(ctx, quicPathAddr{name: quicPathRelay}, p.tlsCfg, p.qcfg)
		return conn, nil, err
	}

	ln, err := tr.Listen(p.tlsCfg, p.qcfg)
	if err != nil {
		return nil, nil, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = ln.Close()
		return nil, ln, errQUICPairClosed
	}
	p.ln = ln
	p.mu.Unlock()

	conn, err := ln.Accept(ctx)
	_ = ln.Close()

	return conn, ln, err
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
	// quic-go clamps InitialPacketSize to its packet-buffer maximum in
	// validateConfig. Clamp to the same bound up front so the resolved config
	// reflects what the handshake uses (and can never overflow uint16).
	mtu := s.MTU
	if mtu > quicMaxInitialPacketSize {
		mtu = quicMaxInitialPacketSize
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
