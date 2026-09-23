package host

import (
	"log/slog"
	"net"
	"sync"
)

// Inbound listener: Tunnel.Listen hands the host's inbound peer streams to an
// in-process embedder as net.Conns instead of letting the host bridge them to
// a --target (the CLI shape). Streams arrive from the engine's per-peer accept
// loops (direct.go serveInbound) and are queued here; the listener's Accept
// drains the queue, stamping each conn with synthetic p2p addresses whose
// String() is the peer's base64 public key.

// inboundBacklog bounds how many accepted-but-undelivered inbound streams the
// host holds; a var so tests can shrink it. Overflow is dropped and logged.
var inboundBacklog = 64

// peerAddr is the synthetic address of a p2p peer: Network "p2p", String the
// base64 public key.
type peerAddr struct{ key string }

func (a peerAddr) Network() string { return "p2p" }
func (a peerAddr) String() string  { return a.key }

// inboundStream is one peer tunnel stream waiting for the embedder.
type inboundStream struct {
	conn      net.Conn
	peer      string
	transport string
	peerAddr  string
	datagram  bool // a udp tunnel: the conn is a net.PacketConn (frames parsed)
}

// inboundQueue carries inbound streams from the engine to Listen's listener.
type inboundQueue struct {
	ch     chan inboundStream
	closed chan struct{}
	once   sync.Once
}

func newInboundQueue() *inboundQueue {
	return &inboundQueue{
		ch:     make(chan inboundStream, inboundBacklog),
		closed: make(chan struct{}),
	}
}

// deliver hands one inbound stream to the embedder; when the backlog is full
// the stream is closed and dropped (lossy, documented).
func (q *inboundQueue) deliver(conn net.Conn, peer, transport, peerAddr string, log *slog.Logger) {
	q.enqueue(inboundStream{conn: conn, peer: peer, transport: transport, peerAddr: peerAddr}, log)
}

// deliverDatagram hands one inbound datagram stream to the embedder: the conn is
// wrapped so Read returns one datagram (the 2-byte framing is parsed here, by
// its owner) and the conn satisfies net.PacketConn, the shape a consumer tells
// a udp tunnel by. The embedder never sees the framing.
func (q *inboundQueue) deliverDatagram(conn net.Conn, peer, transport, peerAddr string, log *slog.Logger) {
	q.enqueue(inboundStream{
		conn:      newFrameConn(conn),
		peer:      peer,
		transport: transport,
		peerAddr:  peerAddr,
		datagram:  true,
	}, log)
}

func (q *inboundQueue) enqueue(s inboundStream, log *slog.Logger) {
	select {
	case q.ch <- s:
	case <-q.closed:
		s.conn.Close()
	default:
		log.Warn("inbound stream dropped (backlog full)", "peer", s.peer)
		s.conn.Close()
	}
}

func (q *inboundQueue) close() {
	q.once.Do(func() {
		close(q.closed)
		for {
			select {
			case s := <-q.ch:
				s.conn.Close()
			default:
				return
			}
		}
	})
}

// inboundListener is the net.Listener returned by Tunnel.Listen.
type inboundListener struct {
	q    *inboundQueue
	host string // the host's own base64 key, for LocalAddr
}

func (l *inboundListener) Accept() (net.Conn, error) {
	select {
	case s := <-l.q.ch:
		conn := &inboundConn{Conn: s.conn, local: peerAddr{key: l.host}, remote: peerAddr{key: s.peer}}
		if s.datagram {
			return &inboundDatagramConn{inboundConn: conn}, nil
		}
		return conn, nil
	case <-l.q.closed:
		return nil, net.ErrClosed
	}
}

func (l *inboundListener) Close() error { l.q.close(); return nil }
func (l *inboundListener) Addr() net.Addr {
	return peerAddr{key: l.host}
}

// inboundConn overrides the addresses: the transport conn's own addrs are
// smux-internal and meaningless to the embedder.
type inboundConn struct {
	net.Conn
	local, remote net.Addr
}

func (c *inboundConn) LocalAddr() net.Addr  { return c.local }
func (c *inboundConn) RemoteAddr() net.Addr { return c.remote }

// inboundDatagramConn is inboundConn's datagram twin: it satisfies
// net.PacketConn, which is how a consumer (x's local handler) tells a udp
// tunnel stream from a tcp one. Read returns one datagram, Write emits one.
type inboundDatagramConn struct {
	*inboundConn
}

func (c *inboundDatagramConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.remote, err
}

func (c *inboundDatagramConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }
