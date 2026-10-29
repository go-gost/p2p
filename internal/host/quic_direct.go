package host

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// directPacketConn adapts a directUnderlay to net.PacketConn for the QUIC
// multi-path conn. Unlike the KCP pair, which reads the underlay's idle tick
// directly to run its watchdog, quic-go treats any ReadFrom error as fatal, so
// this view absorbs os.ErrDeadlineExceeded and keeps waiting.
type directPacketConn struct {
	u *directUnderlay
	// peer is cached because the underlay's peer address is fixed at
	// construction and ReadFrom is on the QUIC packet hot path.
	peer *net.UDPAddr

	// onIdle is the pair's heartbeat watchdog callback. It fires once when the
	// path has been silent (no data and no answered heartbeat) past
	// directUnderlayIdle, which is how a QUIC direct path is retired without
	// waiting for quic-go's connection-level idle timeout.
	onIdle func(*directUnderlay)
	// lastSent and lastRecv are UnixNano stamps for the heartbeat cadence and
	// the silence window. The read loop is their only writer; atomics keep a
	// status or shutdown read off the QUIC read path.
	lastSent atomic.Int64
	lastRecv atomic.Int64
	idleOnce sync.Once
}

var _ net.PacketConn = (*directPacketConn)(nil)

func newDirectPacketConn(u *directUnderlay) *directPacketConn {
	c := &directPacketConn{u: u, peer: net.UDPAddrFromAddrPort(u.peer)}
	c.lastRecv.Store(time.Now().UnixNano())
	return c
}

// ReadFrom returns the next peer datagram. The underlay already filters foreign
// sources and consumes seed magic; this only maps the peer onto a net.Addr and
// swallows the periodic read deadline. Close surfaces as io.EOF.
//
// The deadline ticks also drive the direct heartbeat watchdog: while the path
// is silent this side sends a heartbeat (at directHeartbeatInterval) and judges
// the path dead (past directUnderlayIdle) when neither data nor an answered
// heartbeat has arrived. The watchdog is confined to this read loop, so
// removing the underlay ends it; there is no separate goroutine to leak.
func (c *directPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, err := c.u.readFrom(p)
		if err == nil {
			c.lastRecv.Store(time.Now().UnixNano())
			return n, c.peer, nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if c.heartbeatTick() {
				return 0, nil, net.ErrClosed
			}
			continue
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			// A local read failure is a dead path, not a temporary one. Hand
			// it to the same watchdog retirement so directConn stops reporting
			// a direct path nobody can read; the QUIC connection migrates to
			// the relay on its next write.
			_ = c.fireIdle()
		}
		return 0, nil, err
	}
}

// heartbeatTick sends one heartbeat when the interval has elapsed and reports
// whether the path is dead: no inbound data and no answered heartbeat within
// directUnderlayIdle. An underlay without a heartbeat token is judged on data
// silence alone, matching the KCP watchdog's fallback.
func (c *directPacketConn) heartbeatTick() bool {
	now := time.Now()
	if last := c.lastSent.Load(); last == 0 ||
		now.Sub(time.Unix(0, last)) >= time.Duration(directHeartbeatInterval.Load()) {
		c.lastSent.Store(now.UnixNano())
		c.u.sendHeartbeat()
	}

	idle := time.Duration(directUnderlayIdle.Load())
	if now.Sub(time.Unix(0, c.lastRecv.Load())) < idle {
		return false
	}
	if now.Sub(time.Unix(0, c.u.lastHbRecv.Load())) < idle {
		return false
	}
	return c.fireIdle()
}

// fireIdle dispatches the watchdog callback at most once per underlay and
// reports whether it did. A false return means there is no callback to notify
// (a bare packet conn in a unit test).
func (c *directPacketConn) fireIdle() bool {
	if c.onIdle == nil {
		return false
	}
	c.idleOnce.Do(func() { c.onIdle(c.u) })
	return true
}

// WriteTo sends to the punched peer; the destination is part of the underlay,
// not of the QUIC path address.
func (c *directPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.u.writeTo(p)
}

func (c *directPacketConn) LocalAddr() net.Addr { return c.u.sock.LocalAddr() }

func (c *directPacketConn) RemoteAddr() net.Addr { return c.peer }

// SetReadDeadline is a no-op: directUnderlay.readFrom owns the socket's read
// deadline (it re-arms its 1s idle tick on every call) and ReadFrom absorbs the
// resulting timeout, so a caller-visible read deadline cannot be honored here.
func (c *directPacketConn) SetReadDeadline(time.Time) error { return nil }

func (c *directPacketConn) SetDeadline(t time.Time) error { return c.SetWriteDeadline(t) }

// SetWriteDeadline still reaches the socket: a write timeout is meaningful for
// a full UDP send buffer and does not interact with the read cadence.
func (c *directPacketConn) SetWriteDeadline(t time.Time) error {
	return c.u.sock.SetWriteDeadline(t)
}

func (c *directPacketConn) Close() error { return c.u.close() }

// addDirect installs a punched raw-UDP socket as the direct underlay. The
// client prefers it immediately, which is what makes QUIC migrate; the server
// follows the source address it observes. The socket is owned by the pair from
// here on: removeDirect or close shuts it down.
//
// Call it only after the pair is established. The client starts preferring
// direct as soon as this returns, so the peer's receiving side must already be
// installed, or early datagrams are lost until QUIC retransmits them.
//
// Re-adding the socket that is already installed is a no-op: the installed
// underlay keeps its original peer and token, and the socket stays open.
//
// p.mu is held across the underlay swap so addDirect is atomic with respect to
// removeDirect. Lock order is p.mu -> multiPathConn.mu; nothing takes them in
// the opposite order.
func (p *quicPair) addDirect(sock *net.UDPConn, peerAddr netip.AddrPort, token [seedTokenLen]byte) error {
	if sock == nil {
		return errQUICUnderlayNil
	}
	u := newDirectUnderlayToken(sock, peerAddr, token)
	from := p.pathName()

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = u.close()
		return errQUICPairClosed
	}
	if p.directSock == sock {
		// Abandoning u is safe: it owns no goroutine until installed, and the
		// socket belongs to the underlay that is already live.
		p.mu.Unlock()
		return nil
	}
	p.directSock = sock
	p.directU = u
	dpc := newDirectPacketConn(u)
	dpc.onIdle = p.directHeartbeatDead
	p.mp.addUnderlay(quicUnderlay{
		name: quicPathDirect,
		addr: quicPathAddr{name: quicPathDirect, addr: peerAddr},
		pc:   dpc,
	})
	if p.role == quicRoleClient {
		p.mp.setPreferred(quicPathDirect)
	}
	p.mu.Unlock()

	p.logUnderlay(quicPathDirect, "installed", "punch")
	p.logPathChange(from, p.pathName(), "direct-installed")
	// A first install (or a re-install after a fallback) is a relay->direct
	// flip. Replacing a direct underlay with a fresh one is not a migration:
	// the pair never left the direct path.
	if from != quicPathDirect {
		p.migrations.Add(1)
	}
	return nil
}

// removeDirect retires the direct underlay for sock. It deliberately checks the
// recorded socket first: a delayed retire of an old re-punch must not tear down
// a newer underlay. The client falls back to relay, which QUIC migrates back to
// on its next write.
//
// The identity check, the preferred switch and the underlay removal all happen
// under p.mu, the same lock addDirect holds across installation. A retire that
// loses the race therefore returns without touching the fresh underlay; it
// cannot clear directSock, switch to relay, and remove the new underlay
// afterwards.
func (p *quicPair) removeDirect(sock *net.UDPConn) {
	p.removeDirectReason(sock, "retired")
}

// removeDirectReason is removeDirect with the reason named for the quic
// underlay event: "retired" for an engine-driven retire, "heartbeat" for the
// direct watchdog. It is the same identity-checked teardown either way. It
// reports whether this call actually retired the installed underlay, so a
// caller counting an idle eviction does not count a stale heartbeat for an
// underlay a newer punch already replaced.
func (p *quicPair) removeDirectReason(sock *net.UDPConn, reason string) bool {
	if sock == nil {
		return false
	}
	from := p.pathName()

	p.mu.Lock()
	if p.directSock != sock {
		p.mu.Unlock()
		return false
	}
	p.directSock = nil
	p.directU = nil
	if p.role == quicRoleClient && p.mp.preferredPath() == quicPathDirect {
		p.mp.setPreferred(quicPathRelay)
	}
	p.mp.removeUnderlay(quicPathDirect)
	p.mu.Unlock()

	// removeUnderlay already closed the packet conn, which closes the socket;
	// this is the idempotent belt-and-braces close for a socket that had not
	// been installed yet.
	_ = sock.Close()
	p.logUnderlay(quicPathDirect, "retired", reason)
	p.logPathChange(from, p.pathName(), reason)
	// The pair was on the direct path when it retired: that is a direct->relay
	// fallback even on the server side, whose pathName may not observe the
	// peer's migration until the next datagram arrives.
	if from == quicPathDirect {
		p.fallbacks.Add(1)
	}
	return true
}

// hasDirect reports whether a direct underlay is installed on the pair. It is
// the relay-loss decision: a pair with a direct path keeps its connection,
// while a relay-only pair has no path left and must be rebuilt.
func (p *quicPair) hasDirect() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.directSock != nil && !p.closed
}

// directHeartbeatDead is the QUIC direct underlay's idle watchdog. The
// packet-conn read loop has already proven the path silent, so detach it,
// prefer the relay on the client, and hand the retirement to the engine so the
// punch state is marked down and the existing re-punch backoff runs. The QUIC
// connection and every stream on it stay alive and migrate to the relay.
func (p *quicPair) directHeartbeatDead(u *directUnderlay) {
	if u == nil {
		return
	}
	if !p.removeDirectReason(u.sock, "heartbeat") {
		return // a newer underlay replaced it: not this heartbeat's to retire
	}
	// The idle eviction is what schedules the re-punch (dc.underlayDead
	// below). Count it so Status can tell "idle and recovering" from
	// "flapping" without reading logs.
	p.directIdleEvictions.Add(1)
	p.repunchAfterIdle.Add(1)
	if p.e != nil {
		p.e.quicDirectDead(p.peer, u)
	}
}
