package host

import (
	"errors"
	"net"
	"net/netip"
	"os"
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
}

var _ net.PacketConn = (*directPacketConn)(nil)

func newDirectPacketConn(u *directUnderlay) *directPacketConn {
	return &directPacketConn{u: u, peer: net.UDPAddrFromAddrPort(u.peer)}
}

// ReadFrom returns the next peer datagram. The underlay already filters foreign
// sources and consumes seed magic; this only maps the peer onto a net.Addr and
// swallows the periodic read deadline. Close surfaces as io.EOF.
func (c *directPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, err := c.u.readFrom(p)
		if err == nil {
			return n, c.peer, nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		return 0, nil, err
	}
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

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = u.close()
		return errQUICPairClosed
	}
	if p.directSock == sock {
		// Abandoning u is safe: it owns no goroutine until installed, and the
		// socket belongs to the underlay that is already live.
		return nil
	}
	p.directSock = sock
	p.mp.addUnderlay(quicUnderlay{
		name: quicPathDirect,
		addr: quicPathAddr{name: quicPathDirect, addr: peerAddr},
		pc:   newDirectPacketConn(u),
	})
	if p.role == quicRoleClient {
		p.mp.setPreferred(quicPathDirect)
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
	if sock == nil {
		return
	}

	p.mu.Lock()
	if p.directSock != sock {
		p.mu.Unlock()
		return
	}
	p.directSock = nil
	if p.role == quicRoleClient && p.mp.preferredPath() == quicPathDirect {
		p.mp.setPreferred(quicPathRelay)
	}
	p.mp.removeUnderlay(quicPathDirect)
	p.mu.Unlock()

	// removeUnderlay already closed the packet conn, which closes the socket;
	// this is the idempotent belt-and-braces close for a socket that had not
	// been installed yet.
	_ = sock.Close()
}
