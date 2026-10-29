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
}

var _ net.PacketConn = (*directPacketConn)(nil)

// ReadFrom returns the next peer datagram. The underlay already filters foreign
// sources and consumes seed magic; this only maps the peer onto a net.Addr and
// swallows the periodic read deadline. Close surfaces as io.EOF.
func (c *directPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, err := c.u.readFrom(p)
		if err == nil {
			return n, net.UDPAddrFromAddrPort(c.u.peer), nil
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

func (c *directPacketConn) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.u.peer)
}

func (c *directPacketConn) SetDeadline(t time.Time) error {
	return c.u.sock.SetDeadline(t)
}

func (c *directPacketConn) SetReadDeadline(t time.Time) error {
	return c.u.sock.SetReadDeadline(t)
}

func (c *directPacketConn) SetWriteDeadline(t time.Time) error {
	return c.u.sock.SetWriteDeadline(t)
}

func (c *directPacketConn) Close() error { return c.u.close() }

// addDirect installs a punched raw-UDP socket as the direct underlay. The
// client prefers it immediately, which is what makes QUIC migrate; the server
// follows the source address it observes. The socket is owned by the pair from
// here on: removeDirect or close shuts it down.
func (p *quicPair) addDirect(sock *net.UDPConn, peerAddr netip.AddrPort, token [seedTokenLen]byte) error {
	if sock == nil {
		return errQUICUnderlayNil
	}
	u := newDirectUnderlayToken(sock, peerAddr, token)

	// Record the socket before installing it. A delayed retire from an older
	// punch then sees a mismatch and cannot remove the fresh underlay.
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = u.close()
		return errQUICPairClosed
	}
	p.directSock = sock
	p.mu.Unlock()

	p.mp.addUnderlay(quicUnderlay{
		name: quicPathDirect,
		addr: quicPathAddr{name: quicPathDirect, addr: peerAddr},
		pc:   &directPacketConn{u: u},
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
	p.mu.Unlock()

	if p.role == quicRoleClient && p.mp.preferredPath() == quicPathDirect {
		p.mp.setPreferred(quicPathRelay)
	}
	p.mp.removeUnderlay(quicPathDirect)
	// removeUnderlay already closed the packet conn, which closes the socket;
	// this is the idempotent belt-and-braces close for a socket that had not
	// been installed yet.
	_ = sock.Close()
}
