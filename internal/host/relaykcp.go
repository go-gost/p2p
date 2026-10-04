package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/xtaci/kcp-go/v5"
)

// relayConv deterministically derives the KCP conversation ID for the relay
// plane from a sorted keypair. It mirrors directConn.conv but appends a domain
// tag so the relay underlay never collides with the direct-plane conv for the
// same pair.
func relayConv(a, b derpclient.PublicKey) uint32 {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	h := sha256.Sum256(append(append(a[:], b[:]...), []byte("p2p-relay-kcp")...))
	return binary.BigEndian.Uint32(h[:4])
}

// relayPacketConn adapts a peerConn into a net.PacketConn so KCP can run over
// the lossy DERP relay. Each inbound channel element is one datagram; writes
// become a single DERP SendPacket.
type relayPacketConn struct {
	pc *peerConn
}

// newRelayPacketConn wraps pc for use as a KCP net.PacketConn underlay.
func newRelayPacketConn(pc *peerConn) *relayPacketConn {
	return &relayPacketConn{pc: pc}
}

// ReadFrom returns one queued datagram. It mirrors peerConn.Read's drain-once
// semantics after closeCh is closed: any remaining queued packet is returned
// before io.EOF. If the caller's buffer is smaller than the datagram, the copy
// is truncated to len(p) exactly like UDP.
func (rc *relayPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var pkt []byte
	select {
	case pkt = <-rc.pc.inbound:
	case <-rc.pc.closeCh:
		select {
		case pkt = <-rc.pc.inbound:
		default:
			return 0, nil, io.EOF
		}
	}
	n := copy(p, pkt)
	return n, dummyAddr{}, nil
}

// WriteTo forwards one datagram to pc.Write, which sends it as a single DERP
// SendPacket. The destination address is ignored because the peer is fixed.
func (rc *relayPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return rc.pc.Write(p)
}

// Close closes the underlying peerConn adapter.
func (rc *relayPacketConn) Close() error {
	return rc.pc.Close()
}

// LocalAddr returns a placeholder address.
func (rc *relayPacketConn) LocalAddr() net.Addr { return dummyAddr{} }

// RemoteAddr returns a placeholder address identifying the peer.
func (rc *relayPacketConn) RemoteAddr() net.Addr { return dummyAddr{rc.pc.peer} }

// SetDeadline is a no-op; deadlines are not meaningful for this adapter.
func (rc *relayPacketConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op.
func (rc *relayPacketConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op.
func (rc *relayPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// Relay-plane KCP tuning. Internal constants, deliberately not configurable:
// there is no trusted use case for a less reliable relay plane, so rollback
// is a revert, not a switch (same posture as the direct plane).
const (
	// relayKCPMtu keeps one KCP segment inside a single DERP packet, so a
	// relay drop costs exactly one segment's retransmission. Conservative
	// for the TCP-based client-relay hop, where there is no IP fragmentation
	// to account for.
	relayKCPMtu = 1400
	// relayKCPSndWnd bounds this side's segments in flight, so a bulk
	// transfer cannot overflow the relay's bounded per-client send queue.
	// relayKCPRcvWnd is the peer's ceiling on ours: a slow local reader now
	// shrinks the advertised receive window instead of drowning the relay
	// queue — the backpressure the raw byte-stream underlay never had.
	relayKCPSndWnd = 256
	relayKCPRcvWnd = 256
)

// newRelayKCP builds this peer's KCP session over the relay datagram adapter
// and records it on pc.kcp. KCP is the reliability layer between the lossy
// DERP packet path and the crypto record framing: one dropped relay packet
// used to desync the record stream permanently ("bad secure record length"),
// and now it is one lost segment that KCP retransmits — the same stack the
// direct plane already runs (KCP -> cryptoConn(secure) -> smux). Caller must
// hold pc.mu.
func (pc *peerConn) newRelayKCP() (*kcp.UDPSession, error) {
	adapter := newRelayPacketConn(pc)
	// ownConn=false: a KCP Close must not close the adapter — killSession
	// owns its lifecycle (the adapter shares the process-wide relay client).
	kcpConn, err := kcp.NewConn4(relayConv(pc.e.pub, pc.peer), dummyAddr{}, nil, 0, 0, false, adapter)
	if err != nil {
		return nil, err
	}
	// nodelay=1 (on), 10ms interval, fast retransmit on the 2nd duplicate
	// ACK, congestion control off: a relay drop is a bounded-queue overflow,
	// not a congestion signal, so halving the window on loss would only
	// starve a healthy path.
	kcpConn.SetNoDelay(1, 10, 2, 1)
	kcpConn.SetMtu(relayKCPMtu)
	kcpConn.SetWindowSize(relayKCPSndWnd, relayKCPRcvWnd)
	pc.kcp = kcpConn
	return kcpConn, nil
}
