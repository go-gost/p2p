package host

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// seedProbeMagic prefixes raw-UDP seed handshake packets (Task 6). It lets the
// direct underlay tell seed traffic from KCP segments sharing the same socket,
// and lets a late seed responder echo the peer's probe instead of dropping it
// (a dropped echo would leave the peer's punch one-sided).
var seedProbeMagic = [4]byte{0x50, 0x32, 0x50, 0x53} // "P2PS"

// directUnderlayReadTimeout bounds a single ReadFromUDP so the read loop wakes
// periodically to observe close and to surface silence: on the deadline readFrom
// returns os.ErrDeadlineExceeded, which the pair's direct pump reads as an idle
// tick rather than a failure. It is the watchdog's granularity.
const directUnderlayReadTimeout = time.Second

// directUnderlay is one direct (raw UDP) path of a pair: it owns the punched
// socket and the peer's address, filters inbound datagrams by source, echoes
// seed probes, and hands KCP only the peer's non-seed packets. It deliberately
// exposes no address: the pair normalizes every underlay read to dummyAddr{}.
type directUnderlay struct {
	sock *net.UDPConn
	peer netip.AddrPort

	// installedAt is when the underlay was built, for the O1 direct-underlay
	// retired event's lifetime. It is set once at construction and read-only
	// afterwards, so it needs no lock.
	installedAt time.Time

	// localToken is this side's raw-UDP seed token (Task 6), set by
	// newDirectUnderlayToken when the punch threads it through. A seed packet
	// carrying it is this side's own probe coming back as the peer's echo, not
	// the peer's probe, and must never be echoed again. hasToken says whether
	// localToken is meaningful: a bare newDirectUnderlay leaves it unset, and
	// without it the underlay cannot tell the peer's probe from its own
	// returning echo, so it drops seed magic rather than risk the H2 ping-pong.
	localToken [seedTokenLen]byte
	hasToken   bool

	// seedEchoes counts seed probes this underlay has echoed. Diagnostic, and
	// the two-underlay quiesce test's observable: a ping-pong would keep it
	// climbing. Atomic so a status/test read never contends with readFrom.
	seedEchoes atomic.Int64

	done chan struct{}
	once sync.Once
	err  error
}

// newDirectUnderlay wraps an already-punched UDP socket for peer. The underlay
// takes ownership of sock: close closes it. It has no seed token, so it cannot
// tell a peer's probe from its own returning echo and does NOT echo seed magic
// (it drops it) — echoing without a token is the H2 ping-pong. The token MUST
// be threaded from the handshake to the underlay: use newDirectUnderlayToken.
func newDirectUnderlay(sock *net.UDPConn, peer netip.AddrPort) *directUnderlay {
	return &directUnderlay{
		sock:        sock,
		peer:        peer,
		installedAt: time.Now(),
		done:        make(chan struct{}),
	}
}

// newDirectUnderlayToken is newDirectUnderlay with this side's raw-UDP seed
// token (Task 6). Knowing it lets the underlay echo the peer's probes while
// dropping its own returning echo, so two registered underlays cannot ping-pong
// (the parked H2 ruling). The punch tail calls this after
// seedHandshakeUDPToken and must thread the token through registration.
func newDirectUnderlayToken(sock *net.UDPConn, peer netip.AddrPort, token [seedTokenLen]byte) *directUnderlay {
	u := newDirectUnderlay(sock, peer)
	u.localToken = token
	u.hasToken = true
	return u
}

// echoSeed consumes one datagram known to carry seedProbeMagic and at least a
// full token, echoing the peer's probe back to it and reporting whether it
// echoed. It echoes iff the token is NOT this side's own: our own token is our
// probe coming back as the peer's echo and must never be re-echoed, which is
// what keeps two registered underlays from ping-ponging. There is deliberately
// no per-token dedupe: a retransmitted probe carries the same token and must be
// re-echoed, or a single lost echo would strand the peer. With no token the
// underlay cannot make that distinction, so it does not echo at all.
func (u *directUnderlay) echoSeed(pkt []byte) bool {
	if !u.hasToken {
		return false
	}
	var tok [seedTokenLen]byte
	copy(tok[:], pkt[len(seedProbeMagic):len(seedProbeMagic)+seedTokenLen])
	if tok == u.localToken {
		return false // our own probe, echoed back by the peer: never re-echo
	}
	_, _ = u.sock.WriteToUDP(pkt, net.UDPAddrFromAddrPort(u.peer))
	u.seedEchoes.Add(1)
	return true
}

// name identifies the underlay for stats and preferred-path selection.
func (u *directUnderlay) name() string { return "direct" }

// readFrom blocks for the next datagram from the punched peer. Datagrams from
// any other source are dropped (kcp-go's own source lock cannot apply because
// the pair reports dummyAddr{}). A packet prefixed with seedProbeMagic is
// echoed back to the peer and skipped, never returned to KCP; the echo is
// token-aware (see echoSeed) so two registered underlays cannot ping-pong. It
// returns os.ErrDeadlineExceeded when no datagram arrived within
// directUnderlayReadTimeout — the pair's direct pump reads that as an idle tick,
// not a failure — and io.EOF after close.
func (u *directUnderlay) readFrom(p []byte) (int, error) {
	for {
		select {
		case <-u.done:
			return 0, io.EOF
		default:
		}

		if err := u.sock.SetReadDeadline(time.Now().Add(directUnderlayReadTimeout)); err != nil {
			if u.closed() {
				return 0, io.EOF
			}
			return 0, err
		}
		n, src, err := u.sock.ReadFromUDP(p)
		if err != nil {
			if u.closed() {
				return 0, io.EOF
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Silence, not failure: hand the tick to the direct pump so it
				// can run the idle watchdog.
				return 0, os.ErrDeadlineExceeded
			}
			return 0, err
		}
		if !sameAddrPort(src.AddrPort(), u.peer) {
			continue
		}
		if bytes.HasPrefix(p[:n], seedProbeMagic[:]) {
			// Late seed responder: echo the peer's probe so a peer whose own
			// echo was lost can still complete its seed. A malformed packet
			// (magic without a full token) is dropped; it is never surfaced to
			// KCP either way. echoSeed decides whether to echo (token-aware).
			if n >= len(seedProbeMagic)+seedTokenLen {
				u.echoSeed(p[:n])
			}
			continue
		}
		return n, nil
	}
}

// writeTo sends one datagram to the punched peer. Errors are swallowed and the
// full length is always reported: kcp-go treats a WriteTo error as fatal, so
// delivery is left to KCP retransmission.
func (u *directUnderlay) writeTo(p []byte) (int, error) {
	_, _ = u.sock.WriteToUDP(p, net.UDPAddrFromAddrPort(u.peer))
	return len(p), nil
}

// close closes the socket. It is idempotent and returns the socket's close
// error (nil on repeat calls).
func (u *directUnderlay) close() error {
	u.once.Do(func() {
		close(u.done)
		u.err = u.sock.Close()
	})
	return u.err
}

// closed reports whether close has run.
func (u *directUnderlay) closed() bool {
	select {
	case <-u.done:
		return true
	default:
		return false
	}
}

// sameAddrPort compares two addresses by port and IP, unmapping v4-in-v6 on
// both sides so a v4-mapped peer address still matches its v4 source.
func sameAddrPort(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().Unmap() == b.Addr().Unmap()
}
