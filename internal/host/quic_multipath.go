package host

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC path names. The relay and direct underlays must expose different path
// addresses: quic-go validates a new remote address before migrating, so two
// paths that stringify identically would never trigger migration.
const (
	quicPathRelay  = "relay"
	quicPathDirect = "direct"
)

// quicMultiPathReadQueue bounds the fan-in queue. A full queue drops packets;
// QUIC retransmission covers the loss. It must not block an underlay reader,
// because a blocked reader cannot observe Close and keeps the transport alive.
const quicMultiPathReadQueue = 4096

var errNoQUICUnderlay = errors.New("host: quic multipath has no underlay")

// quicPathAddr is the synthetic net.Addr of one underlay. QUIC treats the
// address returned by ReadFrom as the path identity.
type quicPathAddr struct {
	name string
	addr netip.AddrPort
}

func (a quicPathAddr) Network() string { return "p2p-" + a.name }

func (a quicPathAddr) String() string {
	switch a.name {
	case quicPathRelay:
		return quicPathRelay
	case quicPathDirect:
		return quicPathDirect + ":" + a.addr.String()
	default:
		return a.name
	}
}

// quicUnderlay is one packet path (relay or direct) feeding a multiPathConn.
// pc should unblock a pending ReadFrom when closed so the reader goroutine can
// exit, but removal never waits for that: a non-conforming Close only costs a
// leaked reader, it cannot block the caller.
type quicUnderlay struct {
	name string
	addr net.Addr
	pc   net.PacketConn
}

// quicRole selects the write policy: the client picks the preferred underlay,
// the server routes by the destination address learned from ReadFrom.
type quicRole uint8

const (
	quicRoleClient quicRole = iota
	quicRoleServer
)

type quicReadResult struct {
	data []byte
	addr net.Addr
}

// quicUnderlayReader is the per-instance state of one underlay. Its pointer
// identity lets deliver reject packets from a replaced or removed reader.
type quicUnderlayReader struct {
	u quicUnderlay
}

// multiPathConn presents several packet underlays as a single net.PacketConn
// for one QUIC connection. It is not an MP-QUIC aggregator: at any moment the
// client transmits on exactly one path.
type multiPathConn struct {
	role  quicRole
	local net.Addr

	mu        sync.RWMutex
	underlays map[string]*quicUnderlayReader
	preferred string

	readCh    chan quicReadResult
	closed    chan struct{}
	closeOnce sync.Once

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineCh    chan struct{}

	reads      atomic.Int64
	drops      atomic.Int64
	readErrors atomic.Int64
}

var (
	_ net.PacketConn             = (*multiPathConn)(nil)
	_ quic.ConnectionIDGenerator = zeroCIDGenerator{}
)

func newMultiPathConn(role quicRole) *multiPathConn {
	localName := "client-local"
	if role == quicRoleServer {
		localName = "server-local"
	}
	return &multiPathConn{
		role:       role,
		local:      quicPathAddr{name: localName},
		underlays:  make(map[string]*quicUnderlayReader),
		readCh:     make(chan quicReadResult, quicMultiPathReadQueue),
		closed:     make(chan struct{}),
		deadlineCh: make(chan struct{}),
	}
}

// addUnderlay installs u, replacing any underlay with the same name. The old
// reader is retired by the map swap and its packet conn closed, but it is not
// waited for: deliver drops its packets even if Close does not unblock ReadFrom.
func (c *multiPathConn) addUnderlay(u quicUnderlay) {
	r := &quicUnderlayReader{u: u}

	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		_ = u.pc.Close()
		return
	default:
	}
	old := c.underlays[u.name]
	c.underlays[u.name] = r
	c.mu.Unlock()

	if old != nil {
		_ = old.u.pc.Close()
	}
	go c.pump(r)
}

// removeUnderlay closes the named underlay without waiting for its reader.
// Removing the preferred path clears it; the client then falls back to relay on
// the next write.
func (c *multiPathConn) removeUnderlay(name string) {
	c.mu.Lock()
	r := c.underlays[name]
	if r == nil {
		c.mu.Unlock()
		return
	}
	delete(c.underlays, name)
	if c.preferred == name {
		c.preferred = ""
	}
	c.mu.Unlock()

	_ = r.u.pc.Close()
}

// removeUnderlayIf removes the named underlay only while it is still pc. A
// delayed teardown (a relay being retired after its reconnect) must not remove
// the fresh underlay a newer install put in the same slot.
func (c *multiPathConn) removeUnderlayIf(name string, pc net.PacketConn) bool {
	c.mu.Lock()
	r := c.underlays[name]
	if r == nil || r.u.pc != pc {
		c.mu.Unlock()
		return false
	}
	delete(c.underlays, name)
	if c.preferred == name {
		c.preferred = ""
	}
	c.mu.Unlock()

	_ = r.u.pc.Close()
	return true
}

func (c *multiPathConn) setPreferred(name string) {
	c.mu.Lock()
	c.preferred = name
	c.mu.Unlock()
}

func (c *multiPathConn) preferredPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.preferred
}

// pump copies packets from one underlay into the shared fan-in queue. A read
// error only ends this pump: a dead path must not tear down the QUIC
// connection, which can still migrate to another underlay.
func (c *multiPathConn) pump(r *quicUnderlayReader) {
	buf := make([]byte, 64<<10)
	for {
		n, _, err := r.u.pc.ReadFrom(buf)
		if err != nil {
			c.readErrors.Add(1)
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		if !c.deliver(r, pkt) {
			return
		}
	}
}

// deliver enqueues a packet only while r is still installed. Holding the read
// lock through the non-blocking send makes replacement/removal a barrier: once
// addUnderlay or removeUnderlay returns, r cannot publish again.
func (c *multiPathConn) deliver(r *quicUnderlayReader, pkt []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.underlays[r.u.name] != r {
		return false
	}
	select {
	case <-c.closed:
		return false
	default:
	}
	select {
	case c.readCh <- quicReadResult{data: pkt, addr: r.u.addr}:
		c.reads.Add(1)
	default:
		c.drops.Add(1)
	}
	return true
}

func (c *multiPathConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.deadlineMu.Lock()
		dl := c.readDeadline
		dlCh := c.deadlineCh
		c.deadlineMu.Unlock()

		if !dl.IsZero() && !time.Now().Before(dl) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			timer = time.NewTimer(time.Until(dl))
			timeout = timer.C
		}

		select {
		case r := <-c.readCh:
			if timer != nil {
				timer.Stop()
			}
			return copy(p, r.data), r.addr, nil
		case <-c.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-dlCh:
			// SetReadDeadline woke us; re-evaluate the new deadline.
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			// The deadline may have been extended or cleared while the timer
			// was firing. Re-evaluate instead of reporting a stale expiry.
			c.deadlineMu.Lock()
			current := c.readDeadline
			c.deadlineMu.Unlock()
			if current.IsZero() || time.Now().Before(current) {
				continue
			}
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (c *multiPathConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.writeDeadlineExceeded() {
		return 0, os.ErrDeadlineExceeded
	}

	c.mu.RLock()
	var u *quicUnderlayReader
	if c.role == quicRoleClient {
		// The client drives the path: quic-go's destination address is ignored
		// and the preferred underlay is used, with relay as the fallback.
		if c.preferred != "" {
			u = c.underlays[c.preferred]
		}
		if u == nil {
			u = c.underlays[quicPathRelay]
		}
	} else {
		if name := quicPathName(addr); name != "" {
			u = c.underlays[name]
		}
		if u == nil {
			u = c.underlays[quicPathRelay]
		}
	}
	c.mu.RUnlock()

	if u == nil {
		return 0, errNoQUICUnderlay
	}
	return u.u.pc.WriteTo(p, u.u.addr)
}

func quicPathName(addr net.Addr) string {
	switch a := addr.(type) {
	case quicPathAddr:
		return a.name
	case *quicPathAddr:
		if a != nil {
			return a.name
		}
	}
	return ""
}

func (c *multiPathConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)

		c.mu.Lock()
		readers := make([]*quicUnderlayReader, 0, len(c.underlays))
		for name, r := range c.underlays {
			readers = append(readers, r)
			delete(c.underlays, name)
		}
		c.mu.Unlock()

		for _, r := range readers {
			_ = r.u.pc.Close()
		}
	})
	return nil
}

func (c *multiPathConn) LocalAddr() net.Addr { return c.local }

func (c *multiPathConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	close(c.deadlineCh)
	c.deadlineCh = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

func (c *multiPathConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	close(c.deadlineCh)
	c.deadlineCh = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

func (c *multiPathConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *multiPathConn) writeDeadlineExceeded() bool {
	c.deadlineMu.Lock()
	dl := c.writeDeadline
	c.deadlineMu.Unlock()
	return !dl.IsZero() && !time.Now().Before(dl)
}

// zeroCIDGenerator keeps QUIC connection IDs at zero length. The default
// generator's CID pool is exhausted after one migration cycle; a zero-length
// CID is implicit and needs no allocation. Because the CID cannot identify a
// connection, there must be exactly one QUIC connection per Transport.
type zeroCIDGenerator struct{}

func (zeroCIDGenerator) ConnectionIDLen() int { return 0 }

func (zeroCIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionIDFromBytes(nil), nil
}
