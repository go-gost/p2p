package host

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// Relay batching parameters. One DERP data frame carries several QUIC
// packets framed by their lengths; batching keeps the per-packet relay
// overhead down while the flush bound keeps interactive traffic responsive.
const (
	quicRelayBatchBytes = 32 << 10
	quicRelayFlush      = 200 * time.Microsecond
	// quicRelayBatchVersion identifies the framing advertised in caps. Both
	// ends must agree before any relay payload is exchanged.
	quicRelayBatchVersion = quicCapsBatchVersion

	// quicRelayWriteQueue bounds the packets buffered between QUIC writers and
	// the single relay sender. A full queue drops the packet, which QUIC
	// retransmits; it must never block a QUIC write path.
	quicRelayWriteQueue = 1024

	// quicRelayInQueue bounds inbound DERP payloads waiting to be split by
	// ReadFrom. A full queue drops the payload; the QUIC packets inside it are
	// retransmitted.
	quicRelayInQueue = 256

	// quicRelayMaxPacket is the largest packet the uint16 length prefix can
	// describe. The sender rejects anything whose framed size (2 + packet)
	// exceeds the batch budget before it reaches the encoder.
	quicRelayMaxPacket = 1<<16 - 1

	// quicRelayMaxPayload is the largest encoded batch peerConn.Write can carry
	// as one DERP frame. Write prefixes frameData before SendPacket, and
	// SendPacket rejects anything above derpclient.MaxPacketSize, so the batch
	// payload itself must reserve that one frame-type byte.
	quicRelayMaxPayload = derpclient.MaxPacketSize - 1
)

// quicRelayOptions carries the host's batching configuration. The zero value
// keeps the package defaults, so tests and callers that do not care can pass
// an empty struct.
type quicRelayOptions struct {
	BatchBytes int
	Flush      time.Duration
}

// resolve returns the effective batch size and flush delay. The batch size
// counts each packet's 2-byte length prefix and reserves the frame-type byte
// peerConn.Write prepends, which keeps one encoded payload within both the
// configured budget and the DERP frame limit.
func (o quicRelayOptions) resolve() (int, time.Duration) {
	batch := o.BatchBytes
	if batch <= 0 {
		batch = quicRelayBatchBytes
	}
	if batch > quicRelayMaxPayload {
		batch = quicRelayMaxPayload
	}
	flush := o.Flush
	if flush <= 0 {
		flush = quicRelayFlush
	}
	return batch, flush
}

var (
	errQUICBatchTruncated = errors.New("host: quic relay batch truncated")
	errQUICBatchZero      = errors.New("host: quic relay batch has a zero-length packet")
)

// encodeQUICBatch frames packets as [uint16 big-endian length][packet]...
// Packets that cannot be represented by the length prefix are skipped; the
// sender drops them before calling the encoder. The input slices are not
// modified or retained.
func encodeQUICBatch(packets [][]byte) []byte {
	var out []byte
	for _, pkt := range packets {
		if len(pkt) == 0 || len(pkt) > quicRelayMaxPacket {
			continue
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(pkt)))
		out = append(out, pkt...)
	}
	return out
}

// decodeQUICBatch parses one relay payload. Any malformed or truncated frame
// rejects the whole payload: returning the packets before the bad frame would
// hand QUIC a silently incomplete batch. The returned packets own their
// memory, so the caller may reuse the payload buffer.
func decodeQUICBatch(payload []byte) ([][]byte, error) {
	var packets [][]byte
	for len(payload) > 0 {
		if len(payload) < 2 {
			return nil, errQUICBatchTruncated
		}
		n := int(binary.BigEndian.Uint16(payload[:2]))
		if n == 0 {
			return nil, errQUICBatchZero
		}
		if len(payload) < 2+n {
			return nil, errQUICBatchTruncated
		}
		packets = append(packets, append([]byte(nil), payload[2:2+n]...))
		payload = payload[2+n:]
	}
	return packets, nil
}

// relayQUICConn is the net.PacketConn view of one peer's DERP data path. In
// carries inbound frameData payloads (still batch-encoded); send hands one
// encoded batch to peerConn.Write. It is a bridge only: the multiPathConn and
// the QUIC Transport own lifecycle and path selection.
type relayQUICConn struct {
	in      chan []byte
	send    func([]byte) error
	closeFn func() error

	batchBytes int
	flush      time.Duration

	writeCh    chan []byte
	closedCh   chan struct{}
	senderDone chan struct{}
	closeOnce  sync.Once
	closeErr   error

	readMu  sync.Mutex
	pending [][]byte // decoded packets not yet returned by ReadFrom

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineCh    chan struct{}

	// Counters for Status and debug logging. batches counts successful relay
	// writes, packets counts the QUIC packets inside them, and drops counts
	// every packet lost to a malformed payload, a full queue, or a failed send.
	batches    atomic.Int64
	packets    atomic.Int64
	drops      atomic.Int64
	sendErrors atomic.Int64
}

var _ net.PacketConn = (*relayQUICConn)(nil)

// newRelayQUICConn starts the batching sender. in and send must be non-nil;
// closeFn may be nil. opts carries the host's batching configuration; its zero
// value keeps the package defaults. Close invokes closeFn once after the
// sender exits.
func newRelayQUICConn(in chan []byte, send func([]byte) error, closeFn func() error, opts quicRelayOptions) *relayQUICConn {
	batchBytes, flush := opts.resolve()
	c := &relayQUICConn{
		in:         in,
		send:       send,
		closeFn:    closeFn,
		batchBytes: batchBytes,
		flush:      flush,
		writeCh:    make(chan []byte, quicRelayWriteQueue),
		closedCh:   make(chan struct{}),
		senderDone: make(chan struct{}),
		deadlineCh: make(chan struct{}),
	}
	go c.sender()
	return c
}

// deliver queues one inbound DERP payload for ReadFrom without blocking. The
// payload is owned by the relay pump and is not copied: decodeQUICBatch copies
// each packet before returning it, and nothing else retains the slice.
func (c *relayQUICConn) deliver(pkt []byte) bool {
	select {
	case <-c.closedCh:
		return false
	default:
	}
	select {
	case c.in <- pkt:
		return true
	default:
		c.drops.Add(1)
		return false
	}
}

// sender owns the outbound batch. It accumulates packets until they reach
// quicRelayBatchBytes or quicRelayFlush expires after the first one, then
// encodes and writes exactly one DERP payload. It is the only goroutine that
// calls send, so a slow relay write never blocks concurrent QUIC writers.
func (c *relayQUICConn) sender() {
	defer close(c.senderDone)

	var pending [][]byte
	var pendingBytes int
	var timer *time.Timer
	var timerC <-chan time.Time

	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	startTimer := func() {
		if timer == nil {
			timer = time.NewTimer(c.flush)
		} else {
			timer.Reset(c.flush)
		}
		timerC = timer.C
	}
	flush := func() {
		if len(pending) == 0 {
			return
		}
		n := len(pending)
		payload := encodeQUICBatch(pending)
		pending = nil
		pendingBytes = 0
		if len(payload) == 0 {
			return
		}
		if c.send == nil {
			c.drops.Add(int64(n))
			return
		}
		if err := c.send(payload); err != nil {
			c.sendErrors.Add(1)
			c.drops.Add(int64(n))
			return
		}
		c.batches.Add(1)
		c.packets.Add(int64(n))
	}

	for {
		select {
		case <-c.closedCh:
			return
		default:
		}

		select {
		case pkt := <-c.writeCh:
			// WriteTo rejects oversized packets; keep the sender defensive in
			// case a future caller bypasses it. The 2-byte length prefix is
			// part of the frame budget, so a batch never encodes past
			// batchBytes, which reserves the frame-type byte peerConn.Write
			// prepends to the DERP frame.
			framed := 2 + len(pkt)
			if len(pkt) == 0 || framed > c.batchBytes {
				c.drops.Add(1)
				continue
			}
			if pendingBytes > 0 && pendingBytes+framed > c.batchBytes {
				flush()
				stopTimer()
			}
			pending = append(pending, pkt)
			pendingBytes += framed
			if pendingBytes >= c.batchBytes {
				flush()
				stopTimer()
				continue
			}
			if timerC == nil {
				startTimer()
			}
		case <-timerC:
			flush()
			timerC = nil
		case <-c.closedCh:
			return
		}
	}
}

// WriteTo queues a copy of p for the sender. The queue is bounded and the
// call never blocks: on overflow the packet is dropped and counted, because a
// lost QUIC packet is recovered by retransmission.
func (c *relayQUICConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.writeDeadlineExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	select {
	case <-c.closedCh:
		return 0, net.ErrClosed
	default:
	}

	// Zero-length and over-budget packets cannot be framed usefully by the
	// relay; the budget includes the 2-byte length prefix. QUIC packets stay
	// under the path MTU and never take this branch.
	if len(p) == 0 || 2+len(p) > c.batchBytes {
		c.drops.Add(1)
		return len(p), nil
	}

	pkt := append([]byte(nil), p...)
	select {
	case c.writeCh <- pkt:
		return len(p), nil
	default:
		c.drops.Add(1)
		return len(p), nil
	}
}

// ReadFrom returns one QUIC packet decoded from the next inbound DERP payload.
// A malformed payload is dropped whole and counted; the reader then waits for
// the next payload instead of surfacing a partial batch. A packet larger than
// the caller's buffer is dropped rather than truncated, so QUIC never sees a
// cut packet.
func (c *relayQUICConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		select {
		case <-c.closedCh:
			return 0, nil, net.ErrClosed
		default:
		}

		if len(p) == 0 {
			return 0, nil, nil
		}
		if pkt, ok := c.popPending(); ok {
			if len(pkt) > len(p) {
				c.drops.Add(1)
				continue
			}
			return copy(p, pkt), c.LocalAddr(), nil
		}

		dl, dlCh := c.readDeadlineState()
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
		case payload, ok := <-c.in:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return 0, nil, net.ErrClosed
			}
			packets, err := decodeQUICBatch(payload)
			if err != nil {
				c.drops.Add(1)
				continue
			}
			if len(packets) == 0 {
				continue
			}
			c.pushPending(packets)
		case <-c.closedCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-dlCh:
			// SetReadDeadline woke the reader; re-evaluate the new deadline.
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			if timer != nil {
				timer.Stop()
			}
			// The deadline may have been extended or cleared while the timer
			// fired; only report expiry if the current one is still past.
			current, _ := c.readDeadlineState()
			if current.IsZero() || time.Now().Before(current) {
				continue
			}
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (c *relayQUICConn) pushPending(packets [][]byte) {
	c.readMu.Lock()
	c.pending = append(c.pending, packets...)
	c.readMu.Unlock()
}

func (c *relayQUICConn) popPending() ([]byte, bool) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) == 0 {
		return nil, false
	}
	pkt := c.pending[0]
	c.pending[0] = nil
	c.pending = c.pending[1:]
	if len(c.pending) == 0 {
		c.pending = nil
	}
	return pkt, true
}

func (c *relayQUICConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closedCh)
		<-c.senderDone
		if c.closeFn != nil {
			c.closeErr = c.closeFn()
		}
	})
	return c.closeErr
}

// LocalAddr is the synthetic relay path identity. Both directions report the
// same address so the multiPathConn can treat the relay as one QUIC path.
func (c *relayQUICConn) LocalAddr() net.Addr {
	return quicPathAddr{name: quicPathRelay}
}

func (c *relayQUICConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	close(c.deadlineCh)
	c.deadlineCh = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

func (c *relayQUICConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	close(c.deadlineCh)
	c.deadlineCh = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

func (c *relayQUICConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *relayQUICConn) readDeadlineState() (time.Time, <-chan struct{}) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline, c.deadlineCh
}

func (c *relayQUICConn) writeDeadlineExceeded() bool {
	c.deadlineMu.Lock()
	dl := c.writeDeadline
	c.deadlineMu.Unlock()
	return !dl.IsZero() && !time.Now().Before(dl)
}
