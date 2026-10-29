package host

import (
	"bytes"
	"errors"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

func TestQUICBatchRoundTrip(t *testing.T) {
	in := [][]byte{{1, 2}, {3}}
	out, err := decodeQUICBatch(encodeQUICBatch(in))
	if err != nil || !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip = %v, %v; want %v", out, err, in)
	}
}

func TestQUICBatchRejectsTruncated(t *testing.T) {
	for _, payload := range [][]byte{
		{0},          // no length
		{0, 5, 1, 2}, // length says 5, only 2 bytes follow
		{0, 1},       // length says 1, no payload
		{0, 1, 'a', 0},
	} {
		if _, err := decodeQUICBatch(payload); err == nil {
			t.Fatalf("decodeQUICBatch(%v) succeeded, want error", payload)
		}
	}
}

func TestQUICBatchRejectsZeroLength(t *testing.T) {
	if _, err := decodeQUICBatch([]byte{0, 0}); err == nil {
		t.Fatal("zero-length packet accepted, want error")
	}
}

func TestQUICBatchCopiesPackets(t *testing.T) {
	payload := encodeQUICBatch([][]byte{{1, 2, 3}})
	out, err := decodeQUICBatch(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	payload[2] = 9
	if out[0][0] != 1 {
		t.Fatalf("decoded packet aliases payload: %v", out[0])
	}
}

func TestQUICBatchMaxPacket(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, 1<<16-1)
	out, err := decodeQUICBatch(encodeQUICBatch([][]byte{want}))
	if err != nil {
		t.Fatalf("decode 64 KiB boundary: %v", err)
	}
	if !reflect.DeepEqual(out, [][]byte{want}) {
		t.Fatal("64 KiB boundary packet changed")
	}
}

func TestQUICBatchEmpty(t *testing.T) {
	out, err := decodeQUICBatch(encodeQUICBatch(nil))
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("empty batch decoded to %d packets", len(out))
	}
}

// readRelayPacket reads one packet from c with a bounded test deadline.
func readRelayPacket(t *testing.T, c *relayQUICConn, size int) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, size)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
}

func TestRelayQUICConnSplitsPayload(t *testing.T) {
	in := make(chan []byte, 1)
	c := newRelayQUICConn(in, func([]byte) error { return nil }, nil, quicRelayOptions{})
	defer c.Close()

	want := [][]byte{[]byte("first"), []byte("second")}
	in <- encodeQUICBatch(want)

	for _, pkt := range want {
		got := readRelayPacket(t, c, 64)
		if !bytes.Equal(got, pkt) {
			t.Fatalf("ReadFrom = %q, want %q", got, pkt)
		}
	}
	if got := c.packets.Load(); got != 0 {
		t.Fatalf("packets = %d, want 0 for inbound-only conn", got)
	}
}

func TestRelayQUICConnBatchesWrites(t *testing.T) {
	sends := make(chan []byte, 8)
	c := newRelayQUICConn(make(chan []byte), func(payload []byte) error {
		sends <- append([]byte(nil), payload...)
		return nil
	}, nil, quicRelayOptions{})
	defer c.Close()

	want := [][]byte{{1, 2}, {3, 4}, {5}}
	for _, pkt := range want {
		if n, err := c.WriteTo(pkt, nil); err != nil || n != len(pkt) {
			t.Fatalf("WriteTo(%v) = %d, %v", pkt, n, err)
		}
	}

	var got [][]byte
	batches := 0
	timeout := time.After(2 * time.Second)
	for len(got) < len(want) {
		select {
		case payload := <-sends:
			batches++
			packets, err := decodeQUICBatch(payload)
			if err != nil {
				t.Fatalf("sent malformed batch: %v", err)
			}
			got = append(got, packets...)
		case <-timeout:
			t.Fatalf("only %d/%d packets sent", len(got), len(want))
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sent packets = %v, want %v", got, want)
	}
	if batches < 1 || batches > len(want) {
		t.Fatalf("sent %d batches for %d packets", batches, len(want))
	}
	if n := c.batches.Load(); n != int64(batches) {
		t.Fatalf("batches counter = %d, want %d", n, batches)
	}
	if n := c.packets.Load(); n != int64(len(want)) {
		t.Fatalf("packets counter = %d, want %d", n, len(want))
	}
}

func TestRelayQUICConnFlush(t *testing.T) {
	sent := make(chan time.Time, 1)
	c := newRelayQUICConn(make(chan []byte), func([]byte) error {
		sent <- time.Now()
		return nil
	}, nil, quicRelayOptions{})
	defer c.Close()

	start := time.Now()
	if _, err := c.WriteTo([]byte("x"), nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	select {
	case at := <-sent:
		if delay := at.Sub(start); delay > 100*time.Millisecond {
			t.Fatalf("flush took %v, want near %v", delay, quicRelayFlush)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("single packet was not flushed")
	}
}

func TestRelayQUICConnDropsMalformed(t *testing.T) {
	in := make(chan []byte, 2)
	c := newRelayQUICConn(in, func([]byte) error { return nil }, nil, quicRelayOptions{})
	defer c.Close()

	in <- []byte{0, 5, 1, 2} // truncated batch: drop the whole payload
	in <- encodeQUICBatch([][]byte{[]byte("next")})

	if got := readRelayPacket(t, c, 64); !bytes.Equal(got, []byte("next")) {
		t.Fatalf("ReadFrom after malformed = %q, want %q", got, "next")
	}
	if got := c.drops.Load(); got != 1 {
		t.Fatalf("drops = %d, want 1", got)
	}
}

func TestRelayQUICConnDropsOversizedPacket(t *testing.T) {
	in := make(chan []byte, 1)
	c := newRelayQUICConn(in, func([]byte) error { return nil }, nil, quicRelayOptions{})
	defer c.Close()

	in <- encodeQUICBatch([][]byte{bytes.Repeat([]byte{1}, 8), []byte("ok")})
	if got := readRelayPacket(t, c, 4); !bytes.Equal(got, []byte("ok")) {
		t.Fatalf("ReadFrom = %q, want %q", got, "ok")
	}
	if got := c.drops.Load(); got != 1 {
		t.Fatalf("drops = %d, want 1", got)
	}
}

func TestRelayQUICConnReadDeadline(t *testing.T) {
	c := newRelayQUICConn(make(chan []byte), func([]byte) error { return nil }, nil, quicRelayOptions{})
	defer c.Close()

	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, _, err := c.ReadFrom(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom = %v, want %v", err, os.ErrDeadlineExceeded)
	}

	// Extending the deadline unblocks a reader previously past its expiry.
	done := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 64))
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("ReadFrom = %v, want deadline error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline change did not wake ReadFrom")
	}
}

func TestRelayQUICConnWriteDeadline(t *testing.T) {
	c := newRelayQUICConn(make(chan []byte), func([]byte) error { return nil }, nil, quicRelayOptions{})
	defer c.Close()

	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if n, err := c.WriteTo([]byte("x"), nil); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("WriteTo = %d, %v; want 0, %v", n, err, os.ErrDeadlineExceeded)
	}
}

func TestRelayQUICConnClose(t *testing.T) {
	var closeCalls atomic.Int64
	closeErr := errors.New("close failed")
	in := make(chan []byte)
	c := newRelayQUICConn(in, nil, func() error {
		closeCalls.Add(1)
		return closeErr
	}, quicRelayOptions{})

	readErr := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 64))
		readErr <- err
	}()
	time.Sleep(10 * time.Millisecond)

	if err := c.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close = %v, want %v", err, closeErr)
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom after Close = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Close(); !errors.Is(err, closeErr) {
				t.Errorf("second Close = %v, want %v", err, closeErr)
			}
		}()
	}
	wg.Wait()
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("closeFn called %d times, want 1", got)
	}
	if _, err := c.WriteTo([]byte("x"), nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo after Close = %v, want %v", err, net.ErrClosed)
	}
}

func TestRelayQUICConnCountsSendErrors(t *testing.T) {
	sendErr := errors.New("send failed")
	called := make(chan struct{}, 1)
	c := newRelayQUICConn(make(chan []byte), func([]byte) error {
		called <- struct{}{}
		return sendErr
	}, nil, quicRelayOptions{})
	defer c.Close()

	if _, err := c.WriteTo([]byte("x"), nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not run")
	}
	waitFor(t, 2*time.Second, func() bool { return c.sendErrors.Load() == 1 })
	if got := c.drops.Load(); got != 1 {
		t.Fatalf("drops = %d, want 1 packet lost to send error", got)
	}
	if got := c.batches.Load(); got != 0 {
		t.Fatalf("batches = %d, want 0 after send error", got)
	}
}

func TestRelayQUICConnWriteQueueDrops(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(release) })
	}()

	c := newRelayQUICConn(make(chan []byte), func([]byte) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	}, nil, quicRelayOptions{})

	if _, err := c.WriteTo([]byte("first"), nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not reach send")
	}

	pkt := make([]byte, 8)
	for i := 0; i < quicRelayWriteQueue; i++ {
		if _, err := c.WriteTo(pkt, nil); err != nil {
			t.Fatalf("WriteTo(%d): %v", i, err)
		}
	}
	if n, err := c.WriteTo(pkt, nil); err != nil || n != len(pkt) {
		t.Fatalf("WriteTo on full queue = %d, %v; want %d, nil", n, err, len(pkt))
	}
	if got := c.drops.Load(); got != 1 {
		t.Fatalf("drops = %d, want 1 queue-full drop", got)
	}

	releaseOnce.Do(func() { close(release) })
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestRelayQUICConnConcurrentWrites(t *testing.T) {
	var badBatch atomic.Bool
	c := newRelayQUICConn(make(chan []byte), func(payload []byte) error {
		if _, err := decodeQUICBatch(payload); err != nil {
			badBatch.Store(true)
		}
		return nil
	}, nil, quicRelayOptions{})
	defer c.Close()

	const writers = 8
	const perWriter = 200
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pkt := []byte{byte(id)}
			for j := 0; j < perWriter; j++ {
				if _, err := c.WriteTo(pkt, nil); err != nil {
					t.Errorf("WriteTo: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	total := int64(writers * perWriter)
	waitFor(t, 2*time.Second, func() bool { return c.packets.Load()+c.drops.Load() == total })
	if got := c.packets.Load() + c.drops.Load(); got != total {
		t.Fatalf("sent+dropped = %d, want %d", got, total)
	}
	if badBatch.Load() {
		t.Fatal("sender emitted a malformed batch")
	}
}

// TestRelayQUICConnHonorsFrameBudget pins the DERP frame boundary: the
// configured batch budget counts each packet's 2-byte length prefix and
// reserves the frameData byte peerConn.Write prepends, so the encoded payload
// stays at or below MaxPacketSize-1 and the final SendPacket frame stays within
// derpclient.MaxPacketSize even when the host configures the maximum batch
// size.
func TestRelayQUICConnHonorsFrameBudget(t *testing.T) {
	sends := make(chan []byte, 128)
	c := newRelayQUICConn(make(chan []byte), func(payload []byte) error {
		// pc.Write builds [frameData][payload] before SendPacket.
		if len(payload)+1 > derpclient.MaxPacketSize {
			t.Errorf("relay frame = %d bytes including the type byte, want <= %d",
				len(payload)+1, derpclient.MaxPacketSize)
		}
		sends <- append([]byte(nil), payload...)
		return nil
	}, nil, quicRelayOptions{BatchBytes: derpclient.MaxPacketSize, Flush: time.Millisecond})
	defer c.Close()
	if c.batchBytes != derpclient.MaxPacketSize-1 {
		t.Fatalf("batch budget = %d, want %d after reserving the frame byte",
			c.batchBytes, derpclient.MaxPacketSize-1)
	}

	const packets = 200
	pkt := bytes.Repeat([]byte{0xab}, 1200)
	for i := 0; i < packets; i++ {
		if _, err := c.WriteTo(pkt, nil); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	got := 0
	timeout := time.After(3 * time.Second)
	for got < packets {
		select {
		case payload := <-sends:
			if len(payload) > derpclient.MaxPacketSize-1 {
				t.Fatalf("relay payload = %d bytes, want <= %d",
					len(payload), derpclient.MaxPacketSize-1)
			}
			pkts, err := decodeQUICBatch(payload)
			if err != nil {
				t.Fatalf("decode batch: %v", err)
			}
			got += len(pkts)
		case <-timeout:
			t.Fatalf("only %d/%d packets sent", got, packets)
		}
	}
}

// TestRelayQUICConnFrameBudgetExactlyMax writes one packet whose framed batch
// lands exactly on the payload limit: 2-byte length prefix + (MaxPacketSize-3)
// bytes = MaxPacketSize-1 bytes, leaving the frameData byte room under
// MaxPacketSize. The previous clamp allowed a 65536-byte payload, whose
// prefixed frame SendPacket rejected.
func TestRelayQUICConnFrameBudgetExactlyMax(t *testing.T) {
	sends := make(chan []byte, 1)
	c := newRelayQUICConn(make(chan []byte), func(payload []byte) error {
		sends <- append([]byte(nil), payload...)
		return nil
	}, nil, quicRelayOptions{BatchBytes: derpclient.MaxPacketSize, Flush: time.Millisecond})
	defer c.Close()

	pkt := bytes.Repeat([]byte{0xcd}, derpclient.MaxPacketSize-3)
	if _, err := c.WriteTo(pkt, nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	select {
	case payload := <-sends:
		if len(payload) != derpclient.MaxPacketSize-1 {
			t.Fatalf("relay payload = %d bytes, want %d", len(payload), derpclient.MaxPacketSize-1)
		}
		if len(payload)+1 > derpclient.MaxPacketSize {
			t.Fatalf("relay frame = %d bytes including the type byte, want <= %d",
				len(payload)+1, derpclient.MaxPacketSize)
		}
		pkts, err := decodeQUICBatch(payload)
		if err != nil || len(pkts) != 1 || len(pkts[0]) != len(pkt) {
			t.Fatalf("decode boundary batch: %d packets, %v", len(pkts), err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not emit the boundary batch")
	}
}

// TestRelayQUICConnDropsPacketsOverBudget proves the framing prefix is part of
// the budget: with a 32-byte batch, a 30-byte packet fits (2+30) and a 31-byte
// packet does not.
func TestRelayQUICConnDropsPacketsOverBudget(t *testing.T) {
	sends := make(chan []byte, 4)
	c := newRelayQUICConn(make(chan []byte), func(payload []byte) error {
		sends <- append([]byte(nil), payload...)
		return nil
	}, nil, quicRelayOptions{BatchBytes: 32, Flush: time.Millisecond})
	defer c.Close()

	if _, err := c.WriteTo(make([]byte, 31), nil); err != nil {
		t.Fatalf("WriteTo oversized: %v", err)
	}
	if got := c.drops.Load(); got != 1 {
		t.Fatalf("drops = %d, want 1 for an over-budget packet", got)
	}
	if _, err := c.WriteTo(make([]byte, 30), nil); err != nil {
		t.Fatalf("WriteTo fitting: %v", err)
	}
	select {
	case payload := <-sends:
		if len(payload) != 32 {
			t.Fatalf("encoded payload = %d bytes, want 32", len(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fitting packet was not sent")
	}
}
