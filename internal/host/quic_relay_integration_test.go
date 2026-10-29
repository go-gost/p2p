package host

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// relayDataPump mirrors the relay pump's data branch for a fake DERP queue:
// it accepts only frameData frames, strips the type byte, and hands the payload
// to the peer adapter's sink. A frame of another type is dropped exactly as the
// real pump drops it, so the test cannot accidentally accept a payload the
// production path would reject.
func relayDataPump(q <-chan []byte, sink func([]byte), stop <-chan struct{}) {
	for {
		select {
		case frame, ok := <-q:
			if !ok {
				return
			}
			if len(frame) == 0 || frame[0] != frameData {
				continue
			}
			sink(frame[1:])
		case <-stop:
			return
		}
	}
}

// newFakeDERPRelaySide builds one end of a fake DERP data path: a QUIC pair with
// a relay underlay installed by the Task 8 wiring (pair.addRelayUnderlay) and a
// data sink from Task 8's quicDataSink. out receives the framed payloads the
// relay sender writes, i.e. what peerConn.Write would hand SendPacket.
func newFakeDERPRelaySide(t *testing.T, peer derpclient.PublicKey, out chan<- []byte, opts quicRelayOptions) (*engine, *quicPair, *relayQUICConn) {
	t.Helper()

	e := &engine{transport: transportQUIC, quics: make(map[derpclient.PublicKey]*quicPeer)}
	pair := newQUICPair(e, peer, quicRoleClient, nil, nil, nil)
	t.Cleanup(pair.close)

	batchBytes, _ := opts.resolve()
	in := make(chan []byte, quicRelayInQueue)
	relay := newRelayQUICConn(in, func(payload []byte) error {
		// peerConn.Write's exact framing: one frameData byte in front of the
		// batched payload, then derpclient.SendPacket's 64 KiB boundary.
		frame := make([]byte, 0, len(payload)+1)
		frame = append(frame, frameData)
		frame = append(frame, payload...)
		if len(payload) > batchBytes {
			t.Errorf("relay payload = %d bytes, want <= configured budget %d", len(payload), batchBytes)
		}
		if len(frame) > derpclient.MaxPacketSize {
			t.Errorf("relay frame = %d bytes, want <= %d", len(frame), derpclient.MaxPacketSize)
		}
		out <- frame
		return nil
	}, nil, opts)
	if err := pair.addRelayUnderlay(relay); err != nil {
		t.Fatalf("addRelayUnderlay: %v", err)
	}
	e.quics[peer] = &quicPeer{pair: pair, relay: relay, relayInstalled: true}
	return e, pair, relay
}

// readMultiPathPacket reads one packet from the pair's QUIC-facing PacketConn,
// which is where the relay underlay's ReadFrom splitting ends up.
func readMultiPathPacket(t *testing.T, mp *multiPathConn, size int) []byte {
	t.Helper()
	if err := mp.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, size)
	n, _, err := mp.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
}

// head4 returns at most the first four bytes, so a short or malformed read can
// be reported without slicing past its length.
func head4(b []byte) []byte {
	if len(b) > 4 {
		return b[:4]
	}
	return b
}

// TestQUICRelayBatchingIntegration drives the Task 8 relay data path end to
// end without a QUIC handshake: two fake DERP data payload queues carry the
// batching underlays, the Task 8 data sink feeds each peer's relay conn, and
// the peer's multiPathConn is what a QUIC Transport would read. It pins:
//
//   - several QUIC packets travel in one DERP payload and ReadFrom splits them
//     back into individual packets, in order;
//   - batching actually coalesces (batch count < packet count) while every
//     frame, type byte included, stays within derpclient.MaxPacketSize;
//   - a malformed payload is dropped whole and the next payload is still
//     served, so one corrupt DERP frame cannot desync the reader.
func TestQUICRelayBatchingIntegration(t *testing.T) {
	peerA := derpclient.PublicKey{0x41}
	peerB := derpclient.PublicKey{0x42}

	// The configured budget is the maximum the framing can use, so the test
	// exercises the 64 KiB boundary rather than a comfortable default. The
	// flush is deliberately long: every full batch then fills the budget, so
	// the batch count is a property of the framing, not scheduler timing.
	opts := quicRelayOptions{
		BatchBytes: derpclient.MaxPacketSize,
		Flush:      time.Second,
	}
	toB := make(chan []byte, 256)
	toA := make(chan []byte, 256)

	eA, pairA, relayA := newFakeDERPRelaySide(t, peerB, toB, opts)
	eB, pairB, relayB := newFakeDERPRelaySide(t, peerA, toA, opts)

	pcA := &peerConn{peer: peerB, closeCh: make(chan struct{})}
	pcB := &peerConn{peer: peerA, closeCh: make(chan struct{})}
	sinkA := eA.quicDataSink(pcA)
	sinkB := eB.quicDataSink(pcB)

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go relayDataPump(toB, sinkB, stop)
	go relayDataPump(toA, sinkA, stop)

	// Encode the packet index in the first bytes so a split, reordered or
	// truncated stream is visible, not just a byte count.
	const (
		packets  = 200
		packetSz = 1200
	)
	sent := make([][]byte, packets)
	for i := range sent {
		pkt := bytes.Repeat([]byte{byte(i)}, packetSz)
		binary.BigEndian.PutUint32(pkt[:4], uint32(i))
		sent[i] = pkt
		if n, err := pairA.mp.WriteTo(pkt, nil); err != nil || n != len(pkt) {
			t.Fatalf("WriteTo(%d) = %d, %v", i, n, err)
		}
	}

	// Every packet must be decoded on the peer side, one ReadFrom each: a
	// single unsplit datagram per batch would yield far fewer reads.
	for i, want := range sent {
		got := readMultiPathPacket(t, pairB.mp, 2*packetSz)
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d = %d bytes (prefix %x), want %d bytes (prefix %x)",
				i, len(got), head4(got), len(want), head4(want))
		}
	}

	waitFor(t, 3*time.Second, func() bool { return relayA.packets.Load() == packets })
	batches := relayA.batches.Load()
	if batches >= packets {
		t.Fatalf("sent %d packets in %d batches, want fewer batches than packets", packets, batches)
	}
	if batches > 8 {
		t.Fatalf("sent %d packets in %d batches, want at most 8 (about 54 packets per 64 KiB batch)", packets, batches)
	}
	if batches < 1 {
		t.Fatalf("batches = %d, want at least 1", batches)
	}
	if got := relayA.packets.Load(); got != packets {
		t.Fatalf("relay packets = %d, want %d", got, packets)
	}
	if got := relayB.drops.Load(); got != 0 {
		t.Fatalf("peer drops = %d during the healthy phase, want 0", got)
	}
	if relayA.batchBytes != derpclient.MaxPacketSize-1 {
		t.Fatalf("batch budget = %d, want %d after reserving the frame byte",
			relayA.batchBytes, derpclient.MaxPacketSize-1)
	}

	// A malformed payload is dropped whole; the very next payload must still
	// be read. Feeding it through the same queue exercises the sink and the
	// relay conn's decode path, not decodeQUICBatch in isolation.
	toB <- append([]byte{frameData}, 0, 5, 1, 2) // length says 5, only 2 bytes follow
	next := []byte("payload-after-malformed")
	frame := append([]byte{frameData}, encodeQUICBatch([][]byte{next})...)
	toB <- frame

	if got := readMultiPathPacket(t, pairB.mp, 256); !bytes.Equal(got, next) {
		t.Fatalf("ReadFrom after malformed payload = %q, want %q", got, next)
	}
	if got := relayB.drops.Load(); got != 1 {
		t.Fatalf("peer drops = %d, want exactly the malformed payload", got)
	}

	// The other direction is wired the same way; one packet proves the return
	// queue, pump and sink also deliver to a peer's ReadFrom.
	reverse := []byte("b-to-a")
	if n, err := pairB.mp.WriteTo(reverse, nil); err != nil || n != len(reverse) {
		t.Fatalf("WriteTo reverse = %d, %v", n, err)
	}
	if got := readMultiPathPacket(t, pairA.mp, 256); !bytes.Equal(got, reverse) {
		t.Fatalf("reverse ReadFrom = %q, want %q", got, reverse)
	}
}

// TestQUICRelayUnderlayUsesConfig pins the wiring the batching test above
// bypasses by constructing its relay conn directly: quicRelayUnderlay must
// build the conn from the engine's resolved settings, not package defaults.
func TestQUICRelayUnderlayUsesConfig(t *testing.T) {
	peer := derpclient.PublicKey{0x43}
	e := &engine{
		transport: transportQUIC,
		quics:     make(map[derpclient.PublicKey]*quicPeer),
		quicCfg: quicSettings{
			RelayBatchBytes: 8192,
			RelayFlush:      250 * time.Millisecond,
		},
	}
	pair := newQUICPair(e, peer, quicRoleClient, nil, nil, nil)
	t.Cleanup(pair.close)
	pc := &peerConn{peer: peer, closeCh: make(chan struct{})}
	e.quics[peer] = &quicPeer{pair: pair}

	if err := e.quicRelayUnderlay(peer, pair, pc); err != nil {
		t.Fatalf("quicRelayUnderlay: %v", err)
	}
	qp := e.quics[peer]
	if qp.relay == nil || !qp.relayInstalled {
		t.Fatal("quicRelayUnderlay did not install a relay underlay")
	}
	if got := qp.relay.batchBytes; got != 8192 {
		t.Fatalf("relay batch budget = %d, want the configured 8192", got)
	}
	if got := qp.relay.flush; got != 250*time.Millisecond {
		t.Fatalf("relay flush = %v, want the configured 250ms", got)
	}
}
