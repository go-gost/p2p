package host

// The relay pump's inbound queue separates two verdicts about one event. A
// packet that does not fit is dropped: a KCP segment the peer retransmits, not
// a consumed record, so the pair's nonce sequence stays aligned. Killing on
// that same event is a claim about the future — that the adapter will not drain
// again — and only the duration of the overflow can support it. These pin the
// split, because killing on the first drop took a healthy 2 MiB burst down with
// it on a loaded host (TestRelayToleratesDroppedDataFrames, reproducible under
// GOMAXPROCS=1) and, in the field, a session that was merely behind.

import (
	"log/slog"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// overflowProbe returns an adapter whose inbound queue holds two packets and
// whose session is live — enough to drive deliverInbound's three outcomes
// without a network.
func overflowProbe(t *testing.T, capture *logCapture) *peerConn {
	t.Helper()
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)
	return &peerConn{
		e:       e,
		peer:    derpclient.PublicKey{48},
		inbound: make(chan []byte, 2),
		closeCh: make(chan struct{}),
	}
}

func fillInbound(pc *peerConn) {
	for len(pc.inbound) < cap(pc.inbound) {
		pc.inbound <- []byte{frameData}
	}
}

func (pc *peerConn) isClosed() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.closed
}

// TestInboundOverflowBurstIsLoss: the first packet that does not fit is dropped
// and stamped, and the adapter keeps running — the session was not behind for
// long enough to be called dead.
func TestInboundOverflowBurstIsLoss(t *testing.T) {
	capture := &logCapture{}
	pc := overflowProbe(t, capture)
	fillInbound(pc)

	pc.deliverInbound([]byte{frameData})

	if pc.isClosed() {
		t.Fatal("one overflow killed a live session: a burst is loss, not a wedge")
	}
	if got := capture.count("peer session killed"); got != 0 {
		t.Fatalf("kills = %d, want 0: a burst must not log a death", got)
	}
	if pc.inboundFullSince.Load() == 0 {
		t.Fatal("the overflow was not stamped: the grace window never started")
	}
	if got, want := len(pc.inbound), cap(pc.inbound); got != want {
		t.Fatalf("queued = %d, want %d: the overflow must not evict a queued packet", got, want)
	}
}

// TestInboundOverflowPastGraceIsADeath: the same queue, still full past the
// grace, is a wedge — nothing has drained it — and the adapter is killed with
// the reason the field diagnosis reads.
func TestInboundOverflowPastGraceIsADeath(t *testing.T) {
	capture := &logCapture{}
	pc := overflowProbe(t, capture)
	fillInbound(pc)
	pc.inboundFullSince.Store(time.Now().UnixNano() - int64(inboundOverflowGrace) - int64(10*time.Millisecond))

	pc.deliverInbound([]byte{frameData})

	if !pc.isClosed() {
		t.Fatal("a queue full past the grace left the session running: nothing is draining it")
	}
	if got := capture.count("peer session killed"); got != 1 {
		t.Fatalf("kills = %d, want 1", got)
	}
	if got := capture.nth("peer session killed", 0)["relayReason"]; got != string(reasonQueueOverflow) {
		t.Fatalf("relayReason = %q, want %q", got, reasonQueueOverflow)
	}
}

// TestInboundOverflowDrainResetsTheGrace: a queue that drains clears the stamp,
// so the next burst gets its own window. Without the reset, a pair that
// overflowed once in its life would carry a stale start and be killed by the
// next unrelated burst.
func TestInboundOverflowDrainResetsTheGrace(t *testing.T) {
	capture := &logCapture{}
	pc := overflowProbe(t, capture)
	fillInbound(pc)
	pc.deliverInbound([]byte{frameData}) // overflow: stamped
	if pc.inboundFullSince.Load() == 0 {
		t.Fatal("the overflow was not stamped")
	}

	<-pc.inbound                         // the consumer catches up
	pc.deliverInbound([]byte{frameData}) // queued again: the run is over

	if got := pc.inboundFullSince.Load(); got != 0 {
		t.Fatalf("inboundFullSince = %d, want 0 after a packet was queued", got)
	}
	if pc.isClosed() {
		t.Fatal("draining and refilling killed the session")
	}
}
