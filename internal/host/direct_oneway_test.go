package host

// The direct heartbeat proves the NAT path, not the data plane. It is a 12-byte
// magic packet, written raw on the punched socket and consumed before KCP ever
// sees it, so an underlay whose heartbeats are answered is retired for no reason
// — the sticky-direct fix, and the reason an idle peer is not re-punched every
// few seconds.
//
// The blind spot that came with it: a path that answers heartbeats while its KCP
// plane is one-way dead also lives forever. That is the shape measured on a real
// phone/hub pair — the underlay and the heartbeat looked healthy for 45 minutes
// while nothing came back, and the only recovery was a human flipping the direct
// toggle. The heartbeat design doc accepted this blind spot on the grounds that
// "KCP retransmit over relay still covers it"; it does not when direct is
// preferred, which is exactly when this fires.
//
// ⑤ is the missing distinction. It cannot come from recency, because a dead path
// and a genuinely idle one show the same silence. It comes from the byte
// counters instead: the pair already partitions its datagram totals per
// underlay, and a path that is sending while receiving nothing is one-way dead.
// KCP's own acknowledgements keep the receive side moving for a healthy path,
// including one that is only uploading, so this does not retire a working
// one-directional stream.
//
// The three tests before TestDirectUnderlayOneWayDeadIsRetired are the
// false-positive guard, which matters more: a predicate that retired
// one-directional traffic would turn the sticky-direct fix into a flap.

import (
	"testing"
	"time"
)

// TestDirectOneWayDeadIgnoresAnIdlePath: a path that sends nothing and receives
// nothing is idle, not dead. Retiring it would re-punch every healthy idle pair
// on a timer — the exact churn the heartbeat exists to prevent — so silence
// alone must never satisfy the predicate.
func TestDirectOneWayDeadIgnoresAnIdlePath(t *testing.T) {
	pair := &relayKCPPair{}
	now := time.Now()

	for i := 0; i < 4; i++ {
		now = now.Add(time.Second)
		if pair.directOneWayDead(now) {
			t.Fatalf("an idle path (no traffic either way) read as one-way dead on tick %d", i)
		}
	}
}

// TestDirectOneWayDeadIgnoresAHealthyPath: a path that is sending AND receiving
// is alive whatever its direction. The peer's KCP acknowledgements move the
// receive counter even for a purely one-directional stream, which is why this is
// the healthy case and not a near-miss.
func TestDirectOneWayDeadIgnoresAHealthyPath(t *testing.T) {
	pair := &relayKCPPair{}
	now := time.Now()

	for i := 0; i < 6; i++ {
		pair.directBytesSent.Add(1024)
		pair.directBytesRcvd.Add(64) // ACKs (and any payload) coming back
		now = now.Add(time.Second)
		if pair.directOneWayDead(now) {
			t.Fatalf("a path sending and receiving read as one-way dead on tick %d", i)
		}
	}
}

// TestDirectOneWayDeadIgnoresAStoppedSender: a path that stopped sending in
// both directions is idle again, and must clear the tracker rather than
// latching. Without the clear, a burst of one-way traffic followed by silence
// would retire the pair a window later for a shape that no longer applies.
func TestDirectOneWayDeadIgnoresAStoppedSender(t *testing.T) {
	pair := &relayKCPPair{}
	now := time.Now()

	// A window of one-way traffic: sending, receiving nothing back.
	for i := 0; i < 2; i++ {
		pair.directBytesSent.Add(512)
		now = now.Add(time.Second)
	}
	// Then it goes quiet, as a peer with nothing to say does.
	for i := 0; i < 4; i++ {
		now = now.Add(time.Second)
		if pair.directOneWayDead(now) {
			t.Fatal("a path that stopped sending read as one-way dead")
		}
	}
}

// TestDirectUnderlayOneWayDead: the production shape — heartbeats answered,
// bytes leaving, nothing arriving — must be detected as one-way dead, and only
// once it has persisted. Retiring any earlier would fire on a transient gap in
// the receive counter, which a healthy path produces routinely.
func TestDirectUnderlayOneWayDead(t *testing.T) {
	pair := &relayKCPPair{}
	now := time.Now()
	defer func(w time.Duration) { directOneWayWindow = w }(directOneWayWindow)
	directOneWayWindow = 20 * time.Second

	// One tick of one-way traffic: sending, receiving nothing back.
	pair.directBytesSent.Add(2048)
	now = now.Add(time.Second)
	if pair.directOneWayDead(now) {
		t.Fatal("a one-way shape was declared dead inside the window")
	}

	// Then it keeps doing so, and the path is polled every tick the way the
	// pump polls it: the shape has to persist, and once it has, the path is
	// declared dead rather than living on for want of anyone asking.
	var dead bool
	for i := 0; i < 30 && !dead; i++ {
		pair.directBytesSent.Add(2048)
		now = now.Add(time.Second)
		dead = pair.directOneWayDead(now)
	}
	if !dead {
		t.Fatal("a one-way-dead path persisting past the window was never detected")
	}
}
