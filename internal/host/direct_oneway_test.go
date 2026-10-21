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
//
// The one-way episode is what the diagnostic reports: the span where the path
// was sending and nothing came back. It is kept as an episode (start, end,
// whether it reached the death window) rather than a latch, because the pair
// falls back to the relay exactly when the path is retired — the moment a
// reader needs the fact.

import (
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// TestDirectOneWayDeadIgnoresAnIdlePath: a path that sends nothing and receives
// nothing is idle, not dead. Retiring it would re-punch every healthy idle pair
// on a timer — the exact churn the heartbeat exists to prevent — so silence
// alone must never satisfy the predicate.
func TestDirectOneWayDeadIgnoresAnIdlePath(t *testing.T) {
	pair := &relayKCPPair{}

	for i := 0; i < 4; i++ {
		if pair.directOneWayDead(nil) {
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

	for i := 0; i < 6; i++ {
		pair.directBytesSent.Add(1024)
		pair.directBytesRcvd.Add(64) // ACKs (and any payload) coming back
		if pair.directOneWayDead(nil) {
			t.Fatalf("a path sending and receiving read as one-way dead on tick %d", i)
		}
	}
}

// TestDirectOneWayDeadIgnoresAStoppedSender: a path that stopped sending in
// both directions is idle again, and must end the episode rather than latching.
// Without the end, a burst of one-way traffic followed by silence would retire
// the pair a window later for a shape that no longer applies.
func TestDirectOneWayDeadIgnoresAStoppedSender(t *testing.T) {
	pair := &relayKCPPair{}

	// A window of one-way traffic: sending, receiving nothing back.
	for i := 0; i < 2; i++ {
		pair.directBytesSent.Add(512)
	}
	// Then it goes quiet, as a peer with nothing to say does.
	for i := 0; i < 4; i++ {
		if pair.directOneWayDead(nil) {
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
	defer func(w time.Duration) { directOneWayWindow = w }(directOneWayWindow)
	directOneWayWindow = 20 * time.Millisecond

	// One tick of one-way traffic: sending, receiving nothing back.
	pair.directBytesSent.Add(2048)
	if pair.directOneWayDead(nil) {
		t.Fatal("a one-way shape was declared dead inside the window")
	}

	// Then it keeps doing so, and the path is polled every tick the way the
	// pump polls it: the shape has to persist, and once it has, the path is
	// declared dead rather than living on for want of anyone asking.
	var dead bool
	for i := 0; i < 50 && !dead; i++ {
		pair.directBytesSent.Add(2048)
		time.Sleep(time.Millisecond)
		dead = pair.directOneWayDead(nil)
	}
	if !dead {
		t.Fatal("a one-way-dead path persisting past the window was never detected")
	}
}

// TestDirectOneWayEpisodeIsCurrentWhileHolding: while the path is one-way,
// the episode is open — it has a length and no end yet.
func TestDirectOneWayEpisodeIsCurrentWhileHolding(t *testing.T) {
	pair := &relayKCPPair{}
	defer func(w time.Duration) { directOneWayWindow = w }(directOneWayWindow)
	directOneWayWindow = time.Minute

	u := &directUnderlay{}
	pair.direct = u
	pair.directStop = make(chan struct{})

	// One-way traffic: sending, receiving nothing back.
	for i := 0; i < 3; i++ {
		pair.directBytesSent.Add(2048)
		pair.directOneWayDead(u)
		time.Sleep(time.Millisecond)
	}

	length, age := pair.directOneWayEpisode()
	if length <= 0 {
		t.Fatalf("episode length = %s, want a positive duration", length)
	}
	if age != 0 {
		t.Fatalf("episode age = %s, want 0 while the episode is still going", age)
	}
}

// TestDirectOneWayEpisodeSurvivesRetirement: the episode outlives the path.
// A peer that falls back to the relay is exactly when the reader needs to know
// the direct path was one-way, and the duration is dated (the age says when),
// so it is a fact about a moment, not a claim about a path that is still there.
func TestDirectOneWayEpisodeSurvivesRetirement(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{65}
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)
	defer func(w time.Duration) { directOneWayWindow = w }(directOneWayWindow)
	directOneWayWindow = 20 * time.Millisecond

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	t.Cleanup(func() { b.Close() })
	u := newDirectUnderlay(a, udpAddrPort(t, b))
	pair.direct = u
	pair.directStop = make(chan struct{})

	// The path goes one-way and stays that way past the window: the shape
	// mattered, it declared the path dead.
	var dead bool
	for i := 0; i < 50 && !dead; i++ {
		pair.directBytesSent.Add(2048)
		time.Sleep(time.Millisecond)
		dead = pair.directOneWayDead(u)
	}
	if !dead {
		t.Fatal("the one-way path was never declared dead")
	}

	// The path is retired: the pair falls back to the relay.
	if !pair.clearDirectUnderlayIf(u, pathChangeClear) {
		t.Fatal("the direct underlay was not retired")
	}

	length, age := pair.directOneWayEpisode()
	if length <= 0 {
		t.Fatalf("episode length = %s, want the duration it lasted", length)
	}
	if age <= 0 {
		t.Fatalf("episode age = %s, want it dated after the retirement", age)
	}
}

// TestDirectOneWayBlipIsNotReported: a one-way spell that stops before the
// death window never declared a path dead, so it is not the fact the report is
// for — it is a hiccup of the receive counter, which a healthy path produces
// routinely. Reporting it would leave the peer labelled one-way forever.
func TestDirectOneWayBlipIsNotReported(t *testing.T) {
	pair := &relayKCPPair{}
	defer func(w time.Duration) { directOneWayWindow = w }(directOneWayWindow)
	directOneWayWindow = time.Minute

	u := &directUnderlay{}
	pair.direct = u
	pair.directStop = make(chan struct{})

	pair.directBytesSent.Add(2048)
	pair.directOneWayDead(u)
	// The shape stops on the next tick: nothing moved.
	pair.directOneWayDead(u)

	length, age := pair.directOneWayEpisode()
	if length != 0 || age != 0 {
		t.Fatalf("a blip was reported as a one-way episode: length %s age %s", length, age)
	}
}

// TestDirectOneWayIgnoresARetiredUnderlay: a retiring pump can still be inside
// a tick when the underlay goes away. Its tick must not touch the episode
// state: an episode opened by a path that is already gone could never be ended
// (neither ending path knows about that underlay any more), and the report
// would say the path has been one-way forever.
func TestDirectOneWayIgnoresARetiredUnderlay(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{66}
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)
	defer func(w time.Duration) { directOneWayWindow = w }(directOneWayWindow)
	directOneWayWindow = 20 * time.Millisecond

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	t.Cleanup(func() { b.Close() })
	u := newDirectUnderlay(a, udpAddrPort(t, b))
	pair.direct = u
	pair.directStop = make(chan struct{})

	var dead bool
	for i := 0; i < 50 && !dead; i++ {
		pair.directBytesSent.Add(2048)
		time.Sleep(time.Millisecond)
		dead = pair.directOneWayDead(u)
	}
	if !dead {
		t.Fatal("the one-way path was never declared dead")
	}
	if !pair.clearDirectUnderlayIf(u, pathChangeClear) {
		t.Fatal("the direct underlay was not retired")
	}

	// The retiring pump's last tick.
	pair.directBytesSent.Add(2048)
	if pair.directOneWayDead(u) {
		t.Fatal("a retired underlay's tick declared the path one-way dead")
	}

	length, age := pair.directOneWayEpisode()
	if age == 0 {
		t.Fatal("a retired underlay's tick re-opened the episode: it reads as still going")
	}
	if length <= 0 {
		t.Fatalf("episode length = %s, want the duration it lasted", length)
	}
}

// TestDirectOneWayDoesNotDeclareANewPathDeadOnItsFirstTick: a path that
// replaces a one-way-dead one starts its own episode. The old latch used to
// survive the replacement, so the new path's first one-way tick was judged
// against the OLD timestamp and the path was declared dead immediately — the
// sticky episode ends the old one, so the new path gets a fresh window.
func TestDirectOneWayDoesNotDeclareANewPathDeadOnItsFirstTick(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{67}
	pair := e.relayKCPPairFor(peer)
	t.Cleanup(pair.shutdown)
	defer func(w time.Duration) { directOneWayWindow = w }(directOneWayWindow)
	directOneWayWindow = 20 * time.Millisecond

	a := mustListenUDP(t)
	b := mustListenUDP(t)
	t.Cleanup(func() { b.Close() })
	u1 := newDirectUnderlay(a, udpAddrPort(t, b))
	pair.direct = u1
	pair.directStop = make(chan struct{})

	// The first path goes one-way and stays that way past the window.
	var dead bool
	for i := 0; i < 50 && !dead; i++ {
		pair.directBytesSent.Add(2048)
		time.Sleep(time.Millisecond)
		dead = pair.directOneWayDead(u1)
	}
	if !dead {
		t.Fatal("the one-way path was never declared dead")
	}

	// A fresh path replaces it, and is one-way for a moment.
	c := mustListenUDP(t)
	d := mustListenUDP(t)
	t.Cleanup(func() { d.Close() })
	u2 := newDirectUnderlay(c, udpAddrPort(t, d))
	pair.setDirectUnderlay(u2)

	pair.directBytesSent.Add(2048)
	if pair.directOneWayDead(u2) {
		t.Fatal("the new path was declared one-way dead on its first tick, judged against the replaced path's timestamp")
	}
}
