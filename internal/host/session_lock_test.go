package host

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/xtaci/kcp-go/v5"
)

// TestUnderlayDeadKeepsInFlightRound pins the underlay-death fix: a punch round
// already in flight owns dc.mine, so a dying underlay must not clear it (that
// stops this side answering the peer's announcements), and must not reset the
// state to directNone (that let a second round start on the same candidate
// channel). Only an underlay that itself owned the state (directUp) hands the
// re-punch back.
func TestUnderlayDeadKeepsInFlightRound(t *testing.T) {
	own := []candidate{{addr: netip.MustParseAddrPort("203.0.113.7:2222")}}

	// A round is in flight: state and mine must survive the underlay's death.
	dc := newSlotConn(t)
	sock := mustListenUDP(t)
	dc.mu.Lock()
	dc.sock, dc.mine, dc.state = sock, own, directAttempting
	dc.mu.Unlock()

	dc.underlayDead(&directUnderlay{sock: sock})

	dc.mu.Lock()
	mine, state, drops := dc.mine, dc.state, dc.drops.Load()
	dc.mu.Unlock()
	if state != directAttempting {
		t.Fatalf("state = %v after underlay death, want directAttempting (round left to finish)", state)
	}
	if len(mine) != 1 || mine[0].addr != own[0].addr {
		t.Fatalf("mine = %v after underlay death, want the in-flight round's candidates kept", candAddrs(mine))
	}
	if drops != 0 {
		t.Fatalf("drops = %d, want 0: the round, not the underlay, owns the state", drops)
	}

	// An underlay that owned directUp hands the re-punch back and clears state.
	dc2 := newSlotConn(t)
	sock2 := mustListenUDP(t)
	dc2.mu.Lock()
	dc2.sock, dc2.mine, dc2.state = sock2, own, directUp
	dc2.mu.Unlock()

	dc2.underlayDead(&directUnderlay{sock: sock2})

	dc2.mu.Lock()
	got2, mine2, state2, drops2 := dc2.sock, dc2.mine, dc2.state, dc2.drops.Load()
	dc2.mu.Unlock()
	if got2 != nil || mine2 != nil {
		t.Fatalf("directUp death left sock=%v mine=%v, want nil/nil", got2, candAddrs(mine2))
	}
	if state2 == directUp {
		t.Fatalf("state = %v after a directUp death, want the re-punch scheduled", state2)
	}
	if drops2 != 1 {
		t.Fatalf("drops = %d, want 1", drops2)
	}
}

// TestEnsureSessionNoLockInversion drives the two writers of a peerConn's
// session state at once: peerConn takes e.mu then pc.mu, while ensureSession
// takes pc.mu, releases it, and only then (via maybeStartDirect) takes e.mu.
// With the punch started under pc.mu — where it used to be — these two invert
// and deadlock, so a bounded completion here is the regression guard for the
// lock-order fix. Run under -race, it also covers the pc.sess race the pump's
// unguarded call used to produce.
func TestEnsureSessionNoLockInversion(t *testing.T) {
	e := newTestEngine(t)
	e.stunAddr = "127.0.0.1:3478" // makes directEnabled true, so the punch path takes e.mu
	peer := derpclient.PublicKey{7}

	// A live session and a backed-off punch: the loop then only exercises the
	// locking, not session or punch creation.
	pc := e.peerConn(peer)
	pc.mu.Lock()
	pc.sess = newTestSess(t)
	pc.sessAt = time.Now()
	pc.mu.Unlock()
	dc := e.directConn(peer)
	dc.mu.Lock()
	dc.state = directBackoff
	dc.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			e.peerConn(peer) // e.mu -> pc.mu
		}
	}()
	for i := 0; i < 500; i++ {
		pc.ensureSession(true, true) // pc.mu, released, then e.mu
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("peerConn + ensureSession deadlocked: lock order inverted")
	}
}

// TestRelaySessionChurnReconnectsRelay: a pair whose packets the relay stopped
// routing rebuilds its session every keepalive timeout, forever, while the
// shared connection stays busy with every other peer — the one shape the
// connection-level silence check cannot see (frames still arrive; they are just
// not this pair's). The engine tears the transport down itself, because the
// stale registration that caused it is cleared by nothing smaller.
func TestRelaySessionChurnReconnectsRelay(t *testing.T) {
	defer func(w time.Duration, m int) { relayChurnWindow, relayChurnMax = w, m }(relayChurnWindow, relayChurnMax)
	relayChurnWindow, relayChurnMax = time.Minute, 2

	rs := &relayServer{}
	url := rs.start(t)
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(url, "", priv, slog.Default())
	defer e.Close()
	e.Connect()
	if !e.relayConnected() {
		t.Fatal("engine did not connect to the test relay")
	}

	// A real, registered peer: it answers the relay-session handshake. A
	// fabricated key would make the relay answer our handshake with PeerGone (it
	// reports one for a key it does not hold, like derper's ReasonNotHere), which
	// kills the adapter between builds and defeats the churn accounting here.
	privB, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	eB := newEngine(url, "", privB, slog.Default())
	defer eB.Close()
	if err := eB.Connect(); err != nil {
		t.Fatal(err)
	}

	pc := e.peerConn(eB.pub)
	// One build more than the window allows, each preceded by killing the
	// session it would have reused: rebuild after rebuild, as a pair left
	// un-routed looks from here.
	for i := 0; i <= relayChurnMax; i++ {
		if i > 0 {
			// Exactly what sessionLocked leaves behind when it finds the
			// session dead. Closing the live session directly hangs here: smux
			// retires a session by handing its error to the read loop, and that
			// loop is parked reading pc.inbound through the KCP underlay
			// (relayPacketConn.ReadFrom), which nothing has woken. This test is
			// about the churn accounting, not that path.
			pc.mu.Lock()
			pc.sess = nil
			pc.mu.Unlock()
		}
		if _, err := pc.ensureSession(false, true); err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
	}

	if e.relayConnected() {
		t.Fatal("a churned peer did not take the relay down with it")
	}
	// One-shot: the count is cleared, so a later window can trip again.
	pc.mu.Lock()
	churn, tripped := pc.churn, pc.churnTripped
	pc.mu.Unlock()
	if churn != 0 || tripped {
		t.Fatalf("after the trip: churn=%d tripped=%v, want 0/false", churn, tripped)
	}
}

// TestRelaySessionReplaceRehandshakes pins the epoch-ending half of the rule in
// dropRelaySecure: a kill whose reason ends the pair's epoch (here, the record
// framing desynced past the backstop) drops the keys, so the replacement
// adapter must re-handshake on a fresh secure session instead of reusing the
// cached one. Reuse fails every rebuilt session's first record from then on —
// the production loop that churned a new session every 15s until restart. A
// clean kill no longer re-handshakes (the KCP underlay retransmits a queued
// segment), so the desync backstop is the local path that still does.
func TestRelaySessionReplaceRehandshakes(t *testing.T) {
	eA, eB, _ := newEncryptedPair(t)

	// A and B establish a relay session and carry traffic both ways, so the
	// pair's key holds live counters when the reset hits.
	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn, "before")
	conn.Close()

	pc := eA.peerConn(eB.pub)
	pc.mu.Lock()
	old := pc.secure
	pc.mu.Unlock()

	// The pair's record framing desyncs past the backstop: the callback drops
	// the keys and kills the adapter (see armDesyncRecovery), so the replacement
	// must re-handshake. This is the KCP-era successor to "a kill abandons
	// queued records": the queue no longer carries unrecoverable nonce state, so
	// a record-boundary failure is the local abandonment that is left.
	for i := 0; i < secureDesyncThreshold; i++ {
		old.noteDesync()
	}
	waitFor(t, 2*time.Second, func() bool {
		pc.mu.Lock()
		defer pc.mu.Unlock()
		return pc.closed
	})

	// The replacement adapter must borrow a fresh secure session: the cached
	// one is dropped so the rebuild re-handshakes (see dropRelaySecure).
	pc2 := eA.peerConn(eB.pub)
	pc2.mu.Lock()
	rebuilt := pc2.secure
	pc2.mu.Unlock()
	if rebuilt == old {
		t.Fatal("replacement adapter reused the killed adapter's secure session")
	}
	if _, err := pc2.ensureSession(false, true); err != nil {
		t.Fatal(err)
	}

	// Both ends settle again on the fresh key within the handshake bound, and
	// the pair carries data again.
	waitFor(t, handshakeTimeout, func() bool {
		return eA.peerSecureForTest(eB.pub) && eB.peerSecureForTest(eA.pub)
	})
	waitFor(t, 10*time.Second, func() bool {
		conn, err := eA.OpenStream(eB.PublicKey())
		if err != nil {
			return false
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("after")); err != nil {
			return false
		}
		buf := make([]byte, len("after"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return false
		}
		return string(buf) == "after"
	})
}

// TestRelaySessionReplaceDeadSessionKeepsKeys pins the session-replacement half
// of the same rule under the KCP underlay: when a dead mux session is replaced
// on a live adapter (the smux keepalive timeout starved it and nothing killed
// the adapter), the rebuild keeps the settled keys — it is transparent. A
// queued packet is a KCP segment the peer retransmits, not an abandoned record,
// so nothing is re-handshaken. This is the path that does not pass through
// pc.kill.
func TestRelaySessionReplaceDeadSessionKeepsKeys(t *testing.T) {
	eA, eB, _ := newEncryptedPair(t)

	// B's adapter up front: the half exchange below settles B's security
	// session, and the assertions read it through the adapter.
	eB.peerConn(eA.pub)

	pc := eA.peerConn(eB.pub)
	pc.mu.Lock()
	old := pc.secure
	pc.mu.Unlock()

	// Settle the pair's key with a plain half exchange with B, so the cached
	// session is a settled one the rebuild reuses. No mux session exists yet, so
	// the swap below has nothing else to displace.
	if err := eA.sendSecureHalf(eB.pub, old); err != nil {
		t.Fatal(err)
	}
	waitFor(t, handshakeTimeout, func() bool { return old.settled() })

	// A dead smux session standing in for one that expired in place: closed,
	// but built over its own pipe instead of this adapter's underlay, so the
	// adapter stays live — exactly the state the replacement branch sees. The
	// queued segment is in flight when the session dies, and under KCP it is
	// retransmitted, not abandoned, so the replacement reuses the settled
	// session.
	dead := newTestSess(t)
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}
	pc.inbound <- []byte("segment in flight when the session died")
	pc.mu.Lock()
	pc.sess, pc.sessAt = dead, time.Now()
	pc.mu.Unlock()

	if _, err := pc.ensureSession(false, true); err != nil {
		t.Fatal(err)
	}

	pc.mu.Lock()
	rebuilt := pc.secure
	pc.mu.Unlock()
	if rebuilt != old {
		t.Fatal("session replacement re-handshook; the pair's settled keys must be reused")
	}

	// The pair carries data again over the same keys.
	waitFor(t, 10*time.Second, func() bool {
		conn, err := eA.OpenStream(eB.PublicKey())
		if err != nil {
			return false
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("after")); err != nil {
			return false
		}
		buf := make([]byte, len("after"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return false
		}
		return string(buf) == "after"
	})
}

// logCapture is a slog.Handler that keeps every record, so a test can assert on
// the structured fields the field diagnosis reads a session's death off.
type logCapture struct {
	mu       sync.Mutex
	messages []string
	attrs    [][]slog.Attr
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	c.mu.Lock()
	c.messages = append(c.messages, r.Message)
	c.attrs = append(c.attrs, attrs)
	c.mu.Unlock()
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

// nth returns the attributes of the i-th record with the given message, or nil.
// Indexed because the same message is emitted more than once across a scenario
// (a second kill, a second rebuild) and each occurrence carries its own fields.
func (c *logCapture) nth(msg string, i int) map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for n, m := range c.messages {
		if m != msg {
			continue
		}
		if i > 0 {
			i--
			continue
		}
		out := make(map[string]string, len(c.attrs[n]))
		for _, a := range c.attrs[n] {
			out[a.Key] = a.Value.String()
		}
		return out
	}
	return nil
}

// TestSessionDeathLogCarriesReasonAndSecureReuse pins the fields the field
// diagnosis reads a session's death off. The production symptom was a session
// rebuilt every 15s with no way to tell what killed it or whether it kept its
// keys — so every kill names a reason from a closed set, and every replacement
// states whether the pair re-handshaked. These are also the fields the e2e
// regression greps, so they must not silently change shape.
func TestSessionDeathLogCarriesReasonAndSecureReuse(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	// An epoch-ending kill (the relay link was lost) drops the keys, so the log
	// reports the effective dropSecure=true.
	dropping := derpclient.PublicKey{3}
	inbound := make(chan []byte, 1)
	inbound <- []byte("segment in flight at kill time")
	pc := &peerConn{e: e, peer: dropping, inbound: inbound, closeCh: make(chan struct{})}
	pc.sessAt = time.Now().Add(-3 * time.Second)
	pc.killSession(errors.New("test: link lost"), true, reasonLinkLost)

	attrs := capture.nth("peer session killed", 0)
	if attrs == nil {
		t.Fatal("killSession logged no \"peer session killed\" record")
	}
	if got := attrs["relayReason"]; got != string(reasonLinkLost) {
		t.Fatalf("relayReason = %q, want %q", got, reasonLinkLost)
	}
	if got := attrs["dropSecure"]; got != "true" {
		t.Fatalf("dropSecure = %q, want \"true\": the link-loss kill drops the keys", got)
	}
	if attrs["cause"] == "" {
		t.Fatal("the kill log carries no cause")
	}
	if attrs["sessionAge"] == "" {
		t.Fatal("the kill log carries no sessionAge")
	}

	// A clean kill keeps its keys even with a segment in flight, and dropSecure
	// is the EFFECTIVE value — it is what explains the next rebuild reusing its
	// keys, so it is the reason, not the queue, that decides.
	clean := derpclient.PublicKey{4}
	inbound2 := make(chan []byte, 1)
	inbound2 <- []byte("segment in flight at kill time")
	pc2 := &peerConn{
		e:       e,
		peer:    clean,
		inbound: inbound2,
		closeCh: make(chan struct{}),
	}
	pc2.sessAt = time.Now()
	pc2.killSession(errors.New("test: clean kill"), true, reasonLocalKill)
	attrs = capture.nth("peer session killed", 1)
	if got := attrs["relayReason"]; got != string(reasonLocalKill) {
		t.Fatalf("relayReason = %q, want %q", got, reasonLocalKill)
	}
	if got := attrs["dropSecure"]; got != "false" {
		t.Fatalf("dropSecure = %q, want \"false\": a clean kill keeps its keys even with data in flight", got)
	}
}

// TestSessionRebuildLogReportsReuseAndStreak pins the rebuild half of the same
// diagnostic: a replacement that abandoned nothing reuses the settled security
// session (secureReuse=true — what a healthy rebuild looks like), and one that
// abandoned records re-handshakes (secureReuse=false), reporting the streak
// that explains why.
func TestSessionRebuildLogReportsReuseAndStreak(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	// Dead session, nothing abandoned: the rebuild keeps its keys.
	reusedPeer := derpclient.PublicKey{5}
	reusedSess := newSecureSession(nil, secureTransportRelay, priv, reusedPeer)
	dead := newTestSess(t)
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}
	pc := &peerConn{
		e:       e,
		peer:    reusedPeer,
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
		secure:  reusedSess,
		sess:    dead,
		sessAt:  time.Now().Add(-2 * time.Second),
	}
	pc.ensureSession(false, false) // the log line is emitted before the build

	attrs := capture.nth("relay session rebuilt", 0)
	if attrs == nil {
		t.Fatal("a replaced session logged no \"relay session rebuilt\" record")
	}
	if got := attrs["secureReuse"]; got != "true" {
		t.Fatalf("secureReuse = %q, want \"true\": nothing was abandoned, so the keys are intact", got)
	}
	if attrs["sessionAge"] == "" {
		t.Fatal("the rebuild log carries no sessionAge")
	}

	// Dead session with a streak on the outgoing keys: under the KCP underlay
	// the replacement is still transparent (the pair's KCP stream survives, so
	// the keys stay aligned), and the streak is reported as the diagnostic that
	// explains the session's state. No re-handshake is forced.
	desyncPeer := derpclient.PublicKey{6}
	desyncSess := newSecureSession(nil, secureTransportRelay, priv, desyncPeer)
	if got := desyncSess.noteDesync(); got != 1 {
		t.Fatalf("priming the streak: got %d, want 1", got)
	}
	if got := desyncSess.noteDesync(); got != 2 {
		t.Fatalf("priming the streak: got %d, want 2", got)
	}
	dead2 := newTestSess(t)
	if err := dead2.Close(); err != nil {
		t.Fatal(err)
	}
	inbound := make(chan []byte, 1)
	inbound <- []byte("segment in flight when the session died")
	pc2 := &peerConn{
		e:       e,
		peer:    desyncPeer,
		inbound: inbound,
		closeCh: make(chan struct{}),
		secure:  desyncSess,
		sess:    dead2,
		sessAt:  time.Now().Add(-2 * time.Second),
	}
	pc2.ensureSession(false, false)

	attrs = capture.nth("relay session rebuilt", 1)
	if attrs == nil {
		t.Fatal("a replaced session logged no \"relay session rebuilt\" record")
	}
	if got := attrs["secureReuse"]; got != "true" {
		t.Fatalf("secureReuse = %q, want \"true\": a replaced session keeps its keys under KCP", got)
	}
	if got := attrs["desyncStreak"]; got != "2" {
		t.Fatalf("desyncStreak = %q, want \"2\": the replaced session's streak is the diagnostic", got)
	}
}

// TestKillLogSessionAgeZeroForUnbuiltAdapter pins that a kill on an adapter that
// never built a session reports a zero age. time.Since on a zero sessAt is the
// time since year 1, which is what the e2e showed:
// sessionAge=2562047h47m16.854775807s.
func TestKillLogSessionAgeZeroForUnbuiltAdapter(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	pc := e.peerConn(derpclient.PublicKey{9})
	pc.killSession(errors.New("test: kill before any session"), true, reasonLocalKill)

	attrs := capture.nth("peer session killed", 0)
	if attrs == nil {
		t.Fatal("killSession logged no \"peer session killed\" record")
	}
	if got := attrs["sessionAge"]; got != "0s" {
		t.Fatalf("sessionAge = %q, want \"0s\" for an adapter that never built a session", got)
	}
}

// TestRelayRebuildLogFiresOnFreshAdapter pins WHERE a rebuild is logged.
// killSession CLOSES the adapter, so the next build is a brand-new peerConn
// whose pc.sess is nil — the in-place branch in ensureSession never runs on that
// path. Logging the rebuild only there emitted nothing: a full e2e run showed
// `relay session rebuilt = 0` against `peer session killed = 4`, so secureReuse
// was never reported and the e2e gate had no field to grep.
func TestRelayRebuildLogFiresOnFreshAdapter(t *testing.T) {
	capture := &logCapture{}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("", "", priv, slog.New(capture))
	t.Cleanup(e.Close)

	// A clean kill keeps the keys, so the replacement reuses them. The queued
	// segment does not change that: it is retransmitted, not abandoned.
	reused := derpclient.PublicKey{7}
	pc1 := e.peerConn(reused)
	pc1.inbound <- []byte("segment in flight at kill time")
	pc1.killSession(errors.New("test: clean kill"), true, reasonLocalKill)
	pc2 := e.peerConn(reused)
	if pc2 == pc1 {
		t.Fatal("a closed adapter was handed back instead of a replacement")
	}
	attrs := capture.nth("relay session rebuilt", 0)
	if attrs == nil {
		t.Fatal("replacing a killed adapter logged no \"relay session rebuilt\" record")
	}
	if got := attrs["secureReuse"]; got != "true" {
		t.Fatalf("secureReuse = %q, want \"true\": a clean kill keeps the settled keys", got)
	}

	// An epoch-ending kill drops them, so the replacement must re-handshake.
	dropped := derpclient.PublicKey{8}
	pc3 := e.peerConn(dropped)
	pc3.killSession(errors.New("test: link lost"), true, reasonLinkLost)
	e.peerConn(dropped)

	attrs = capture.nth("relay session rebuilt", 1)
	if attrs == nil {
		t.Fatal("the second rebuild logged no \"relay session rebuilt\" record")
	}
	if got := attrs["secureReuse"]; got != "false" {
		t.Fatalf("secureReuse = %q, want \"false\": an epoch-ending kill dropped the keys", got)
	}
}

// count returns how many records carry the given message.
func (c *logCapture) count(msg string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, m := range c.messages {
		if m == msg {
			n++
		}
	}
	return n
}

// pairKCPSession returns the pair's current KCP session from the pair store —
// the epoch identity, independent of any adapter's view of it.
func pairKCPSession(e *engine, peer derpclient.PublicKey) *kcp.UDPSession {
	e.kcpMu.Lock()
	pair := e.relayKCPs[peer]
	e.kcpMu.Unlock()
	if pair == nil {
		return nil
	}
	pair.mu.Lock()
	defer pair.mu.Unlock()
	return pair.sess
}

// TestRelayCleanKillKeepsPairKCPAndRecovers pins the pair-level KCP session: a
// clean kill (nothing abandoned, keys kept) must leave the pair's KCP session
// running across the adapter swap, so the rebuilt mux session continues the
// pair's sequence epoch instead of restarting at sn=0 under a peer whose
// session is still running. That one-sided reset is the livelock this fixes:
// kcp-go buffers the peer's advanced segments as out-of-order holes and ACKs
// them, and the secure counters keep the peer's smux from ever timing out.
func TestRelayCleanKillKeepsPairKCPAndRecovers(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, echo, privA, slog.Default()) // A answers inbound
	engineB := newEngine(url, "", privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	engineA.Connect()
	engineB.Connect()

	// First inbound stream: A builds its adapter from the packet pump alone.
	s, err := engineB.OpenStream(keyName(pubA))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()
	waitFor(t, 5*time.Second, func() bool {
		engineA.mu.Lock()
		_, ok := engineA.peers[pubB]
		engineA.mu.Unlock()
		return ok
	})

	// Snapshot the pair state a clean kill must preserve.
	pcA1 := engineA.livePeerConn(pubB)
	pcA1.mu.Lock()
	kcpA1, secureA1 := pcA1.kcp, pcA1.secure
	pcA1.mu.Unlock()
	if kcpA1 == nil {
		t.Fatal("A's session was built without a KCP underlay")
	}
	pcB1 := engineB.livePeerConn(pubA)
	pcB1.mu.Lock()
	kcpB1 := pcB1.kcp
	pcB1.mu.Unlock()

	// Mute the relay so no KCP segment is in flight across the kill: the kill
	// must deterministically be the clean one (nothing abandoned), which is the
	// case under test.
	rs.setDropData(true)
	time.Sleep(50 * time.Millisecond)
	pcA1.killSession(errors.New("test: clean kill"), true, reasonLocalKill)
	if n := len(pcA1.inbound); n != 0 {
		t.Fatalf("the kill was not clean: %d packets still queued", n)
	}

	// The pair's KCP session outlives the adapter it was built on.
	engineA.kcpMu.Lock()
	pairA := engineA.relayKCPs[pubB]
	engineA.kcpMu.Unlock()
	if pairA == nil {
		t.Fatal("the clean kill dropped the pair's KCP holder")
	}
	pairA.mu.Lock()
	pairSess := pairA.sess
	pairA.mu.Unlock()
	if pairSess != kcpA1 {
		t.Fatal("the clean kill replaced the pair's KCP session, restarting its sequence epoch")
	}

	// The peer's next inbound stream is still served, over the same session.
	rs.setDropData(false)
	s2, err := engineB.OpenStream(keyName(pubA))
	if err != nil {
		t.Fatalf("inbound open after the clean kill: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "recovered")

	// The replacement adapter continues the pair: same KCP session, same keys.
	pcA2 := engineA.livePeerConn(pubB)
	if pcA2 == pcA1 {
		t.Fatal("the killed adapter was handed back instead of a replacement")
	}
	pcA2.mu.Lock()
	kcpA2, secureA2 := pcA2.kcp, pcA2.secure
	pcA2.mu.Unlock()
	if kcpA2 != kcpA1 {
		t.Fatal("the rebuild did not continue the pair's KCP session")
	}
	if secureA2 != secureA1 {
		t.Fatal("the clean kill dropped the pair's settled keys")
	}
	// B was never touched: its session is the one it started with.
	pcB2 := engineB.livePeerConn(pubA)
	pcB2.mu.Lock()
	kcpB2 := pcB2.kcp
	pcB2.mu.Unlock()
	if kcpB2 != kcpB1 {
		t.Fatal("B's KCP session changed although B was never touched")
	}
}

// TestRelayCleanKillWithDataInFlightKeepsSecureHalf pins the KCP-era
// abandonment decision: a clean kill that happens with relay data in flight
// (segments still queued in the adapter) must keep the pair's settled keys and
// its KCP session, so the rebuild is transparent — no re-handshake, no epoch
// reset, secureReuse=true in the accounting. Before the KCP underlay a queued
// packet was a secure record whose nonce the peer had already spent, so a
// non-empty queue forced the abandoning class (drop the secure half, pay a
// re-handshake). Under KCP a queued packet is a segment the peer retransmits,
// so the same kill is clean and the pair carries on — this test fails on the
// byte-queue decision and passes on the reason-driven one.
func TestRelayCleanKillWithDataInFlightKeepsSecureHalf(t *testing.T) {
	capture := &logCapture{}
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, echo, privA, slog.New(capture)) // A answers inbound
	engineB := newEngine(url, "", privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	engineA.Connect()
	engineB.Connect()

	// First inbound stream: A builds its adapter from the packet pump alone.
	s, err := engineB.OpenStream(keyName(pubA))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()
	waitFor(t, 5*time.Second, func() bool {
		engineA.mu.Lock()
		_, ok := engineA.peers[pubB]
		engineA.mu.Unlock()
		return ok
	})

	// Snapshot the pair state a clean kill must preserve.
	pcA1 := engineA.livePeerConn(pubB)
	pcA1.mu.Lock()
	kcpA1, secureA1 := pcA1.kcp, pcA1.secure
	pcA1.mu.Unlock()
	if kcpA1 == nil {
		t.Fatal("A's session was built without a KCP underlay")
	}

	// Queue relay segments in the adapter so the kill happens with data in
	// flight: under the old byte-stream accounting a non-empty queue was the
	// "abandoned records" signal that dropped the keys. The segments are
	// garbage to the pair's KCP session (it drops a mismatched conversation
	// id), which is exactly the "garbage belonging to the dying mux session"
	// the clean path is allowed to discard.
	rs.setDropData(true) // stop real traffic so the queue stays as we filled it
	time.Sleep(50 * time.Millisecond)
	seg := bytes.Repeat([]byte{0}, 32)
	for i := 0; i < inboundQueueSize; i++ {
		pcA1.inbound <- seg
	}
	if n := len(pcA1.inbound); n == 0 {
		t.Fatal("the adapter's queue drained before the kill; the test needs data in flight")
	}

	pcA1.killSession(errors.New("test: clean kill"), true, reasonLocalKill)

	// The kill was clean even with data in flight: the log reports no secure
	// drop (the byte queue no longer decides the abandoning class).
	if attrs := capture.nth("peer session killed", 0); attrs == nil || attrs["dropSecure"] != "false" {
		t.Fatalf("dropSecure = %v, want \"false\": a clean kill with data in flight keeps its keys", logField(attrs, "dropSecure"))
	}

	// The pair's KCP session outlives the adapter it was built on.
	engineA.kcpMu.Lock()
	pairA := engineA.relayKCPs[pubB]
	engineA.kcpMu.Unlock()
	if pairA == nil {
		t.Fatal("the clean kill dropped the pair's KCP holder")
	}
	pairA.mu.Lock()
	pairSess := pairA.sess
	pairA.mu.Unlock()
	if pairSess != kcpA1 {
		t.Fatal("the clean kill replaced the pair's KCP session, restarting its sequence epoch")
	}

	// The peer's next inbound stream is still served, over the same session.
	rs.setDropData(false)
	s2, err := engineB.OpenStream(keyName(pubA))
	if err != nil {
		t.Fatalf("inbound open after the clean kill: %v", err)
	}
	defer s2.Close()
	roundTrip(t, s2, "recovered")

	// The replacement adapter continues the pair: same KCP session, same keys,
	// and the rebuild accounting says the keys were reused.
	pcA2 := engineA.livePeerConn(pubB)
	if pcA2 == pcA1 {
		t.Fatal("the killed adapter was handed back instead of a replacement")
	}
	pcA2.mu.Lock()
	kcpA2, secureA2 := pcA2.kcp, pcA2.secure
	pcA2.mu.Unlock()
	if kcpA2 != kcpA1 {
		t.Fatal("the rebuild did not continue the pair's KCP session")
	}
	if secureA2 != secureA1 {
		t.Fatal("the clean kill dropped the pair's settled keys")
	}
	if attrs := capture.nth("relay session rebuilt", 0); attrs == nil || attrs["secureReuse"] != "true" {
		t.Fatalf("secureReuse = %v, want \"true\": a clean kill with data in flight reuses its keys", logField(attrs, "secureReuse"))
	}
}

// logField returns the named attribute's value, or "<absent>" for the failure
// message when the attribute (or the record) is missing.
func logField(attrs map[string]string, key string) string {
	if attrs == nil {
		return "<no record>"
	}
	if v, ok := attrs[key]; ok {
		return v
	}
	return "<absent>"
}

// TestRelayKCPClosedOnRekeyAndLinkLoss pins the other half of the lifecycle: a
// kill that ends the pair's epoch (the peer restarted, or the relay link
// carrying the session died) must close the pair's KCP session, and the next
// build starts a fresh one — same conv, both ends' sequence numbers aligned
// from 0 again.
func TestRelayKCPClosedOnRekeyAndLinkLoss(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reason     sessionEndReason
		dropSecure bool
	}{
		{"rekey", reasonPeerRekeyed, false},
		{"link-loss", reasonLinkLost, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eA, eB, rs := newEncryptedPair(t)

			// Both sides build a session, so both hold a pair-level KCP.
			pcA := eA.peerConn(eB.pub)
			if _, err := pcA.ensureSession(false, true); err != nil {
				t.Fatal(err)
			}
			pcB := eB.peerConn(eA.pub)
			if _, err := pcB.ensureSession(false, true); err != nil {
				t.Fatal(err)
			}
			pcA.mu.Lock()
			kcpA1 := pcA.kcp
			pcA.mu.Unlock()
			pcB.mu.Lock()
			kcpB1 := pcB.kcp
			pcB.mu.Unlock()
			if kcpA1 == nil || kcpB1 == nil {
				t.Fatal("a side was built without a KCP underlay")
			}

			// Quiet the relay so the kills are the clean kind (nothing
			// abandoned): what is under test is the reason's classification,
			// not the race. The end of a pair's epoch resets BOTH ends (a
			// restarted peer's sequence numbers start over; a lost link ends the
			// session for both), so the rebuild below is the convergent shape.
			rs.setDropData(true)
			time.Sleep(50 * time.Millisecond)
			pcA.killSession(errors.New("test: "+tc.name), tc.dropSecure, tc.reason)
			pcB.killSession(errors.New("test: "+tc.name), tc.dropSecure, tc.reason)

			rebuild := func(name string, e *engine, peer derpclient.PublicKey, old *kcp.UDPSession) {
				t.Helper()
				e.kcpMu.Lock()
				pair := e.relayKCPs[peer]
				e.kcpMu.Unlock()
				if pair != nil {
					pair.mu.Lock()
					live := pair.sess
					pair.mu.Unlock()
					if live != nil {
						t.Fatalf("%s: the %s kill left the pair's KCP session alive", name, tc.name)
					}
				}
				pc := e.peerConn(peer)
				if _, err := pc.ensureSession(false, true); err != nil {
					t.Fatalf("%s: rebuild after %s: %v", name, tc.name, err)
				}
				pc.mu.Lock()
				fresh := pc.kcp
				pc.mu.Unlock()
				if fresh == nil || fresh == old {
					t.Fatalf("%s: the rebuild did not create a fresh KCP session", name)
				}
				if fresh.GetConv() != old.GetConv() {
					t.Fatalf("%s: conv changed across the rebuild", name)
				}
			}
			rs.setDropData(false)
			rebuild("A", eA, eB.pub, kcpA1)
			rebuild("B", eB, eA.pub, kcpB1)

			// Both ends restarted their sequence numbers together: the pair
			// carries data again.
			conn, err := eA.OpenStream(eB.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			roundTrip(t, conn, "after "+tc.name)
		})
	}
}

// TestRelayKCPRebuildConvergesOnce pins the recovery shape (Review Focus 2):
// one clean kill is exactly one rebuild — the pair converges on the surviving
// KCP session at once, and the recovery window shows no second kill, no second
// rebuild, and no livelock (the storm the one-sided epoch reset used to cause).
func TestRelayKCPRebuildConvergesOnce(t *testing.T) {
	capture := &logCapture{}
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, echo, privA, slog.New(capture))
	engineB := newEngine(url, "", privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	engineA.Connect()
	engineB.Connect()

	s, err := engineB.OpenStream(keyName(pubA))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "hi")
	s.Close()
	waitFor(t, 5*time.Second, func() bool {
		engineA.mu.Lock()
		_, ok := engineA.peers[pubB]
		engineA.mu.Unlock()
		return ok
	})

	rs.setDropData(true)
	time.Sleep(50 * time.Millisecond)
	pc := engineA.livePeerConn(pubB)
	pc.killSession(errors.New("test: clean kill"), true, reasonLocalKill)
	rs.setDropData(false)

	s2, err := engineB.OpenStream(keyName(pubA))
	if err != nil {
		t.Fatalf("inbound open after the clean kill: %v", err)
	}
	roundTrip(t, s2, "recovered")
	s2.Close()

	// Exactly one rebuild for the one kill.
	pc2 := engineA.livePeerConn(pubB)
	if pc2 == pc {
		t.Fatal("the killed adapter was handed back instead of a replacement")
	}
	if got := pc2.relayRebuilds.Load(); got != 1 {
		t.Fatalf("relayRebuilds = %d after one clean kill, want 1", got)
	}

	// ... and nothing more: a quiet window must show no second kill, no second
	// rebuild, and the pair still carrying data afterwards.
	time.Sleep(2 * time.Second)
	if got := capture.count("peer session killed"); got != 1 {
		t.Fatalf("peer session killed = %d in the recovery window, want 1", got)
	}
	if got := capture.count("relay session rebuilt"); got != 1 {
		t.Fatalf("relay session rebuilt = %d in the recovery window, want 1", got)
	}
	conn, err := engineB.OpenStream(keyName(pubA))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "still up")
	if got := pc2.relayRebuilds.Load(); got != 1 {
		t.Fatalf("relayRebuilds = %d after the recovery window, want 1 (no rebuild storm)", got)
	}
}

// TestRelayOneSidedEpochResetRecovers pins how a ONE-SIDED pair-epoch reset
// coordinates with the peer. A resets its KCP epoch and its keys — the
// record-boundary desync backstop — while B is untouched. The changed secure
// half is the reset signal: it rides control frames, which no KCP epoch can
// affect, and B must end its own epoch when it sees it (resetPeerSession),
// before its answer lets A build. The peer-between-adapters shape is where that
// signal lands on an adapter that is already dead: the reset must still reach
// the pair's KCP session there, or B rebuilds on the advanced epoch and
// discards A's fresh session's segments (the mismatch this task exists to
// kill). A clean kill is no longer a one-sided reset — under KCP it keeps both
// the keys and the pair's epoch, so the desync backstop is the remaining
// one-sided trigger.
func TestRelayOneSidedEpochResetRecovers(t *testing.T) {
	resets := []struct {
		name  string
		reset func(t *testing.T, eA, eB *engine)
	}{
		{"desync", func(t *testing.T, eA, eB *engine) {
			pcA := eA.peerConn(eB.pub)
			pcA.mu.Lock()
			sec := pcA.secure
			pcA.mu.Unlock()
			for i := 0; i < secureDesyncThreshold; i++ {
				sec.noteDesync()
			}
		}},
	}
	peerStates := []struct {
		name string
		prep func(t *testing.T, eB, eA *engine, rs *relayServer)
	}{
		{"peer-live", func(t *testing.T, eB, eA *engine, rs *relayServer) {}},
		{"peer-between-adapters", func(t *testing.T, eB, eA *engine, rs *relayServer) {
			// B's adapter is dead but its pair KCP session runs on (a clean
			// kill leaves it): the peer's reset signal then lands on an adapter
			// killSession early-returns from, and must still end the pair's
			// epoch. The relay is muted so the kill is deterministically clean.
			rs.setDropData(true)
			time.Sleep(50 * time.Millisecond)
			pcB := eB.peerConn(eA.pub)
			pcB.killSession(errors.New("test: clean kill at B"), true, reasonLocalKill)
			rs.setDropData(false)
		}},
	}
	for _, r := range resets {
		for _, ps := range peerStates {
			t.Run(r.name+"/"+ps.name, func(t *testing.T) {
				eA, eB, rs := newEncryptedPair(t)

				// Traffic first: both epochs carry advanced sequence numbers
				// when the one-sided reset hits.
				conn, err := eA.OpenStream(eB.PublicKey())
				if err != nil {
					t.Fatal(err)
				}
				roundTrip(t, conn, "before")
				conn.Close()

				eA.peerConn(eB.pub)
				kcpA1 := pairKCPSession(eA, eB.pub)
				eB.peerConn(eA.pub)
				kcpB1 := pairKCPSession(eB, eA.pub)
				if kcpA1 == nil || kcpB1 == nil {
					t.Fatal("a side was built without a KCP underlay")
				}

				ps.prep(t, eB, eA, rs)
				r.reset(t, eA, eB)

				// Recovery in the production retry shape: the first open can
				// fail while the reset lands; the pair must converge promptly.
				waitFor(t, 20*time.Second, func() bool {
					conn, err := eA.OpenStream(eB.PublicKey())
					if err != nil {
						return false
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					if _, err := conn.Write([]byte("after")); err != nil {
						return false
					}
					buf := make([]byte, 5)
					if _, err := io.ReadFull(conn, buf); err != nil {
						return false
					}
					return string(buf) == "after"
				})

				// Coordinated, not one-sided: both epochs were reset — each side
				// rides a fresh KCP session, and the working stream above is
				// what proves their sequence numbers aligned from 0. Read the
				// pair store, not an adapter: the adapters were replaced too.
				if kcpA2 := pairKCPSession(eA, eB.pub); kcpA2 == nil || kcpA2 == kcpA1 {
					t.Fatal("A's epoch was not reset alongside its keys")
				}
				if kcpB2 := pairKCPSession(eB, eA.pub); kcpB2 == nil || kcpB2 == kcpB1 {
					t.Fatal("B's epoch survived the peer's reset signal")
				}
			})
		}
	}
}

// TestRelaySessionRunsOverKCP pins the relay session's underlay: the smux
// session must ride a KCP session over the datagram adapter (derp packet ->
// adapter -> KCP -> secure record -> smux), mirroring the direct plane's
// KCP -> cryptoConn(secure) -> smux stack, instead of the raw peerConn byte
// stream that one dropped relay packet desyncs forever.
func TestRelaySessionRunsOverKCP(t *testing.T) {
	eA, eB, _ := newEncryptedPair(t)

	// Build both sides explicitly: A's build settles B's keys but B's own
	// session is otherwise built only by B's pump on the first inbound data
	// packet, and both adapters' state is asserted right after.
	pcA := eA.peerConn(eB.pub)
	if _, err := pcA.ensureSession(false, true); err != nil {
		t.Fatal(err)
	}
	pcB := eB.peerConn(eA.pub)
	if _, err := pcB.ensureSession(false, true); err != nil {
		t.Fatal(err)
	}

	for _, side := range []struct {
		name string
		pc   *peerConn
	}{
		{"A", pcA}, {"B", pcB},
	} {
		side.pc.mu.Lock()
		kcpConn, sess := side.pc.kcp, side.pc.sess
		side.pc.mu.Unlock()
		if kcpConn == nil {
			t.Fatalf("%s's relay session was built without a KCP underlay", side.name)
		}
		if sess == nil {
			t.Fatalf("%s's relay session was not built", side.name)
		}
		// The pair's deterministic conv is what makes the two sides'
		// sessions interoperate without a handshake (mirrors directConn.conv).
		if got := kcpConn.GetConv(); got != relayConv(side.pc.e.pub, side.pc.peer) {
			t.Fatalf("%s's KCP underlay conv = %#x, want the pair's relayConv", side.name, got)
		}
	}

	// Bytes both ways through the pair's session: the stream rides A's smux
	// session over its KCP underlay to B's echo bridge, and the reply rides
	// B's back — the whole chain carries.
	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "relay bytes over kcp")
}

// TestRelayToleratesDroppedDataFrames pins the KCP-underlay fix against the
// failure it exists to absorb: one dropped relay data frame used to desync the
// crypto record framing forever ("p2p: bad secure record length") and kill the
// link at ~2 MB. Here the pair's smux stream carries a multi-megabyte payload
// while the sender drops every Nth relay data frame (p2p.FaultsConfig.
// DropDataRate): KCP must retransmit the lost segments and the payload must
// arrive intact, with no secure-record desync, no relay-session rebuild, and
// the pair's KCP session never resetting — loss repaired by KCP, not by
// tearing the session down and redialing.
func TestRelayToleratesDroppedDataFrames(t *testing.T) {
	eA, eB, _ := newEncryptedPair(t)

	// Build both sides explicitly (as TestRelaySessionRunsOverKCP does), so the
	// pair's KCP session and secure session exist before the loss is turned on
	// and their identity can be snapshotted.
	pcA := eA.peerConn(eB.pub)
	if _, err := pcA.ensureSession(false, true); err != nil {
		t.Fatal(err)
	}
	pcB := eB.peerConn(eA.pub)
	if _, err := pcB.ensureSession(false, true); err != nil {
		t.Fatal(err)
	}

	// Snapshot the identities the loss must not disturb.
	kcpA := pairKCPSession(eA, eB.pub)
	kcpB := pairKCPSession(eB, eA.pub)
	if kcpA == nil || kcpB == nil {
		t.Fatal("a side was built without a KCP underlay")
	}
	pcA.mu.Lock()
	secureA, rebuildsA, rebuildPeersA := pcA.secure, pcA.relayRebuilds.Load(), pcA.relayRebuildPeers.Load()
	pcA.mu.Unlock()
	pcB.mu.Lock()
	secureB, rebuildsB, rebuildPeersB := pcB.secure, pcB.relayRebuilds.Load(), pcB.relayRebuildPeers.Load()
	pcB.mu.Unlock()

	// Loss on the sender only, installed the same way the fault tests install
	// one: a fresh fault state on the engine's atomic pointer. rate=0.02 drops
	// every round(1/0.02)=50th relay data frame.
	const rate = 0.02
	loss := newFaults(&p2p.FaultsConfig{DropDataRate: rate})
	eA.faults.Store(loss)

	// A payload well past the KCP receive window (256 packets * 1400 B ≈ 350
	// KiB): 2 MiB forces the send window to cycle ~6 times, so retransmitted
	// segments land in a window that has already moved on — the case that must
	// not desync the record stream.
	const payloadSize = 2 << 20 // 2 MiB
	payload := make([]byte, payloadSize)
	// Stamp each 8-byte lane with a position-derived 64-bit value (big-endian
	// uint64(i/8)) so every lane is distinct. A plain byte(i) repeats every 256
	// bytes, so a block moved by an exact multiple of 256 bytes would compare
	// equal and reordering would slip through; lane uniqueness makes any swap of
	// two lanes — across a KCP segment or a 16 KiB crypto record boundary —
	// change the payload, which the byte-for-byte check below catches.
	for i := 0; i < payloadSize; i += 8 {
		binary.BigEndian.PutUint64(payload[i:], uint64(i/8))
	}

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the full payload did not round-trip intact and in order")
	}

	// The injector genuinely exercised the lossy path: it counted every relay
	// data frame A sent and dropped every 50th, so a non-trivial number of
	// drops must have occurred — the test cannot pass vacuously.
	period := loss.dropDataPeriod
	sent := loss.dropDataSeq.Load()
	if period == 0 {
		t.Fatal("dropDataRate did not enable the deterministic drop")
	}
	if drops := sent / period; drops < 10 {
		t.Fatalf("only %d frames dropped over %d sent (want a non-trivial count)", drops, sent)
	}

	// No secure-record desync on either side: the pair's secure session is the
	// same object it was, and its desync streak is clean. A desync would have
	// reset the session (dropRelaySecure) and killed the adapter, so identity is
	// the hard assertion; the streak is the desync accounting itself.
	pcA.mu.Lock()
	secureA2 := pcA.secure
	pcA.mu.Unlock()
	pcB.mu.Lock()
	secureB2 := pcB.secure
	pcB.mu.Unlock()
	if secureA2 != secureA || secureB2 != secureB {
		t.Fatal("the pair re-handshaked: a secure-record desync reset the session")
	}
	if s := secureA.desyncStreakValue(); s != 0 {
		t.Fatalf("A's desync streak = %d after the transfer, want 0", s)
	}
	if s := secureB.desyncStreakValue(); s != 0 {
		t.Fatalf("B's desync streak = %d after the transfer, want 0", s)
	}

	// No relay session rebuild: loss was repaired by KCP, not by tearing the
	// session down and redialing.
	if got := pcA.relayRebuilds.Load(); got != rebuildsA {
		t.Fatalf("A rebuilt its relay session %d time(s) under loss, want 0", got-rebuildsA)
	}
	if got := pcA.relayRebuildPeers.Load(); got != rebuildPeersA {
		t.Fatalf("A saw %d peer rekeys under loss, want 0", got-rebuildPeersA)
	}
	if got := pcB.relayRebuilds.Load(); got != rebuildsB {
		t.Fatalf("B rebuilt its relay session %d time(s) under loss, want 0", got-rebuildsB)
	}
	if got := pcB.relayRebuildPeers.Load(); got != rebuildPeersB {
		t.Fatalf("B saw %d peer rekeys under loss, want 0", got-rebuildPeersB)
	}

	// The pair's KCP session never reset: same object before and after.
	if kcpA2 := pairKCPSession(eA, eB.pub); kcpA2 != kcpA {
		t.Fatal("A's pair KCP session changed across the transfer")
	}
	if kcpB2 := pairKCPSession(eB, eA.pub); kcpB2 != kcpB {
		t.Fatal("B's pair KCP session changed across the transfer")
	}
}
