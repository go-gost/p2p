package host

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestCryptoConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	send, _ := chacha20poly1305.New(bytes.Repeat([]byte{1}, 32))
	recv, _ := chacha20poly1305.New(bytes.Repeat([]byte{2}, 32))
	// a seals with key 1, opens with key 2; b is the mirror. Each direction has
	// its own counter; the two ends of a direction must start at the same value.
	var asc, arc, bsc, brc nonceCtr
	ca := newCryptoConn(a, send, recv, &asc, &arc, &sync.Mutex{}, nil, derpclient.PublicKey{}, nil)
	cb := newCryptoConn(b, recv, send, &bsc, &brc, &sync.Mutex{}, nil, derpclient.PublicKey{}, nil)

	go func() {
		ca.Write(bytes.Repeat([]byte("x"), 40000)) // 3 records
		ca.Write([]byte("tail"))
		ca.Close()
	}()

	got, err := io.ReadAll(cb)
	if err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte("x"), 40000), []byte("tail")...)
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip mismatch: got %d bytes", len(got))
	}
}

func TestCryptoConnRejectsTamperedRecord(t *testing.T) {
	aead, _ := chacha20poly1305.New(bytes.Repeat([]byte{9}, 32))
	// Craft a record exactly as cryptoConn.Write does, then corrupt one body byte.
	var nonce [12]byte
	ct := aead.Seal(nil, nonce[:], []byte("payload"), nil)
	ct[len(ct)-1] ^= 0xff
	var wire bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
	wire.Write(hdr[:])
	wire.Write(ct)

	a, b := net.Pipe()
	go func() { io.Copy(b, &wire); b.Close() }()
	c := newCryptoConn(a, aead, aead, &nonceCtr{}, &nonceCtr{}, &sync.Mutex{}, nil, derpclient.PublicKey{}, nil)
	if _, err := c.Read(make([]byte, 64)); err == nil {
		t.Fatal("tampered record did not fail")
	}
}

func TestCryptoConnRejectsBadLength(t *testing.T) {
	aead, _ := chacha20poly1305.New(bytes.Repeat([]byte{9}, 32))
	a, b := net.Pipe()
	go func() {
		b.Write([]byte{0, 0, 0, 0}) // zero-length record: invalid
		b.Close()
	}()
	c := newCryptoConn(a, aead, aead, &nonceCtr{}, &nonceCtr{}, &sync.Mutex{}, nil, derpclient.PublicKey{}, nil)
	if _, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatal("zero-length record did not fail")
	}
}

func TestSecureSessionNegotiatesDeterministically(t *testing.T) {
	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a := newSecureSession(nil, secureTransportRelay, privA, pubB)
	b := newSecureSession(nil, secureTransportRelay, privB, pubA)

	// Exchange halves the way the engine does: seal with the static key, open
	// with the peer's static key.
	pa, err := a.start()
	if err != nil {
		t.Fatal(err)
	}
	clear, ok := privB.OpenFrom(pubA, pa)
	if !ok {
		t.Fatal("b could not open a's half")
	}
	if bOK, _ := b.respond(clear); !bOK {
		t.Fatal("b rejected a's half")
	}
	pb, _ := b.start()
	clear, ok = privA.OpenFrom(pubB, pb)
	if !ok {
		t.Fatal("a could not open b's half")
	}
	if aOK, _ := a.respond(clear); !aOK {
		t.Fatal("a rejected b's half")
	}
	if !a.waitReady(time.Second) || !b.waitReady(time.Second) {
		t.Fatal("no session key after both halves")
	}
	as, ar, okA := a.keys()
	bs, br, okB := b.keys()
	if !okA || !okB {
		t.Fatal("keys not ready")
	}
	// a's send must equal b's recv, and vice versa.
	if !bytes.Equal(as, br) || !bytes.Equal(ar, bs) {
		t.Fatal("directional keys do not match")
	}
	if bytes.Equal(as, ar) {
		t.Fatal("send and recv keys must differ")
	}
}

func TestSecureSessionRejectsWrongTransport(t *testing.T) {
	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a := newSecureSession(nil, secureTransportDirect, privA, pubB)
	b := newSecureSession(nil, secureTransportRelay, privB, pubA)
	pa, _ := a.start()                    // sealed by a, tagged direct
	clear, ok := privB.OpenFrom(pubA, pa) // b opens it
	if !ok {
		t.Fatal("seal/open round trip failed")
	}
	if bOK, _ := b.respond(clear); bOK {
		t.Fatal("accepted a direct half on a relay session")
	}
}

func TestSecureSessionTimesOut(t *testing.T) {
	privA, _, _ := derpclient.Generate()
	_, pubB, _ := derpclient.Generate()
	a := newSecureSession(nil, secureTransportRelay, privA, pubB)
	if _, err := a.start(); err != nil {
		t.Fatal(err)
	}
	if a.waitReady(50 * time.Millisecond) {
		t.Fatal("settled without the peer's half")
	}
	if _, _, ok := a.keys(); ok {
		t.Fatal("keys ready without the peer's half")
	}
}

// TestSecureSessionConnSharesCounter pins the cross-rebuild nonce contract: a
// session's security state outlives the mux session it protects, so a rebuilt
// mux session wraps the same keys AND the same counters. Two conn() calls must
// yield two cryptoConns that share the session counters; if the counters were
// per-conn, a rebuild would restart the nonce sequence and reuse nonces under
// the same key.
func TestSecureSessionConnSharesCounter(t *testing.T) {
	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a := newSecureSession(nil, secureTransportRelay, privA, pubB)
	b := newSecureSession(nil, secureTransportRelay, privB, pubA)
	pa, _ := a.start()
	clear, _ := privB.OpenFrom(pubA, pa)
	b.respond(clear)
	pb, _ := b.start()
	clear, _ = privA.OpenFrom(pubB, pb)
	a.respond(clear)

	x, _ := net.Pipe()
	y, _ := net.Pipe()
	c1, err := a.conn(x)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := a.conn(y)
	if err != nil {
		t.Fatal(err)
	}
	s1 := c1.(*cryptoConn)
	s2 := c2.(*cryptoConn)
	if s1 == s2 {
		t.Fatal("conn built twice must be two conns")
	}
	if s1.sendCtr != s2.sendCtr || s1.recvCtr != s2.recvCtr {
		t.Fatal("rebuilt conns must share the session counters, or the nonce space repeats")
	}
}

// TestSecureSessionRekeyOnChangedHalf pins the peer-restart path: a different
// peer ephemeral re-derives the keys (changed=true) and restarts the counters;
// a repeated half is a no-op that still reports ok.
func TestSecureSessionRekeyOnChangedHalf(t *testing.T) {
	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a := newSecureSession(nil, secureTransportRelay, privA, pubB)
	if _, err := a.start(); err != nil {
		t.Fatal(err)
	}

	// First session with the peer: accepted, not changed.
	b1 := newSecureSession(nil, secureTransportRelay, privB, pubA)
	p1, _ := b1.start()
	clear1, _ := privB.OpenFrom(pubA, p1)
	if ok, changed := a.respond(clear1); !ok || changed {
		t.Fatalf("first half: ok=%v changed=%v, want true/false", ok, changed)
	}
	if _, _, ready := a.keys(); !ready {
		t.Fatal("not ready after first half")
	}
	if ok, changed := a.respond(clear1); !ok || changed {
		t.Fatalf("repeated half: ok=%v changed=%v, want true/false", ok, changed)
	}

	// The peer restarts: a fresh session → a different ephemeral → changed.
	b2 := newSecureSession(nil, secureTransportRelay, privB, pubA)
	p2, _ := b2.start()
	clear2, _ := privB.OpenFrom(pubA, p2)
	if ok, changed := a.respond(clear2); !ok || !changed {
		t.Fatalf("changed half: ok=%v changed=%v, want true/true", ok, changed)
	}
	if _, _, ready := a.keys(); !ready {
		t.Fatal("not ready after rekey")
	}
}

// TestSecureSessionRekeyReplacesCounters pins the nonce-safety half of a rekey: a
// conn built over the OLD key holds its counter by pointer and may still write in
// the window before its session is torn down, so the rekey must hand the new key
// a fresh counter object rather than reset the old one in place (which would
// replay nonces 0..N under the old key).
func TestSecureSessionRekeyReplacesCounters(t *testing.T) {
	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a := newSecureSession(nil, secureTransportRelay, privA, pubB)
	b1 := newSecureSession(nil, secureTransportRelay, privB, pubA)

	pa, _ := a.start()
	clearA, _ := privB.OpenFrom(pubA, pa)
	b1.respond(clearA)
	pb1, _ := b1.start()
	clearB1, _ := privA.OpenFrom(pubB, pb1)
	if ok, changed := a.respond(clearB1); !ok || changed {
		t.Fatalf("initial half: ok=%v changed=%v, want true/false", ok, changed)
	}

	x, _ := net.Pipe()
	c1, err := a.conn(x)
	if err != nil {
		t.Fatal(err)
	}

	// A "restarted" peer: a different ephemeral forces a rekey.
	b2 := newSecureSession(nil, secureTransportRelay, privB, pubA)
	pb2, _ := b2.start()
	clearB2, _ := privA.OpenFrom(pubB, pb2)
	if ok, changed := a.respond(clearB2); !ok || !changed {
		t.Fatalf("rekey half: ok=%v changed=%v, want true/true", ok, changed)
	}

	y, _ := net.Pipe()
	c2, err := a.conn(y)
	if err != nil {
		t.Fatal(err)
	}
	old := c1.(*cryptoConn)
	newC := c2.(*cryptoConn)
	if old.sendCtr == newC.sendCtr || old.recvCtr == newC.recvCtr {
		t.Fatal("rekey reused the old conn's counter object: the nonce space would repeat")
	}
}

// TestSecureSessionUnderivableHalfDoesNotWake: an underivable half (an all-zero
// X25519 point) that arrives before our first start() is accepted but is not
// ready. peerCh must NOT close on it: if it did, waitReady would return at once
// and ensureSession's retry loop would spin hot instead of spacing retries by
// resendInterval.
func TestSecureSessionUnderivableHalfDoesNotWake(t *testing.T) {
	privA, _, _ := derpclient.Generate()
	_, pubB, _ := derpclient.Generate()
	a := newSecureSession(nil, secureTransportRelay, privA, pubB)

	// An opened ctrlSecure payload: relay-tagged, a zero (underivable) ephemeral,
	// want set.
	clear := make([]byte, secureHalfLen)
	clear[0] = secureTransportRelay
	clear[secureHalfLen-1] = 1

	if ok, _ := a.respond(clear); !ok {
		t.Fatal("respond rejected a well-formed half")
	}
	if a.settled() {
		t.Fatal("settled on an underivable half")
	}

	start := time.Now()
	if a.waitReady(50 * time.Millisecond) {
		t.Fatal("waitReady reported ready on an underivable half")
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("waitReady returned after %v, want it to wait ~50ms (not wake on a pre-closed channel)", elapsed)
	}

	// Even once we generate our own ephemeral, the zero peer point cannot derive,
	// so the session stays unsettled (and must not signal).
	if _, err := a.start(); err != nil {
		t.Fatal(err)
	}
	if a.settled() {
		t.Fatal("settled after start() against an underivable peer half")
	}
}

// TestKillSessionDropsRelaySecureUnlessRekeyed pins the dropSecure contract of
// killSession: a kill that abandons records (queued, never-read packets whose
// nonces the peer already spent) drops the pair's relay security session — but
// never the direct one (that transport re-keys via rekeyIfUsed). A clean kill
// abandons nothing and keeps the session (the nonce sequence is intact, so the
// rebuild is transparent), and the peer-rekeyed teardown is the one kill that
// must never drop it — respond already re-derived both halves, so dropping
// would make the two ends swap halves forever.
func TestKillSessionDropsRelaySecureUnlessRekeyed(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{7}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// freshPC returns an adapter holding both cached sessions, optionally with
	// one queued record — the packet the kill abandons.
	newPC := func(queued bool) *peerConn {
		e.mu.Lock()
		relay := newSecureSession(nil, secureTransportRelay, priv, peer)
		e.secure[secureKey{peer: peer, transport: secureTransportRelay}] = relay
		e.secure[secureKey{peer: peer, transport: secureTransportDirect}] =
			newSecureSession(nil, secureTransportDirect, priv, peer)
		e.mu.Unlock()
		inbound := make(chan []byte, 1)
		if queued {
			inbound <- []byte("stale record queued at kill time")
		}
		return &peerConn{e: e, peer: peer, inbound: inbound, closeCh: make(chan struct{}), secure: relay}
	}
	cached := func() (relay, direct bool) {
		e.mu.Lock()
		defer e.mu.Unlock()
		_, relay = e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
		_, direct = e.secure[secureKey{peer: peer, transport: secureTransportDirect}]
		return
	}

	// A kill that abandoned records drops the relay session, never the direct.
	newPC(true).killSession(errors.New("test: local kill"), true, reasonLocalKill)
	if relay, direct := cached(); relay || !direct {
		t.Fatalf("after an abandoning kill: relay kept=%v direct kept=%v, want false/true", relay, direct)
	}

	// A clean kill abandons nothing: the settled session is reused.
	newPC(false).killSession(errors.New("test: local kill"), true, reasonLocalKill)
	if relay, direct := cached(); !relay || !direct {
		t.Fatalf("after a clean kill: relay kept=%v direct kept=%v, want true/true", relay, direct)
	}

	// The peer-rekeyed teardown keeps it even when records were abandoned.
	newPC(true).killSession(errors.New("derp engine: peer rekeyed"), false, reasonPeerRekeyed)
	if relay, direct := cached(); !relay || !direct {
		t.Fatalf("after the peer-rekeyed kill: relay kept=%v direct kept=%v, want true/true", relay, direct)
	}
}

// --- record-boundary self-heal (desync backstop) ---

// readOverRecord builds a cryptoConn over a pipe carrying wire, reads once and
// returns the error. The writer closes, so a read that consumes less than the
// whole wire still terminates. Each conn gets its own counters, so a record
// sealed with nonce 0 is the record it reads.
func readOverRecord(t *testing.T, s *secureSession, aead cipher.AEAD, wire []byte) error {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		b.Write(wire)
		b.Close()
	}()
	c := newCryptoConn(a, aead, aead, &nonceCtr{}, &nonceCtr{}, &sync.Mutex{}, nil, derpclient.PublicKey{}, s)
	_, err := c.Read(make([]byte, 64))
	return err
}

// outOfRangeRecord is a record header whose length cannot be a record: the
// boundary failure the production logs show as `bad secure record length
// 3559037810`. readRecord rejects it without consuming a body, so the header
// alone is the whole wire.
func outOfRangeRecord() []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 3559037810)
	return hdr[:]
}

// desyncStreakOf reads a session's streak the way the engine observes it.
func desyncStreakOf(s *secureSession) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.desyncStreak
}

// newDesyncSession builds a relay security session with the backstop's callback
// reporting every streak it is handed.
func newDesyncSession(t *testing.T) (*secureSession, chan int) {
	t.Helper()
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, peerPub, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := newSecureSession(nil, secureTransportRelay, priv, peerPub)
	fired := make(chan int, 8)
	s.mu.Lock()
	s.onDesync = func(n int) { fired <- n }
	s.mu.Unlock()
	return s, fired
}

// TestSecureDesyncStreakCounts pins the backstop's counter: each record-boundary
// failure adds one, secureDesyncThreshold failures in a row trip the reset, and
// a record that opens cleanly clears the streak — the count is of CONSECUTIVE
// failures, so one healthy record heals the session.
func TestSecureDesyncStreakCounts(t *testing.T) {
	s, fired := newDesyncSession(t)
	aead, err := chacha20poly1305.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}

	for want := 1; want <= secureDesyncThreshold; want++ {
		if err := readOverRecord(t, s, aead, outOfRangeRecord()); err == nil {
			t.Fatalf("failure %d: an out-of-range record length did not fail the read", want)
		}
		if got := desyncStreakOf(s); got != want {
			t.Fatalf("after %d failing reads: streak=%d, want %d", want, got, want)
		}
	}

	// The backstop fires once, at the threshold. A session that kept firing
	// would reset whatever session replaced it, turning one fault into a reset
	// loop — the handshake storm the queue-overflow path must not escalate into.
	select {
	case n := <-fired:
		if n != secureDesyncThreshold {
			t.Fatalf("onDesync got streak=%d, want %d", n, secureDesyncThreshold)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onDesync never fired at the threshold")
	}
	select {
	case n := <-fired:
		t.Fatalf("onDesync fired again on the same session (streak=%d)", n)
	case <-time.After(100 * time.Millisecond):
	}

	// A record that opens cleanly clears the streak.
	var nonce [12]byte
	ct := aead.Seal(nil, nonce[:], []byte("ok"), nil)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
	if err := readOverRecord(t, s, aead, append(hdr[:], ct...)); err != nil {
		t.Fatalf("a valid record after the failures did not open: %v", err)
	}
	if got := desyncStreakOf(s); got != 0 {
		t.Fatalf("streak after a clean record = %d, want 0", got)
	}

	// clearDesync is the same reset the clean record performs, and the count
	// restarts from one.
	if got := s.noteDesync(); got != 1 {
		t.Fatalf("noteDesync = %d, want 1", got)
	}
	s.clearDesync()
	if got := s.noteDesync(); got != 1 {
		t.Fatalf("noteDesync after clearDesync = %d, want 1 (the count restarts)", got)
	}
}

// TestBadRecordLengthStaysFatal pins that the backstop counts a bad length
// without swallowing it: the read still fails with the diagnostic the
// production logs carry, because the reset is driven by the callback and never
// by turning the error into a success.
func TestBadRecordLengthStaysFatal(t *testing.T) {
	s, _ := newDesyncSession(t)
	aead, err := chacha20poly1305.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}

	err = readOverRecord(t, s, aead, outOfRangeRecord())
	if err == nil {
		t.Fatal("an out-of-range record length did not fail the read")
	}
	if !strings.Contains(err.Error(), "bad secure record length") {
		t.Fatalf("read error = %q, want it to carry the bad-length diagnostic", err)
	}
	if got := desyncStreakOf(s); got != 1 {
		t.Fatalf("streak = %d, want 1: the backstop counts this failure", got)
	}
}

// TestSecureRecordAuthFailureStaysFatal pins the same property for the other
// counted boundary failure — the `secure record auth failed` the hub logged 69
// times in production. The backstop counts it; it does not hide it.
func TestSecureRecordAuthFailureStaysFatal(t *testing.T) {
	s, _ := newDesyncSession(t)
	aead, err := chacha20poly1305.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}

	// A record of a valid length whose body does not authenticate.
	var nonce [12]byte
	ct := aead.Seal(nil, nonce[:], []byte("payload"), nil)
	ct[len(ct)-1] ^= 0xff
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))

	err = readOverRecord(t, s, aead, append(hdr[:], ct...))
	if err == nil {
		t.Fatal("a tampered record did not fail the read")
	}
	if !strings.Contains(err.Error(), "secure record auth failed") {
		t.Fatalf("read error = %q, want it to carry the auth diagnostic", err)
	}
	if got := desyncStreakOf(s); got != 1 {
		t.Fatalf("streak = %d, want 1: the backstop counts this failure", got)
	}
}

// TestDesyncStreakNotInheritedByFreshSession pins that the backstop does not
// double-reset one fault. The queue-overflow and link-lost paths already drop
// the relay security session before the streak could reach the threshold, so
// the session that replaces a dropped one must start clean: a session that
// inherited a streak of three would re-handshake on every rebuild and never
// settle. Direct sessions are never armed — they re-key via rekeyIfUsed on
// every punch.
func TestDesyncStreakNotInheritedByFreshSession(t *testing.T) {
	e := newTestEngine(t)
	peer := derpclient.PublicKey{9}
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}

	relay := newSecureSession(nil, secureTransportRelay, priv, peer)
	direct := newSecureSession(nil, secureTransportDirect, priv, peer)
	e.mu.Lock()
	e.secure[secureKey{peer: peer, transport: secureTransportRelay}] = relay
	e.secure[secureKey{peer: peer, transport: secureTransportDirect}] = direct
	e.mu.Unlock()
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, 1),
		closeCh: make(chan struct{}),
		secure:  relay,
	}
	e.mu.Lock()
	e.peers[peer] = pc
	e.mu.Unlock()

	e.armDesyncRecovery(peer, relay)
	if relay.onDesync == nil {
		t.Fatal("relay security session was not armed")
	}
	e.armDesyncRecovery(peer, direct)
	if direct.onDesync != nil {
		t.Fatal("direct security session was armed: rekeyIfUsed owns that path")
	}

	// Trip the backstop. Its callback runs on its own goroutine, so both effects
	// are observed rather than assumed.
	for i := 1; i <= secureDesyncThreshold; i++ {
		if got := relay.noteDesync(); got != i {
			t.Fatalf("failure %d: streak=%d, want %d", i, got, i)
		}
	}
	waitFor(t, 2*time.Second, func() bool {
		pc.mu.Lock()
		defer pc.mu.Unlock()
		return pc.closed
	})
	e.mu.Lock()
	_, cached := e.secure[secureKey{peer: peer, transport: secureTransportRelay}]
	e.mu.Unlock()
	if cached {
		t.Fatal("the backstop did not drop the relay security session")
	}

	// The replacement starts clean: it must not inherit the old session's streak.
	fresh := e.secureSessionFor(peer, secureTransportRelay)
	if fresh == relay {
		t.Fatal("the dropped session was handed out again")
	}
	if got := desyncStreakOf(fresh); got != 0 {
		t.Fatalf("fresh session streak = %d, want 0: a rebuild inheriting the old "+
			"streak would re-handshake on every replacement and never settle", got)
	}
}
