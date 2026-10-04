package host

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"golang.org/x/crypto/chacha20poly1305"
)

// errEncryptionRequired is returned when a session is asked to wrap an underlay
// before it settled. Encryption is forced: a session that did not negotiate keys
// is refused, never built as plaintext.
var errEncryptionRequired = errors.New("p2p: encryption required but the session did not negotiate it")

// maxSecureRecord bounds one AEAD record's plaintext. 16 KiB keeps the 4-byte
// length prefix and the 16-byte tag at ~0.1% overhead.
const maxSecureRecord = 16 * 1024

// secureDesyncThreshold is how many consecutive record-boundary failures force
// the pair to re-handshake. A rebuilt session reuses its keys and nonce
// counters (see secureSession), so one boundary failure can be a stale read
// racing a teardown — but a run of them means the reuse assumption is broken
// for good and the counters can never realign. Three is past anything a single
// rebuild race can explain, and low enough that the pair recovers in seconds
// rather than churning until the process restarts.
const secureDesyncThreshold = 3

// secureHalfLen is the ctrlSecure payload length: [transport 1B][ephemeral
// public key 32B][want 1B].
const secureHalfLen = 1 + 32 + 1

// Secure transport tags: the ctrlSecure frame's first byte, so the relay
// session's handshake and the direct session's never collide.
const (
	secureTransportRelay  byte = 0x00
	secureTransportDirect byte = 0x01
)

// The values p2p.Status.PeerEncryption reports, one per connected peer. Keep
// them in sync with that field's doc.
const (
	encStateSecure = "secure" // the session settled encrypted
	// encStatePlaintext is retained for API/wire compatibility only. Encryption
	// is forced, so a peer either connects encrypted (encStateSecure) or is
	// refused (no session is built), and this value is not reported for a live
	// peer. It is kept so the field and its proto value stay stable.
	encStatePlaintext = "plaintext"
)

// nonceCtr is a shared, monotonic 64-bit nonce counter for one direction of one
// (peer, transport) session. It lives on the secureSession so a rebuilt smux
// session continues the sequence instead of restarting it (which would reuse a
// nonce under the same key).
type nonceCtr struct {
	mu sync.Mutex
	n  uint64
}

// next reserves the next nonce in the sequence.
func (c *nonceCtr) next() [12]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], c.n)
	c.n++
	return nonce
}

// used reports whether any nonce has been drawn. Safe for concurrent use: a
// cryptoConn holds this counter by pointer and may draw from it at any time.
func (c *nonceCtr) used() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n > 0
}

// cryptoConn is a net.Conn that seals/opens a byte stream as AEAD records:
// [4B big-endian length][ciphertext+tag]. Each direction has its own key and
// borrows the session's shared 64-bit counter (never transmitted — both
// underlays are reliable and ordered). A record that fails to authenticate is
// fatal, and is logged because a cipher failure must be distinguishable from
// ordinary session churn.
type cryptoConn struct {
	net.Conn
	send, recv       cipher.AEAD
	sendCtr, recvCtr *nonceCtr
	// wmu is shared by every cryptoConn of one secureSession and held across a
	// record's two underlying writes, so a rebuild that starts a second conn on
	// the same underlay cannot interleave header and body into corrupt framing.
	wmu  *sync.Mutex
	log  *slog.Logger // optional; the owning session's logger
	peer derpclient.PublicKey

	rmu  sync.Mutex
	rbuf []byte

	// session owns this conn's share of the security state; it counts the
	// record-boundary failures this conn sees. It may be nil in tests that drive
	// the framing directly.
	session *secureSession
}

// newCryptoConn wraps underlay with the directional AEADs and the session's
// shared counters and write mutex. log and peer are used only to report a
// record-auth failure; both may be zero in tests. session reports the
// record-boundary failures readRecord sees, and may be nil.
func newCryptoConn(underlay net.Conn, send, recv cipher.AEAD, sendCtr, recvCtr *nonceCtr, wmu *sync.Mutex, log *slog.Logger, peer derpclient.PublicKey, session *secureSession) *cryptoConn {
	return &cryptoConn{
		Conn:    underlay,
		send:    send,
		recv:    recv,
		sendCtr: sendCtr,
		recvCtr: recvCtr,
		wmu:     wmu,
		log:     log,
		peer:    peer,
		session: session,
	}
}

func (c *cryptoConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), maxSecureRecord)
		nonce := c.sendCtr.next()
		ct := c.send.Seal(nil, nonce[:], p[:n], nil)
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
		c.wmu.Lock()
		_, err := c.Conn.Write(hdr[:])
		if err == nil {
			_, err = c.Conn.Write(ct)
		}
		c.wmu.Unlock()
		if err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *cryptoConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	rec, err := c.readRecord()
	if err != nil {
		return 0, err
	}
	n := copy(b, rec)
	if n < len(rec) {
		c.rbuf = append(c.rbuf[:0], rec[n:]...)
	}
	return n, nil
}

func (c *cryptoConn) readRecord() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxSecureRecord+16 {
		c.noteDesync()
		return nil, fmt.Errorf("p2p: bad secure record length %d", n)
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, ct); err != nil {
		return nil, err
	}
	nonce := c.recvCtr.next()
	pt, err := c.recv.Open(nil, nonce[:], ct, nil)
	if err != nil {
		if c.log != nil {
			c.log.Warn("secure record auth failed", "peer", keyName(c.peer), "error", err)
		}
		c.noteDesync()
		return nil, fmt.Errorf("p2p: secure record auth failed: %w", err)
	}
	c.clearDesync()
	return pt, nil
}

// noteDesync hands the session one record-boundary failure. Only the two
// failures above the record boundary count: a short read or an orderly end of
// stream is a torn-down session, not a misaligned pair.
func (c *cryptoConn) noteDesync() {
	if c.session != nil {
		c.session.noteDesync()
	}
}

// clearDesync tells the session a record opened cleanly.
func (c *cryptoConn) clearDesync() {
	if c.session != nil {
		c.session.clearDesync()
	}
}

// handshakeTimeout bounds waiting for the peer's handshake half. Both peers
// send their half eagerly, so a healthy wait is one control round trip
// (sub-second); the bound only bites for a peer that does not support it.
var handshakeTimeout = 3 * time.Second

// secureSession drives one (peer, transport) handshake and owns its keys. It
// outlives any one smux session: a rebuilt mux session reuses the same keys and
// the same nonce counters, so a one-sided rebuild is transparent and the nonce
// sequence never restarts. That reuse holds only while the pair stays aligned —
// a replacement that abandoned records re-handshakes on a fresh session instead
// (see dropRelaySecure), and a session that sees repeated record-boundary
// failures asks to be dropped (see noteDesync). It holds no I/O: the caller
// seals/sends the half returned by start and feeds the peer's opened half to
// respond. Once both halves are present the directional AEAD keys are derived;
// until then the session is plaintext.
type secureSession struct {
	transport byte
	local     derpclient.PrivateKey
	peer      derpclient.PublicKey
	log       *slog.Logger // optional

	mu      sync.Mutex
	wmu     sync.Mutex // shared write lock handed to every cryptoConn of this session
	started bool
	eph     *ecdh.PrivateKey // retained for the session's life: needed to re-derive on a peer restart
	ephPub  []byte
	peerEph []byte
	sendKey []byte
	recvKey []byte
	ready   bool
	sendCtr *nonceCtr
	recvCtr *nonceCtr
	peerCh  chan struct{}

	// desyncStreak counts consecutive record-boundary failures seen by any
	// cryptoConn of this session. It is deliberately not carried across a
	// rebuild: a fresh session starts clean, so the reset it triggers cannot
	// compound into a handshake storm.
	desyncStreak int
	// onDesync asks the owner to drop this session and rebuild the pair. It is
	// wired by the engine for relay sessions only, and may be nil.
	onDesync func(streak int)
}

// noteDesync records one record-boundary failure and returns the running streak.
// The first time the streak reaches secureDesyncThreshold it dispatches onDesync
// on its own goroutine: the callback drops the security session and kills the
// adapter, neither of which may run on the read path (this is called under
// cryptoConn.rmu, and the engine takes e.mu before pc.mu). It fires exactly once
// per session — at the threshold, not on every failure past it — because a later
// failure can belong to a session that has already been replaced, and resetting
// that one would restart the churn the backstop exists to end.
func (s *secureSession) noteDesync() int {
	s.mu.Lock()
	s.desyncStreak++
	n := s.desyncStreak
	cb := s.onDesync
	fire := n == secureDesyncThreshold && cb != nil
	s.mu.Unlock()
	if fire {
		go cb(n)
	}
	return n
}

// clearDesync resets the streak: the count is of consecutive failures, so one
// record that opens cleanly proves the pair is still aligned.
func (s *secureSession) clearDesync() {
	s.mu.Lock()
	s.desyncStreak = 0
	s.mu.Unlock()
}

func newSecureSession(log *slog.Logger, transport byte, local derpclient.PrivateKey, peer derpclient.PublicKey) *secureSession {
	return &secureSession{
		transport: transport,
		local:     local,
		peer:      peer,
		log:       log,
		sendCtr:   &nonceCtr{},
		recvCtr:   &nonceCtr{},
		peerCh:    make(chan struct{}),
	}
}

// start generates our ephemeral on the first call and returns the sealed
// ctrlSecure payload to send; later calls re-seal the same public half (a
// resend). The payload carries a want bit set while we are unsettled, which
// asks the peer to (re-)send its own half — that is how a lost reply heals. It
// never errors on the ephemeral after the first success.
func (s *secureSession) start() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		s.eph = eph
		s.ephPub = eph.PublicKey().Bytes()
		s.started = true
		s.deriveLocked()
	}
	want := byte(0)
	if !s.ready {
		want = 1 // we still need the peer's half: ask for it
	}
	payload := make([]byte, 0, secureHalfLen)
	payload = append(payload, s.transport)
	payload = append(payload, s.ephPub...)
	payload = append(payload, want)
	return s.local.SealTo(s.peer, payload), nil
}

// respond consumes the peer's half. changed is true when the peer's ephemeral
// differs from the one already settled (the peer restarted); the keys are then
// re-derived from our retained ephemeral and the nonce counters are replaced
// under the new key. A repeated half is a no-op that still reports ok. A
// well-formed half that cannot derive (a bad point, or a failed ECDH/HKDF) is
// rejected: ok=false and nothing is stored, so the session stays unsettled and
// the caller keeps retrying instead of wedging into silent plaintext.
func (s *secureSession) respond(clear []byte) (ok, changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(clear) != secureHalfLen || clear[0] != s.transport {
		return false, false
	}
	eph := clear[1 : 1+32]
	changed = s.peerEph != nil && !bytes.Equal(s.peerEph, eph)

	// Derive against the candidate without committing anything.
	send, recv, derived := s.deriveFor(eph)
	if s.eph != nil && !derived {
		// We hold a usable ephemeral, so a derivation failure means the peer's
		// half is unusable. Storing it would make settled() true and leave the
		// session silently plaintext forever — the downgrade the design forbids.
		// Leave the session as it was and let the retry loop try again.
		return false, false
	}

	if changed {
		s.ready = false
		s.sendKey, s.recvKey = nil, nil
	}
	s.peerEph = append([]byte(nil), eph...)
	if derived {
		s.sendKey, s.recvKey = send, recv
		s.ready = true
		s.signalReadyLocked()
	}
	if changed && derived {
		// Replace the counters rather than resetting them in place: a
		// cryptoConn built over the previous key still holds the old pointers
		// and may write in the window before its session is torn down, so
		// resetting in place would replay nonces 0..N under the old key. New
		// objects give the new key a clean nonce space and leave the old conn's
		// counter untouched.
		s.sendCtr = &nonceCtr{}
		s.recvCtr = &nonceCtr{}
	}
	return true, changed
}

// signalReadyLocked closes peerCh exactly once, on the transition to ready.
// peerCh means "the session became ready", not "a half arrived": a half that
// does not derive must not wake waitReady, or ensureSession's retry loop would
// spin without the resendInterval spacing (a half is accepted but the session is
// not ready until both ephemerals derive). Caller must hold s.mu.
func (s *secureSession) signalReadyLocked() {
	select {
	case <-s.peerCh:
	default:
		close(s.peerCh)
	}
}

// deriveFor computes the directional keys for a candidate peer ephemeral,
// without touching the session. It reports ok=false when we have no ephemeral
// yet, or when the peer's half is unusable (a bad point, a failed ECDH, or a
// failed HKDF).
func (s *secureSession) deriveFor(peerEph []byte) (send, recv []byte, ok bool) {
	if s.eph == nil || len(peerEph) != 32 {
		return nil, nil, false
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerEph)
	if err != nil {
		return nil, nil, false
	}
	ss, err := s.eph.ECDH(peerPub)
	if err != nil {
		return nil, nil, false
	}
	a, b := s.ephPub, peerEph
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	salt := append(append([]byte(nil), a...), b...)
	keys, err := hkdf.Key(sha256.New, ss, salt, "p2p-session-v1"+string([]byte{s.transport}), 64)
	if err != nil {
		return nil, nil, false
	}
	// Direction by static-key order: the lower key claims keys[0:32] as its
	// send. Both ends compute the same comparison, so send matches recv.
	k0, k1 := keys[:32], keys[32:64]
	localPub := s.local.Public()
	if bytes.Compare(localPub[:], s.peer[:]) < 0 {
		return k0, k1, true
	}
	return k1, k0, true
}

// deriveLocked commits the keys for the currently stored peerEph, mixing the
// two ephemerals. The salt is the ordered concatenation of both public halves
// and the info binds the transport, so relay and direct sessions never share a
// key. It reports whether keys were produced. It is re-runnable: respond clears
// ready before calling it when the peer's ephemeral changed.
func (s *secureSession) deriveLocked() bool {
	send, recv, ok := s.deriveFor(s.peerEph)
	if !ok {
		return false
	}
	s.sendKey, s.recvKey, s.ready = send, recv, true
	s.signalReadyLocked()
	return true
}

// settled reports whether the session holds usable keys. A settled session
// needs no proactive half: a rebuild reuses its keys, and a peer restart arrives
// as a changed half that respond reports. A rejected (underivable) half leaves
// the session unsettled, so the caller keeps retrying.
func (s *secureSession) settled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

// rekeyIfUsed rotates the ephemeral and nonce space when the current key has
// already carried records. The direct session is rebuilt over a *new* KCP
// underlay on every punch, and the old underlay's records can be lost in the
// teardown — a peer that writes one last keepalive into the dying session
// advances the shared counter for a record this side never reads, so continuing
// the sequence across the rebuild would desync and fail authentication. (The
// relay does not have this: its underlay is one continuous byte stream, so a
// one-sided rebuild picks the sequence up where it left off.) Continuing the
// counter under the *same* key would instead replay nonces, so the key is
// rotated with it — a fresh ephemeral opens a fresh nonce space, and the peer
// sees the changed half and re-derives in one exchange.
//
// It is a no-op while the key is fresh (no records sent or received), so that
// two peers rebuilding at once — the normal case for a dead session — converge
// on one exchange instead of rekeying each other in a loop.
func (s *secureSession) rekeyIfUsed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || (!s.sendCtr.used() && !s.recvCtr.used()) {
		return
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	s.eph = eph
	s.ephPub = eph.PublicKey().Bytes()
	s.peerEph = nil
	s.sendKey, s.recvKey = nil, nil
	s.ready = false
	s.sendCtr = &nonceCtr{}
	s.recvCtr = &nonceCtr{}
	// A fresh readiness channel: the old one is already closed (the previous key
	// settled), so waitReady would return at once and the punch's settle loop
	// would spin. A new channel makes it block for the new half.
	s.peerCh = make(chan struct{})
}

// waitReady blocks until the peer's half arrives or the deadline d elapses, then
// reports whether the session settled encrypted. The channel is read under the
// lock because rekeyIfUsed replaces it on a rotation.
func (s *secureSession) waitReady(d time.Duration) bool {
	s.mu.Lock()
	ch := s.peerCh
	s.mu.Unlock()
	select {
	case <-ch:
	case <-time.After(d):
	}
	_, _, ok := s.keys()
	return ok
}

// keys returns the directional keys, or ok=false while the session is plaintext.
func (s *secureSession) keys() (send, recv []byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendKey, s.recvKey, s.ready
}

// conn wraps underlay with the session cipher and refuses when the session did
// not settle: encryption is forced, so there is no plaintext fallback. It may be
// called once per session rebuild: each call builds a fresh cryptoConn over the
// same keys, the same shared counters and the same write mutex, so a rebuilt
// session continues the nonce sequence instead of restarting it.
func (s *secureSession) conn(underlay net.Conn) (net.Conn, error) {
	// Read the key AND its counters in one lock section: respond replaces the
	// counters under s.mu on a rekey, so reading them after unlocking could pair
	// an old key with a fresh counter (and replay nonces).
	s.mu.Lock()
	send, recv, ok := s.sendKey, s.recvKey, s.ready
	sendCtr, recvCtr := s.sendCtr, s.recvCtr
	s.mu.Unlock()
	if !ok {
		return nil, errEncryptionRequired
	}
	sa, err := chacha20poly1305.New(send)
	if err != nil {
		return nil, err
	}
	ra, err := chacha20poly1305.New(recv)
	if err != nil {
		return nil, err
	}
	return newCryptoConn(underlay, sa, ra, sendCtr, recvCtr, &s.wmu, s.log, s.peer, s), nil
}
