# p2p end-to-end encryption — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Commit policy:** this repo does not commit without explicit user approval. The
> `git commit` steps below are the *intended* commits — run them only when the
> user has said to commit. Build/vet/test are the real gates for each task.

**Goal:** Encrypt the p2p data plane end to end — every smux session (relay and
direct, tcp and udp) runs over a per-session ephemeral-X25519 + chacha20poly1305
cipher negotiated through a new sealed control frame, with a plaintext fallback
for peers that do not support it.

**Architecture:** A `cryptoConn` (net.Conn) wraps the underlay of each per-peer
smux session (`peerConn` for the relay, the KCP conn for direct). A per-session
`secureSession` generates an ephemeral X25519 keypair, ships the public half in a
new `ctrlSecure` (0x05) control frame sealed to the peer's static key, and derives
two directional chacha20poly1305 keys via HKDF once the peer's half arrives. A
session is encrypted iff the peer's half arrived before the session is built;
otherwise it is built plaintext. The relay/hole-punched path carries ciphertext
only.

**Tech Stack:** Go 1.26 (workspace), `crypto/ecdh`, `crypto/hkdf`, `crypto/sha256`,
`golang.org/x/crypto/chacha20poly1305` (already required), `github.com/xtaci/smux`.

Design spec: [docs/2026-09-30-p2p-e2e-encryption-design.md](docs/2026-09-30-p2p-e2e-encryption-design.md).

---

## Revision (v2): key lifetime is per (peer, transport), not per session

Implementation of Tasks 1–3 found that a **per-session** ephemeral is incompatible
with the engine's lifecycle: a `peerConn` can be rebuilt on one side alone (queue
overflow, or a peer restart the other end was not told about) while the other end
keeps its live smux session, so a per-session key would desync and every record
would fail authentication (`TestInboundRecoversAfterAdapterClosed`,
`TestPeerGoneFastFail`). Resolution (decision recorded in the design doc):

- The `secureSession` is scoped to **(peer, transport)**, cached on the engine,
  and **outlives the smux session**. A one-sided rebuild reuses the same
  ephemeral, key and counters.
- **Nonce counters are shared** per session+direction and passed by pointer into
  each `cryptoConn`, so a rebuilt session continues the sequence (a second
  `cryptoConn` over the pair's life is expected; `conn()` is *not* single-use).
- The ephemeral is **retained** for the session's life (needed to re-derive), not
  discarded after the first derivation.
- A **changed** peer ephemeral (peer restart) re-derives, resets the counters, and
  rebuilds the peer's smux session; an unchanged half is a no-op.

Concretely, Task 1's `cryptoConn` takes `*nonceCtr` send/recv counters instead of
owning them; Task 2's `respond` returns `(ok, changed)`; Task 3 caches the session
on `engine.secure` keyed by `{peer, transport}`. Tasks 4–6 use the same cached
session for the direct transport.

---

## Revision (v3): forced encryption, no fallback

The negotiated design this plan implements — a session built **plaintext** when the
peer's `ctrlSecure` half does not arrive — was **replaced by mandatory encryption**.
A session that does not settle now ends in **refusal** (`errEncryptionRequired`,
surfaced as `p2p.ErrEncryptionRequired` / `codes.FailedPrecondition`), never
plaintext, and a peer that predates the feature is incompatible: no fallback, no
flag. Superseded by this revision: every step that builds a plaintext session on a
handshake timeout; Task 6's "mixed old/new pair falls back to plaintext and still
passes traffic" (a mixed pair is now refused); and the `requireEncryption` item in
"Open follow-ups" (forced encryption is now the behavior). The status fields are
kept, but `PlaintextPeers` is a constant 0 and `PeerEncryption` is `secure` for any
live peer. The cipher, the per-(peer, transport) lifetime, the `ctrlSecure` frame
and the `want`-bit heal are unchanged — the terminal state is refusal, not
plaintext.

---

## File structure

| File | Responsibility |
|---|---|
| `internal/host/secure.go` (new) | `cryptoConn` record layer; `secureSession` handshake state; key derivation; `ctrlSecure` payload codec. Pure — no engine dependency. |
| `internal/host/secure_test.go` (new) | Unit tests for the above. |
| `internal/host/engine.go` | `ctrlSecure` const; `handleControl` case; `peerConn.secure`; handshake in `ensureSession`; wrap in `sessionLocked`; `secureHalf` sender; status counters. |
| `internal/host/direct.go` | transport const; `directConn.secure`; punch sends/awaits the direct half; wrap the KCP conn. |
| `status.go`, `grpc/rpc.go`, `../plugin/p2p/proto/p2p.proto` | `EncryptedPeers`/`PlaintextPeers` in `Status` and over gRPC. |

---

## Task 1: `cryptoConn` record layer

**Files:**
- Create: `internal/host/secure.go`
- Test: `internal/host/secure_test.go`

- [ ] **Step 1: Write the failing test**

```go
package host

import (
	"bytes"
	"io"
	"net"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestCryptoConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	send, _ := chacha20poly1305.New(bytes.Repeat([]byte{1}, 32))
	recv, _ := chacha20poly1305.New(bytes.Repeat([]byte{2}, 32))
	// a seals with key 1, opens with key 2; b is the mirror.
	ca := newCryptoConn(a, send, recv)
	cb := newCryptoConn(b, recv, send)

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

func TestCryptoConnTamperFails(t *testing.T) {
	// A flipped ciphertext byte must fail auth, not return plaintext.
	key := bytes.Repeat([]byte{7}, 32)
	aead, _ := chacha20poly1305.New(key)
	var nonce [12]byte
	ct := aead.Seal(nil, nonce[:], []byte("secret"), nil)
	ct[0] ^= 0xff
	if _, err := aead.Open(nil, nonce[:], ct, nil); err == nil {
		t.Fatal("tampered record authenticated")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd p2p && go test ./internal/host/ -run TestCryptoConn -v`
Expected: FAIL — `undefined: newCryptoConn`.

- [ ] **Step 3: Write `secure.go`**

```go
package host

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"golang.org/x/crypto/chacha20poly1305"
)

// maxSecureRecord bounds one AEAD record's plaintext. 16 KiB keeps the 4-byte
// length prefix and the 16-byte tag at ~0.1% overhead.
const maxSecureRecord = 16 * 1024

// Secure transport tags: the ctrlSecure frame's first byte, so the relay
// session's handshake and the direct session's never collide.
const (
	secureTransportRelay  byte = 0x00
	secureTransportDirect byte = 0x01
)

// handshakeTimeout bounds waiting for the peer's handshake half. Both peers
// send their half eagerly, so a healthy wait is one control round trip
// (sub-second); the bound only bites for a peer that does not support it.
var handshakeTimeout = 3 * time.Second

// cryptoConn is a net.Conn that seals/opens a byte stream as AEAD records:
// [4B big-endian length][ciphertext+tag]. Each direction has its own key and its
// own implicit 64-bit counter nonce (never transmitted — both underlays are
// reliable and ordered). A record that fails to authenticate is fatal.
type cryptoConn struct {
	net.Conn
	send, recv cipher.AEAD

	wmu  sync.Mutex
	wctr uint64

	rmu  sync.Mutex
	rctr uint64
	rbuf []byte
}

func newCryptoConn(underlay net.Conn, send, recv cipher.AEAD) *cryptoConn {
	return &cryptoConn{Conn: underlay, send: send, recv: recv}
}

func (c *cryptoConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxSecureRecord {
			n = maxSecureRecord
		}
		var nonce [12]byte
		binary.BigEndian.PutUint64(nonce[4:], c.wctr)
		c.wctr++
		ct := c.send.Seal(nil, nonce[:], p[:n], nil)
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
		if _, err := c.Conn.Write(hdr[:]); err != nil {
			return total, err
		}
		if _, err := c.Conn.Write(ct); err != nil {
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
		return nil, fmt.Errorf("p2p: bad secure record length %d", n)
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, ct); err != nil {
		return nil, err
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], c.rctr)
	c.rctr++
	pt, err := c.recv.Open(nil, nonce[:], ct, nil)
	if err != nil {
		return nil, fmt.Errorf("p2p: secure record auth failed: %w", err)
	}
	return pt, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd p2p && CGO_ENABLED=1 go test -race -run TestCryptoConn ./internal/host/ -v`
Expected: PASS. (`TestCryptoConnTamperFails` is a guard on the primitive; delete it if you prefer — it does not exercise our code.)

- [ ] **Step 5: Commit (gated)**

```bash
cd p2p && git add internal/host/secure.go internal/host/secure_test.go
git commit -m "p2p: add AEAD record layer for session encryption"
```

---

## Task 2: ephemeral handshake and key derivation

**Files:**
- Modify: `internal/host/secure.go` (append)
- Test: `internal/host/secure_test.go` (append)

- [ ] **Step 1: Write the failing test**

```go
func TestSecureSessionNegotiatesDeterministically(t *testing.T) {
	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a := newSecureSession(secureTransportRelay, privA, pubB)
	b := newSecureSession(secureTransportRelay, privB, pubA)

	// Exchange halves the way the engine does: seal with the static key, open
	// with the peer's static key.
	pa, err := a.start()
	if err != nil {
		t.Fatal(err)
	}
	clear, ok := privB.OpenFrom(pubA, pa)
	if !ok || !b.respond(clear) {
		t.Fatal("b rejected a's half")
	}
	pb, _ := b.start()
	clear, ok = privA.OpenFrom(pubB, pb)
	if !ok || !a.respond(clear) {
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
	a := newSecureSession(secureTransportDirect, privA, pubB)
	b := newSecureSession(secureTransportRelay, privB, pubA)
	pa, _ := a.start()                    // sealed by a, tagged direct
	clear, ok := privB.OpenFrom(pubA, pa) // b opens it
	if !ok {
		t.Fatal("seal/open round trip failed")
	}
	if b.respond(clear) {
		t.Fatal("accepted a direct half on a relay session")
	}
}

func TestSecureSessionTimesOut(t *testing.T) {
	privA, _, _ := derpclient.Generate()
	_, pubB, _ := derpclient.Generate()
	a := newSecureSession(secureTransportRelay, privA, pubB)
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd p2p && go test ./internal/host/ -run TestSecureSession -v`
Expected: FAIL — `undefined: newSecureSession`.

- [ ] **Step 3: Append the handshake to `secure.go`**

```go
// secureSession drives one mux session's ephemeral handshake. It holds no I/O:
// the caller seals/sends the half returned by start and feeds the peer's opened
// half to respond. Once both halves are present the directional AEAD keys are
// derived; until then the session is plaintext.
type secureSession struct {
	transport byte
	local     derpclient.PrivateKey
	peer      derpclient.PublicKey

	mu      sync.Mutex
	started bool
	eph     *ecdh.PrivateKey
	ephPub  []byte
	peerEph []byte
	sendKey []byte
	recvKey []byte
	ready   bool
	peerCh  chan struct{}
}

func newSecureSession(transport byte, local derpclient.PrivateKey, peer derpclient.PublicKey) *secureSession {
	return &secureSession{transport: transport, local: local, peer: peer, peerCh: make(chan struct{})}
}

// start generates our ephemeral on the first call and returns the sealed
// ctrlSecure payload to send; later calls re-seal the same public half (a
// resend). It never errors on the ephemeral after the first success.
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
	payload := append([]byte{s.transport}, s.ephPub...)
	return s.local.SealTo(s.peer, payload), nil
}

// respond consumes the peer's half (already opened from its box). It returns
// false for a malformed payload or one tagged for another transport, so a
// relay half cannot be fed to a direct session.
func (s *secureSession) respond(clear []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(clear) != 1+32 || clear[0] != s.transport {
		return false
	}
	s.peerEph = append([]byte(nil), clear[1:]...)
	s.deriveLocked()
	select {
	case <-s.peerCh:
	default:
		close(s.peerCh)
	}
	return true
}

// deriveLocked mixes the two ephemerals into the directional keys once both are
// present. The salt is the ordered concatenation of both public halves and the
// info binds the transport, so relay and direct sessions never share a key.
func (s *secureSession) deriveLocked() {
	if s.ready || s.eph == nil || s.peerEph == nil {
		return
	}
	peerPub, err := ecdh.X25519().NewPublicKey(s.peerEph)
	if err != nil {
		return
	}
	ss, err := s.eph.ECDH(peerPub)
	if err != nil {
		return
	}
	a, b := s.ephPub, s.peerEph
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	salt := append(append([]byte(nil), a...), b...)
	keys, err := hkdf.Key(sha256.New, ss, salt, "p2p-session-v1"+string([]byte{s.transport}), 64)
	if err != nil {
		return
	}
	// Direction by static-key order: the lower key claims keys[0:32] as its
	// send. Both ends compute the same comparison, so send matches recv.
	k0, k1 := keys[:32], keys[32:64]
	if bytes.Compare(s.local.Public()[:], s.peer[:]) < 0 {
		s.sendKey, s.recvKey = k0, k1
	} else {
		s.sendKey, s.recvKey = k1, k0
	}
	s.ready = true
}

// waitReady blocks until the peer's half arrives or d elapses, then reports
// whether the session settled encrypted.
func (s *secureSession) waitReady(d time.Duration) bool {
	select {
	case <-s.peerCh:
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

// conn wraps underlay with the session cipher, or returns it unchanged when the
// session settled plaintext (the peer does not support encryption).
func (s *secureSession) conn(underlay net.Conn) (net.Conn, error) {
	send, recv, ok := s.keys()
	if !ok {
		return underlay, nil
	}
	sa, err := chacha20poly1305.New(send)
	if err != nil {
		return nil, err
	}
	ra, err := chacha20poly1305.New(recv)
	if err != nil {
		return nil, err
	}
	return newCryptoConn(underlay, sa, ra), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd p2p && CGO_ENABLED=1 go test -race -run TestSecureSession ./internal/host/ -v`
Expected: PASS (all three).

- [ ] **Step 5: Commit (gated)**

```bash
cd p2p && git add internal/host/secure.go internal/host/secure_test.go
git commit -m "p2p: add ephemeral handshake and session key derivation"
```

---

## Task 3: relay path integration

**Files:**
- Modify: `internal/host/engine.go`
- Test: `internal/host/engine_test.go`

**Test scaffolding (add once to `internal/host/engine_test.go`).** The existing
`relayServer` + `startEcho` + `newEngine` scaffolding is reused:

```go
// newEncryptedPair starts two engines on one in-process relay with the echo
// target, connected and ready.
func newEncryptedPair(t *testing.T) (*engine, *engine, *relayServer) {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)
	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	eA := newEngine(url, "", privA, slog.Default())
	eB := newEngine(url, echo, privB, slog.Default())
	t.Cleanup(func() { eA.Close(); eB.Close() })
	if err := eA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := eB.Connect(); err != nil {
		t.Fatal(err)
	}
	return eA, eB, rs
}

// peerSecureForTest reports whether this engine's session to peer is encrypted.
func (e *engine) peerSecureForTest(peer derpclient.PublicKey) bool {
	e.mu.Lock()
	pc := e.peers[peer] // adjust to the actual map field on *engine
	e.mu.Unlock()
	if pc == nil {
		return false
	}
	_, _, ok := pc.secure.keys()
	return ok
}

// StatusForTest exposes the engine's status snapshot to tests.
func (e *engine) StatusForTest() *p2p.Status { return e.status() } // adjust to the real snapshot method
```

`directSecureForTest` (Task 4) reads `e.directs[peer].secure.keys()`. `waitDirect`
(Task 4) reuses whatever helper `direct_test.go` already polls with; if named
differently, adapt.

- [ ] **Step 1: Add the frame kind and transport consts**

In `internal/host/direct.go`, extend the kind block (around line 45) and add the
transport tags next to it (they already live in `secure.go`, so only the kind is
new):

```go
	ctrlPunchCandidates = 0x02 // sealed candidate list
	ctrlCaps            = 0x04 // sealed capability bitfield (forward-looking seam)
	ctrlSecure          = 0x05 // sealed [transport][ephemeral X25519 public key]
	// 0x03 was the udp dial notice: a datagram link now always presents its own
	// edge, so no notice is sent and none is acted on. The kind stays unused.
```

- [ ] **Step 2: Write the failing test**

The engine's relay session is built lazily; the handshake must complete first.
Drive two engines through a test relay (the pattern already in `engine_test.go`)
and assert the session is encrypted and a round-trip works.

```go
func TestRelaySessionEncrypted(t *testing.T) {
	// Two engines wired to one in-process DERP relay (see newTestRelay in this
	// file). Bring both relay sessions up, open a stream from A to B, and assert
	// both sides report an encrypted session and bytes round-trip.
	eA, eB, relay := newEncryptedPair(t)
	defer eA.Close()
	defer eB.Close()
	defer relay.Close()

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("round trip: got %q", buf)
	}
	if !eA.peerSecureForTest(eB.pub) || !eB.peerSecureForTest(eA.pub) {
		t.Fatal("session did not settle encrypted")
	}
}
```

(Add `newEncryptedPair` / `peerSecureForTest` in the test file as thin helpers
over the existing relay-test scaffolding; if a named relay helper is not present,
reuse whatever `TestEngineRelay*` already builds.)

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd p2p && go test ./internal/host/ -run TestRelaySessionEncrypted -v`
Expected: FAIL — the session is plaintext / helpers undefined.

- [ ] **Step 4: Add `secure` to `peerConn` and create it in `peerConn()`**

In `internal/host/engine.go`, add the field to the struct (near `peer`):

```go
type peerConn struct {
	e       *engine
	peer    derpclient.PublicKey
	secure  *secureSession
	inbound chan []byte
	// ...(unchanged)
}
```

In `peerConn(peer)` where the adapter is constructed, set it:

```go
	pc := &peerConn{
		e:       e,
		peer:    peer,
		secure:  newSecureSession(secureTransportRelay, e.priv, peer),
		inbound: make(chan []byte, inboundQueueSize),
		closeCh: make(chan struct{}),
	}
```

- [ ] **Step 5: Handle `ctrlSecure` in `handleControl`**

In `internal/host/engine.go` `handleControl`, add a case (rule (b): a received half
makes us answer with our own, so a one-sided tunnel cannot deadlock — the opener
cannot send data before the key exists, so it cannot trigger the peer with data):

```go
	case ctrlSecure:
		clear, ok := e.priv.OpenFrom(src, body[1:])
		if !ok || len(clear) < 1 {
			e.log.Debug("secure: bad box", "peer", keyName(src))
			return
		}
		switch clear[0] {
		case secureTransportRelay:
			pc := e.peerConn(src)
			if err := e.sendSecureHalf(pc); err != nil {
				e.log.Debug("secure: respond failed", "peer", keyName(src), "error", err)
			}
			pc.secure.respond(clear)
		case secureTransportDirect:
			dc := e.directConn(src)
			if err := e.sendSecureHalfDirect(dc); err != nil {
				e.log.Debug("secure: respond failed", "peer", keyName(src), "error", err)
			}
			dc.secure.respond(clear)
		}
```

- [ ] **Step 6: Add the half-sender and settle-then-build in `ensureSession`**

Add near `sendControl` calls in `engine.go`:

```go
// sendSecureHalf sends our relay-session handshake half to the peer. Idempotent
// (re-sealing the same public half); safe to call more than once.
func (e *engine) sendSecureHalf(pc *peerConn) error {
	sealed, err := pc.secure.start()
	if err != nil {
		return err
	}
	return e.sendControl(pc.peer, ctrlSecure, sealed)
}
```

Rework `ensureSession` so the handshake settles (outside `pc.mu`) before the
session is built. Replace the current body:

```go
func (pc *peerConn) ensureSession(punch bool) (*smux.Session, error) {
	// Fast path: a live session needs no handshake and no rebuild.
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return nil, errPeerSessionClosed
	}
	if pc.sess != nil && !pc.sess.IsClosed() {
		sess := pc.sess
		pc.mu.Unlock()
		if punch {
			pc.e.maybeStartDirect(pc.peer)
		}
		return sess, nil
	}
	pc.mu.Unlock()

	// No live session: settle the handshake before building, so both ends agree
	// on encrypted-vs-plaintext for this session. The send and the wait run
	// outside pc.mu: sendControl takes e.mu, which pc.mu is taken under
	// elsewhere, so holding pc.mu here would invert the two.
	if err := pc.e.sendSecureHalf(pc); err != nil {
		pc.e.log.Debug("secure: send half failed", "peer", keyName(pc.peer), "error", err)
	}
	pc.secure.waitReady(handshakeTimeout)

	pc.mu.Lock()
	sess, err := pc.sessionLocked()
	pc.mu.Unlock()
	if pc.takeChurnTripped() {
		pc.e.log.Error("derp: peer relay session churn, reconnecting the relay",
			"peer", keyName(pc.peer), "builds", relayChurnMax+1, "window", relayChurnWindow.String())
		pc.e.reconnectRelay(fmt.Errorf("peer %s rebuilt its relay session more than %d times in %v",
			keyName(pc.peer), relayChurnMax, relayChurnWindow))
	}
	if err == nil && punch {
		pc.e.maybeStartDirect(pc.peer)
	}
	return sess, err
}
```

- [ ] **Step 7: Wrap the underlay in `sessionLocked`**

In `sessionLocked`, build smux over the session cipher instead of `pc`:

```go
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = smuxKeepAliveInterval
	cfg.KeepAliveTimeout = smuxKeepAliveTimeout
	roleIsClient := bytes.Compare(pc.e.pub[:], pc.peer[:]) < 0
	underlay, err := pc.secure.conn(pc)
	if err != nil {
		return nil, err
	}
	if roleIsClient {
		pc.sess, _ = smux.Client(underlay, cfg)
	} else {
		pc.sess, _ = smux.Server(underlay, cfg)
	}
	// ...(unchanged from `if pc.sess == nil {`)
```

Add a log of the settled state next to the existing "peer relay session up" line:

```go
	_, _, enc := pc.secure.keys()
	pc.e.log.Debug("peer relay session up", "peer", keyName(pc.peer), "client", roleIsClient, "secure", enc)
```

- [ ] **Step 8: Run the tests**

Run: `cd p2p && CGO_ENABLED=1 go test -race -run 'TestRelay|TestEngine' ./internal/host/ -v`
Expected: PASS — new test passes and no existing engine test regresses.

- [ ] **Step 9: Commit (gated)**

```bash
cd p2p && git add internal/host/engine.go internal/host/direct.go internal/host/engine_test.go
git commit -m "p2p: encrypt the relay session with a negotiated handshake"
```

---

## Task 4: direct path integration

**Files:**
- Modify: `internal/host/direct.go`
- Test: `internal/host/direct_test.go`

- [ ] **Step 1: Add `secure` to `directConn` and create it**

```go
type directConn struct {
	// ...(unchanged fields)
	peerCaps uint8          // capability bits the peer advertised via ctrlCaps
	secure   *secureSession // direct-session handshake
	// ...(unchanged atomics)
}
```

In `directConn(peer)` where the struct is constructed, set
`secure: newSecureSession(secureTransportDirect, e.priv, peer)`.

- [ ] **Step 2: Write the failing test**

```go
func TestDirectSessionEncrypted(t *testing.T) {
	// Two engines, relay up, punch forced (the pattern in direct_test.go).
	// After the direct session is up, assert both report an encrypted direct
	// session and a stream opened over it round-trips.
	eA, eB, relay := newEncryptedPair(t)
	defer eA.Close()
	defer eB.Close()
	defer relay.Close()

	if err := eA.warm(eB.pub, true); err != nil {
		t.Fatal(err)
	}
	waitDirect(t, eA, eB) // existing helper pattern: poll until both see direct

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go conn.Write([]byte("direct"))
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "direct" {
		t.Fatalf("round trip: got %q", buf)
	}
	if !eA.directSecureForTest(eB.pub) {
		t.Fatal("direct session did not settle encrypted")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd p2p && go test ./internal/host/ -run TestDirectSessionEncrypted -v`
Expected: FAIL — helpers undefined / session plaintext.

- [ ] **Step 4: Add the direct half-sender**

```go
// sendSecureHalfDirect sends our direct-session handshake half over the relay
// control channel (which is up during a punch).
func (e *engine) sendSecureHalfDirect(dc *directConn) error {
	sealed, err := dc.secure.start()
	if err != nil {
		return err
	}
	return e.sendControl(dc.peer, ctrlSecure, sealed)
}
```

- [ ] **Step 5: Send the half at punch start**

In `punch`, right after the `sendCaps` call (around direct.go:669), add:

```go
	if err := e.sendSecureHalfDirect(dc); err != nil {
		e.log.Debug("direct punch: send secure half failed", "peer", pname, "error", err)
	}
```

- [ ] **Step 6: Settle and wrap before building smux**

In `punch`, just before the smux construction (around direct.go:766), settle the
handshake and wrap `kcpConn`:

```go
		// Settle the direct handshake before smux: by the time the KCP seed
		// round completes the peer's half has almost always arrived, so this is
		// a no-op wait on a healthy pair.
		if !dc.secure.waitReady(handshakeTimeout) {
			e.log.Debug("direct punch: secure half not received, plaintext session", "peer", pname)
		}

		cfg := directSmuxConfig(dc.supports(capsTightKeepalive))
		underlay, err := dc.secure.conn(kcpConn)
		if err != nil {
			kcpConn.Close()
			e.log.Debug("direct punch: secure wrap failed", "peer", pname, "error", err)
			continue
		}
		var sess *smux.Session
		if roleIsClient {
			sess, err = smux.Client(underlay, cfg)
		} else {
			sess, err = smux.Server(underlay, cfg)
		}
```

- [ ] **Step 7: Run the tests**

Run: `cd p2p && CGO_ENABLED=1 go test -race -run 'TestDirect|TestEngine' ./internal/host/ -v`
Expected: PASS — new test passes, existing direct tests unchanged.

- [ ] **Step 8: Commit (gated)**

```bash
cd p2p && git add internal/host/direct.go internal/host/direct_test.go
git commit -m "p2p: encrypt the direct session with a negotiated handshake"
```

---

## Task 5: observability

**Files:**
- Modify: `status.go`, `internal/host/engine.go`, `internal/host/host.go`, `grpc/rpc.go`, `../plugin/p2p/proto/p2p.proto`

- [ ] **Step 1: Add the in-process Status fields**

In `status.go`, add to `Status`:

```go
	// EncryptedPeers counts connected peers whose session settled encrypted;
	// PlaintextPeers counts those that did not (a peer that does not support
	// encryption, or a handshake that timed out). A negotiated peer can be
	// forced to plaintext by a relay that drops the handshake, so a nonzero
	// PlaintextPeers is the signal to watch.
	EncryptedPeers int
	PlaintextPeers int
	// PeerEncryption names each connected peer's session state, keyed by base64
	// public key: "secure" or "plaintext". In-process only, like PeerTransports.
	PeerEncryption map[string]string
```

- [ ] **Step 2: Write the failing test**

```go
func TestStatusReportsEncryption(t *testing.T) {
	eA, eB, relay := newEncryptedPair(t)
	defer eA.Close()
	defer eB.Close()
	defer relay.Close()

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	st := eA.StatusForTest() // thin accessor over the existing status snapshot
	if st.EncryptedPeers == 0 {
		t.Fatal("encrypted peer not reported")
	}
	if st.PeerEncryption[eB.PublicKey()] != "secure" {
		t.Fatalf("peer encryption = %q", st.PeerEncryption[eB.PublicKey()])
	}
}
```

- [ ] **Step 3: Populate it in `engine.status()`**

In `internal/host/engine.go` where the status snapshot is assembled (the same
place `PeerTransports` and `PeerPunches` are filled), iterate the peer conns and
set `EncryptedPeers`, `PlaintextPeers`, `PeerEncryption`; a peer counts only when
its relay session is live (`pc.sess != nil && !pc.sess.IsClosed()`), and is
`secure` when `pc.secure.keys()` reports ready. Add the exported pass-through in
`host.go` alongside the existing `PeerTransports` wiring, and the accessor in
`status.go`/`endpoint`.

- [ ] **Step 4: Add the gRPC fields**

In `../plugin/p2p/proto/p2p.proto`, extend `StatusReply`:

```proto
	int32 encrypted_peers = 8; // gauge: connected peers with an encrypted session
	int32 plaintext_peers = 9; // gauge: connected peers without one
```

Regenerate (pinned toolchain noted in the proto header):

```bash
cd plugin && protoc --proto_path=. --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative p2p/proto/p2p.proto
```

Map them in `grpc/rpc.go` `Status`:

```go
		EncryptedPeers: int32(st.EncryptedPeers),
		PlaintextPeers: int32(st.PlaintextPeers),
```

- [ ] **Step 5: Run the build and tests**

Run: `cd plugin && go build ./... && cd ../p2p && go build ./... && CGO_ENABLED=1 go test -race -run TestStatus ./internal/host/ ./grpc/ -v`
Expected: PASS. The `plugin` module is in `go.work`, so `p2p` resolves the new field locally.

- [ ] **Step 6: Commit (gated)**

```bash
cd plugin && git add p2p/proto/p2p.proto p2p/proto/*.go && git commit -m "plugin: report peer encryption gauges"
cd ../p2p && git add status.go internal/host/engine.go internal/host/host.go grpc/rpc.go internal/host/engine_test.go
git commit -m "p2p: report per-peer encryption state"
```

**Release note:** the `p2p` module pins `github.com/go-gost/plugin`; the new field
needs a pushed `plugin` tag before the `p2p` bump resolves (see the repo's
go-mod-bump ordering rule). Until then, keep the workspace build green.

---

## Task 6: end-to-end verification and docs

**Files:**
- Modify: `tests/e2e/e2e_test.go`, `README.md`, `CLAUDE.md`, `docs/embedding.md`

- [ ] **Step 1: Add the e2e scenarios**

In `tests/e2e/e2e_test.go`, extend the existing nested-netns scenario:

```go
// Assertion 1: a tcp tunnel through the relay carries ciphertext. Run tcpdump
// on the derper's loopback for the relay port during the transfer and assert no
// plaintext payload markers appear in the captured packets.
// Assertion 2: with --direct=false (relay-only), the same tunnel still encrypts
// and curl succeeds.
// Assertion 3: an old-version host (no ctrlSecure) paired with a current host
// falls back to plaintext and still passes traffic.
```

- [ ] **Step 2: Run the e2e suite**

Run (in the privileged container the harness requires, per the repo's e2e notes):
`go test ./gost/tests/e2e/ -v -timeout 10m`
Expected: PASS — existing scenarios green, the three new assertions green.

- [ ] **Step 3: Update the docs**

- `README.md` "Positioning" and "Security": the data plane is now encrypted end to
  end by default when both peers support it; the relay sees ciphertext only; a
  mixed-version pair falls back to plaintext, and (the caveat) a relay that drops
  the handshake can force that fallback. Update the "Encryption is out of scope by
  design" paragraph — it is now in scope for the data plane.
- `CLAUDE.md`: add the handshake to the "Trust boundary" section; add
  `internal/host/secure.go` to the package table; note the `ctrlSecure` frame.
- `docs/embedding.md`: note that an embedded endpoint's tunnels are encrypted to
  the peer automatically (no opt-in), and the plaintext-fallback condition.

- [ ] **Step 4: Full verification**

Run: `cd p2p && go build ./... && go vet ./... && GOWORK=off go build ./... && gofmt -l . && CGO_ENABLED=1 go test -race -count=1 ./...`
Expected: build clean, vet clean, `gofmt -l` prints nothing, all tests pass.

- [ ] **Step 5: Commit (gated)**

```bash
cd p2p && git add tests/e2e/e2e_test.go README.md CLAUDE.md docs/embedding.md
git commit -m "p2p: document and e2e-verify end-to-end session encryption"
```

---

## Open follow-ups (not in this plan)

- `requireEncryption` config knob that refuses a plaintext session (closes the
  downgrade caveat at the cost of the compat fallback).
- Traffic-analysis resistance (padding). Out of scope by design.
