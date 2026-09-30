package host

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
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
	ca := newCryptoConn(a, send, recv, &asc, &arc, &sync.Mutex{}, nil, derpclient.PublicKey{})
	cb := newCryptoConn(b, recv, send, &bsc, &brc, &sync.Mutex{}, nil, derpclient.PublicKey{})

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
	c := newCryptoConn(a, aead, aead, &nonceCtr{}, &nonceCtr{}, &sync.Mutex{}, nil, derpclient.PublicKey{})
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
	c := newCryptoConn(a, aead, aead, &nonceCtr{}, &nonceCtr{}, &sync.Mutex{}, nil, derpclient.PublicKey{})
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
