package host

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

// quietLogger keeps the strict-mode tests from printing the expected rejection
// debugs. Each engine gets its own logger so a shared logger cannot serialize
// unrelated tests through one handler.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestQUICStrictKCPPeerIsRejectedAndKCPStillWorks pins the strict side of the
// transport switch end to end: a QUIC host that has learned a KCP-only peer's
// caps refuses to open a stream to it, builds neither a QUIC pair nor a KCP
// pair, reports the failure as diagnostic-only state, and leaves the KCP peer's
// own KCP transport fully usable with another KCP host.
func TestQUICStrictKCPPeerIsRejectedAndKCPStillWorks(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privB, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privC, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}

	a := newQUICTestEngine(t, url, "", privA)
	b := newEngine(url, echo, privB, quietLogger())
	c := newEngine(url, "", privC, quietLogger())
	t.Cleanup(b.Close)
	t.Cleanup(c.Close)
	for name, e := range map[string]*engine{"a": a, "b": b, "c": c} {
		if err := e.Connect(); err != nil {
			t.Fatalf("connect %s: %v", name, err)
		}
	}

	// b is KCP-only: its caps frame has the legacy bits and no QUIC TLV. Send
	// it directly so a's refusal happens immediately instead of after the caps
	// timeout (b.warm would build a KCP session a never answers).
	if err := b.sendCaps(a.pub, capsInfo{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return peerCapsSeen(a, b.pub) })

	conn, err := a.OpenStream(b.PublicKey())
	if err == nil {
		conn.Close()
		t.Fatal("OpenStream to a KCP-only peer succeeded, want ErrTransportUnsupported")
	}
	if !errors.Is(err, p2p.ErrTransportUnsupported) {
		t.Fatalf("OpenStream error = %v, want ErrTransportUnsupported", err)
	}
	waitFor(t, 5*time.Second, func() bool {
		return a.quicTransportError(b.pub) == "peer-no-quic"
	})

	// Strict means no hidden data plane: a must not have built a QUIC pair or
	// a KCP pair, and the KCP peer must not have built a KCP session toward a
	// QUIC-only host either.
	if pair := a.getQUIC(b.pub); pair != nil {
		t.Fatalf("a built a QUIC pair to a KCP-only peer: %+v", pair)
	}
	if n := relayKCPCount(a); n != 0 {
		t.Fatalf("a built %d KCP pairs in QUIC mode, want 0", n)
	}
	if p := a.relayKCPPairGet(b.pub); p != nil {
		t.Fatal("a built a KCP pair to the rejected peer")
	}
	if p := b.relayKCPPairGet(a.pub); p != nil {
		t.Fatal("b built a KCP pair to the QUIC-only peer")
	}

	// The rejection is visible in diagnostics but must not inflate the
	// connected-peer surface (Task 12 contract).
	srv := newServer(a)
	t.Cleanup(srv.close)
	st := srv.status()
	key := b.PublicKey()
	d, ok := st.PeerDiagnostics[key]
	if !ok {
		t.Fatalf("no diagnostic for the rejected peer %s: %+v", key, st.PeerDiagnostics)
	}
	if d.Transport != "quic" {
		t.Fatalf("rejected peer transport = %q, want quic", d.Transport)
	}
	if d.Path != "" {
		t.Fatalf("rejected peer path = %q, want empty", d.Path)
	}
	if d.TransportError != "peer-no-quic" {
		t.Fatalf("rejected peer TransportError = %q, want peer-no-quic", d.TransportError)
	}
	if _, ok := st.PeerTransports[key]; ok {
		t.Fatalf("rejected peer leaked into PeerTransports: %+v", st.PeerTransports)
	}
	if st.DerpPeers != 0 || st.DirectPeers != 0 {
		t.Fatalf("rejected peer inflated gauges: %d direct / %d relay",
			st.DirectPeers, st.DerpPeers)
	}

	// b is still a healthy KCP host: c opens a normal KCP tunnel through it to
	// the echo target. If either side had switched transports this would fail.
	kconn, err := c.OpenStream(b.PublicKey())
	if err != nil {
		t.Fatalf("KCP OpenStream after the QUIC rejection: %v", err)
	}
	roundTrip(t, kconn, "kcp-still-works")
	kconn.Close()
	if p := c.relayKCPPairGet(b.pub); p == nil {
		t.Fatal("c has no KCP pair to b after a successful KCP round trip")
	}
	if n := relayKCPCount(a); n != 0 {
		t.Fatalf("a built %d KCP pairs after unrelated KCP traffic, want 0", n)
	}
	if p := b.relayKCPPairGet(a.pub); p != nil {
		t.Fatal("b built a KCP pair to the QUIC-only peer during unrelated traffic")
	}
}

// TestQUICStrictInvalidCapsNoConnection pins caps validation: a peer that
// claims QUIC but cannot supply a usable identity (missing TLV, wrong version,
// wrong batch version, or a TLV without the bit) is refused with
// ErrTransportUnsupported before any pair is created, and no KCP pair appears
// as a fallback.
func TestQUICStrictInvalidCapsNoConnection(t *testing.T) {
	validQUIC := quicCaps{
		Version:      quicCapsVersion,
		Fingerprint:  [32]byte{0x01},
		BatchVersion: quicCapsBatchVersion,
	}
	staleVersion := validQUIC
	staleVersion.Version = quicCapsVersion + 1
	staleBatch := validQUIC
	staleBatch.BatchVersion = quicCapsBatchVersion + 1

	cases := []struct {
		name string
		caps capsInfo
	}{
		{name: "missing TLV", caps: capsInfo{Bits: capsQUIC}},
		{name: "unsupported version", caps: capsInfo{Bits: capsQUIC, QUIC: &staleVersion}},
		{name: "unsupported batch", caps: capsInfo{Bits: capsQUIC, QUIC: &staleBatch}},
		{name: "TLV without bit", caps: capsInfo{Bits: 0, QUIC: &validQUIC}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := &relayServer{}
			url := rs.start(t)

			privA, _, err := derpclient.Generate()
			if err != nil {
				t.Fatal(err)
			}
			privB, _, err := derpclient.Generate()
			if err != nil {
				t.Fatal(err)
			}
			a := newQUICTestEngine(t, url, "", privA)
			b := newQUICTestEngine(t, url, "", privB)
			// Drop b's identity so its own caps()/maybeStartQUIC cannot replace
			// the deliberately invalid frame below with a valid one.
			b.quicID = nil
			if err := a.Connect(); err != nil {
				t.Fatal(err)
			}
			if err := b.Connect(); err != nil {
				t.Fatal(err)
			}

			if err := b.sendCaps(a.pub, tc.caps); err != nil {
				t.Fatal(err)
			}
			waitFor(t, 5*time.Second, func() bool { return peerCapsSeen(a, b.pub) })

			conn, err := a.OpenStream(b.PublicKey())
			if err == nil {
				conn.Close()
				t.Fatal("OpenStream succeeded with invalid QUIC caps")
			}
			if !errors.Is(err, p2p.ErrTransportUnsupported) {
				t.Fatalf("OpenStream error = %v, want ErrTransportUnsupported", err)
			}
			if pair := a.getQUIC(b.pub); pair != nil {
				t.Fatalf("a built a QUIC pair from invalid caps: %+v", pair)
			}
			if n := relayKCPCount(a); n != 0 {
				t.Fatalf("a built %d KCP pairs from invalid caps, want 0", n)
			}
			if n := relayKCPCount(b); n != 0 {
				t.Fatalf("b built %d KCP pairs from invalid caps, want 0", n)
			}
			if reason := a.quicTransportError(b.pub); reason == "" {
				t.Fatal("no transport-error reason recorded for invalid caps")
			}
		})
	}
}

// TestQUICStrictFingerprintMismatchNoConnection pins the other half of the
// no-pin contract: caps that look valid but name a certificate the peer does
// not hold pass caps validation, then fail the TLS pin. The open fails as an
// unreachable peer, the pair never establishes, and there is still no KCP
// fallback.
func TestQUICStrictFingerprintMismatchNoConnection(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privB, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newQUICTestEngine(t, url, echo, privA)
	b := newQUICTestEngine(t, url, echo, privB)
	// Advertise a fingerprint that is not the SHA-256 of b's certificate. The
	// caps frame is well formed, so validation passes and the pin rejects the
	// real certificate during the handshake. Shorten the handshake budget: a
	// rejection still has to wait for the losing side of the TLS exchange, and
	// the package default is 10s.
	b.quicID.fp = [32]byte{0xde, 0xad, 0xbe, 0xef}
	a.quicCfg.HandshakeTimeout = 2 * time.Second
	b.quicCfg.HandshakeTimeout = 2 * time.Second
	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := b.Connect(); err != nil {
		t.Fatal(err)
	}

	conn, err := a.OpenStream(b.PublicKey())
	if err == nil {
		conn.Close()
		t.Fatal("OpenStream succeeded against a mismatched certificate pin")
	}
	if !errors.Is(err, p2p.ErrPeerUnreachable) {
		t.Fatalf("OpenStream error = %v, want ErrPeerUnreachable", err)
	}
	if errors.Is(err, p2p.ErrTransportUnsupported) {
		t.Fatalf("fingerprint mismatch mapped to ErrTransportUnsupported: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool {
		return a.quicTransportError(b.pub) == "quic-handshake"
	})
	if pair := a.getQUIC(b.pub); pair != nil && pair.established() {
		t.Fatal("pair established despite the certificate pin mismatch")
	}
	if n := relayKCPCount(a); n != 0 {
		t.Fatalf("a built %d KCP pairs after a pin mismatch, want 0", n)
	}
	if n := relayKCPCount(b); n != 0 {
		t.Fatalf("b built %d KCP pairs after a pin mismatch, want 0", n)
	}
}
