package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

func TestQUICIdentityFingerprint(t *testing.T) {
	id, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if len(id.cert.Certificate) != 1 {
		t.Fatalf("certificate chain length = %d, want 1", len(id.cert.Certificate))
	}
	if sum := sha256.Sum256(id.cert.Certificate[0]); id.fingerprint() != sum {
		t.Fatal("fingerprint != sha256(DER)")
	}
}

func TestQUICIdentityCertificate(t *testing.T) {
	id, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(id.cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if leaf.NotBefore.After(now.Add(-59*time.Minute)) || leaf.NotBefore.Before(now.Add(-61*time.Minute)) {
		t.Fatalf("NotBefore = %v, want about -1h", leaf.NotBefore)
	}
	if leaf.NotAfter.Before(now.Add(364*24*time.Hour)) || leaf.NotAfter.After(now.Add(366*24*time.Hour)) {
		t.Fatalf("NotAfter = %v, want about +365d", leaf.NotAfter)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("KeyUsage = %v, want digitalSignature", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 2 {
		t.Fatalf("ExtKeyUsage = %v, want serverAuth+clientAuth", leaf.ExtKeyUsage)
	}
	wantEKU := map[x509.ExtKeyUsage]bool{
		x509.ExtKeyUsageServerAuth: false,
		x509.ExtKeyUsageClientAuth: false,
	}
	for _, u := range leaf.ExtKeyUsage {
		if _, ok := wantEKU[u]; !ok {
			t.Fatalf("unexpected ExtKeyUsage %v", u)
		}
		wantEKU[u] = true
	}
	for u, seen := range wantEKU {
		if !seen {
			t.Fatalf("ExtKeyUsage %v missing from %v", u, leaf.ExtKeyUsage)
		}
	}
	if leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		t.Fatalf("serial = %v, want a positive random value", leaf.SerialNumber)
	}
	pub, ok := id.cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T, want ed25519.PrivateKey", id.cert.PrivateKey)
	}
	cn, err := base64.RawURLEncoding.DecodeString(leaf.Subject.CommonName)
	if err != nil {
		t.Fatalf("CN %q is not base64: %v", leaf.Subject.CommonName, err)
	}
	if !bytes.Equal(cn, pub.Public().(ed25519.PublicKey)) {
		t.Fatal("CN does not encode the certificate public key")
	}
}

// tlsHandshakeResult is one end of a TLS handshake.
type tlsHandshakeResult struct {
	err   error
	state tls.ConnectionState
}

// handshakeTLS runs a TLS handshake over a loopback TCP connection with both
// ends live at once: a handshake cannot make progress if only one side runs.
// TCP is used instead of net.Pipe because its buffering lets the rejecting side
// return while the other side is still writing its flight; both raw conns are
// closed afterwards.
func handshakeTLS(t *testing.T, clientCfg, serverCfg *tls.Config) (client, server tlsHandshakeResult) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			acceptCh <- c
			return
		}
		close(acceptCh)
	}()
	clientConn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverConn, ok := <-acceptCh
	if !ok {
		t.Fatal("accept failed")
	}
	defer serverConn.Close()
	srv := tls.Server(serverConn, serverCfg)
	cli := tls.Client(clientConn, clientCfg)

	srvCh := make(chan tlsHandshakeResult, 1)
	cliCh := make(chan tlsHandshakeResult, 1)
	go func() {
		err := srv.Handshake()
		srvCh <- tlsHandshakeResult{err: err, state: srv.ConnectionState()}
	}()
	go func() {
		err := cli.Handshake()
		cliCh <- tlsHandshakeResult{err: err, state: cli.ConnectionState()}
	}()

	timer := time.AfterFunc(5*time.Second, func() {
		serverConn.Close()
		clientConn.Close()
	})
	defer timer.Stop()
	client = <-cliCh
	server = <-srvCh
	if !timer.Stop() {
		t.Fatal("TLS handshake did not finish")
	}
	return client, server
}

func TestQUICTLSMutualPinning(t *testing.T) {
	a, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, server := handshakeTLS(t,
		quicTLSConfig(a, b.fp, false),
		quicTLSConfig(b, a.fp, true),
	)
	if client.err != nil {
		t.Fatalf("client handshake: %v", client.err)
	}
	if server.err != nil {
		t.Fatalf("server handshake: %v", server.err)
	}
	if client.state.NegotiatedProtocol != quicALPN {
		t.Fatalf("client ALPN = %q, want %q", client.state.NegotiatedProtocol, quicALPN)
	}
	if server.state.NegotiatedProtocol != quicALPN {
		t.Fatalf("server ALPN = %q, want %q", server.state.NegotiatedProtocol, quicALPN)
	}
	if len(client.state.PeerCertificates) != 1 {
		t.Fatalf("client peer certificates = %d, want 1", len(client.state.PeerCertificates))
	}
	if got := sha256.Sum256(client.state.PeerCertificates[0].Raw); got != b.fp {
		t.Fatal("client did not pin the server certificate")
	}
	if len(server.state.PeerCertificates) != 1 {
		t.Fatalf("server peer certificates = %d, want 1", len(server.state.PeerCertificates))
	}
	if got := sha256.Sum256(server.state.PeerCertificates[0].Raw); got != a.fp {
		t.Fatal("server did not pin the client certificate")
	}
	if got := quicTLSConfig(a, b.fp, false).NextProtos; len(got) != 1 || got[0] != quicALPN {
		t.Fatalf("client NextProtos = %v, want [%q]", got, quicALPN)
	}
}

func TestQUICTLSRejectsWrongFingerprint(t *testing.T) {
	a, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrong := b.fp
	wrong[0] ^= 0xff
	client, _ := handshakeTLS(t,
		quicTLSConfig(a, wrong, false),
		quicTLSConfig(b, a.fp, true),
	)
	if client.err == nil {
		t.Fatal("client handshake succeeded with a wrong server fingerprint")
	}
}

func TestQUICTLSRejectsWrongClientFingerprint(t *testing.T) {
	a, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrong := a.fp
	wrong[0] ^= 0xff
	_, server := handshakeTLS(t,
		quicTLSConfig(a, b.fp, false),
		quicTLSConfig(b, wrong, true),
	)
	if server.err == nil {
		t.Fatal("server handshake succeeded with a wrong client fingerprint")
	}
}

func TestPinFingerprintRejectsEmptyChain(t *testing.T) {
	if err := pinFingerprint([32]byte{})(nil, nil); err == nil {
		t.Fatal("empty certificate chain passed the pin")
	}
}

func TestQUICTLSRequiresClientCert(t *testing.T) {
	a, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	anonymous := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{quicALPN},
	}
	_, server := handshakeTLS(t, anonymous, quicTLSConfig(b, a.fp, true))
	if server.err == nil {
		t.Fatal("server handshake succeeded without a client certificate")
	}
}

func TestQUICTLSALPN(t *testing.T) {
	a, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientCfg := quicTLSConfig(a, b.fp, false)
	clientCfg.NextProtos = []string{"p2p-quic/2"}
	client, server := handshakeTLS(t, clientCfg, quicTLSConfig(b, a.fp, true))
	if client.err == nil && server.err == nil {
		t.Fatal("handshake succeeded with mismatched ALPN")
	}
	if client.state.NegotiatedProtocol == quicALPN {
		t.Fatal("client negotiated quicALPN despite a mismatch")
	}
}

func TestCapsIncludesQUICFingerprint(t *testing.T) {
	id, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{transport: transportQUIC, quicID: id}
	ci := e.caps()
	if ci.Bits&capsQUIC == 0 {
		t.Fatalf("bits = %#x, want capsQUIC set", ci.Bits)
	}
	if ci.QUIC == nil {
		t.Fatal("QUIC TLV missing")
	}
	if ci.QUIC.Fingerprint != id.fp {
		t.Fatal("QUIC TLV fingerprint != identity fingerprint")
	}
	if ci.QUIC.Version != quicCapsVersion {
		t.Fatalf("QUIC version = %d, want %d", ci.QUIC.Version, quicCapsVersion)
	}
	if ci.QUIC.BatchVersion != quicCapsBatchVersion {
		t.Fatalf("batch version = %d, want %d", ci.QUIC.BatchVersion, quicCapsBatchVersion)
	}
}

func TestCapsNoQUICInKCPMode(t *testing.T) {
	id, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{transport: transportKCP, quicID: id}
	ci := e.caps()
	if ci.Bits&capsQUIC != 0 {
		t.Fatalf("bits = %#x, want no capsQUIC in KCP mode", ci.Bits)
	}
	if ci.QUIC != nil {
		t.Fatal("QUIC TLV present in KCP mode")
	}
}

func TestQUICIdentityOnlyInQUICMode(t *testing.T) {
	hexKey, _, err := p2p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		transport string
		want      bool
	}{
		{"kcp", "", false},
		{"quic", "quic", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := New(&p2p.Config{Derp: "http://127.0.0.1:1", Key: hexKey, Transport: tc.transport})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			if got := h.engine.quicID != nil; got != tc.want {
				t.Fatalf("quicID present = %v, want %v", got, tc.want)
			}
			if tc.want {
				if sum := sha256.Sum256(h.engine.quicID.cert.Certificate[0]); sum != h.engine.quicID.fp {
					t.Fatal("identity fingerprint != sha256(DER)")
				}
			}
		})
	}
}

// TestAnnounceDirectQUICCarriesFingerprint pins the carry-forward from Task 2:
// a warm/announceDirect in QUIC mode must send the QUIC bit and TLV, not a
// bits-only caps frame. A bits-only frame would make addCaps forget the peer's
// fingerprint, and a peer with direct off has no punch frame to restore it.
func TestAnnounceDirectQUICCarriesFingerprint(t *testing.T) {
	srv := &relayServer{}
	url := srv.start(t)

	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(url, "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.transport = transportQUIC
	e.quicID, err = newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	if err := e.Connect(); err != nil {
		t.Fatal(err)
	}

	peerPriv, peerPub, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := derpclient.Dial(context.Background(), url, peerPriv, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })

	e.announceDirect(peerPub)

	type recvResult struct {
		pkt []byte
		err error
	}
	ch := make(chan recvResult, 1)
	go func() {
		_, pkt, err := peer.Recv()
		ch <- recvResult{pkt: pkt, err: err}
	}()
	var got recvResult
	select {
	case got = <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("peer did not receive the caps frame")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if len(got.pkt) < 3 || got.pkt[0] != frameControl || got.pkt[1] != ctrlCaps {
		t.Fatalf("caps frame = % x, want control/caps prefix", got.pkt)
	}
	clear, ok := peerPriv.OpenFrom(e.pub, got.pkt[2:])
	if !ok {
		t.Fatal("cannot open sealed caps payload")
	}
	info, err := decodeCaps(clear)
	if err != nil {
		t.Fatal(err)
	}
	if info.Bits&capsQUIC == 0 {
		t.Fatalf("caps bits = %#x, want capsQUIC", info.Bits)
	}
	if info.Bits&capsNoDirect == 0 {
		t.Fatalf("caps bits = %#x, want capsNoDirect on a host with no punch source", info.Bits)
	}
	if info.QUIC == nil || info.QUIC.Fingerprint != e.quicID.fp {
		t.Fatalf("caps QUIC = %+v, want fingerprint % x", info.QUIC, e.quicID.fp)
	}
}
