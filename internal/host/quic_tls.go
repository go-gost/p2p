package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"time"
)

// quicALPN is the only application protocol the QUIC data plane speaks. Both
// ends offer exactly this value, so a peer that is not running the QUIC
// transport fails the TLS handshake instead of negotiating a different use of
// the connection.
const quicALPN = "p2p-quic/1"

// QUIC caps parameters advertised with capsQUIC. The version byte identifies
// the QUIC data-plane protocol and the batch version identifies the relay
// batching framing (see capsTLVQUIC). Both are validated by the transport
// setup; this task only publishes them.
const (
	quicCapsVersion      = 1
	quicCapsBatchVersion = 1
)

// quicIdentity is the per-engine QUIC TLS identity. The certificate is
// self-signed and never verified as an X.509 chain: the peer pins the exact DER
// fingerprint exchanged in caps.
type quicIdentity struct {
	cert tls.Certificate
	fp   [32]byte
}

// newQUICIdentity generates a fresh Ed25519 self-signed certificate. The
// fingerprint is SHA-256 over the DER encoding, the same value advertised in
// caps and compared after the TLS handshake.
func newQUICIdentity() (*quicIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: base64.RawURLEncoding.EncodeToString(pub),
		},
		// The validity window follows the QUIC design: an hour of clock-skew
		// allowance behind, one year ahead. The trust decision is the exact DER
		// pin, not this window.
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	return &quicIdentity{
		cert: tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		},
		fp: sha256.Sum256(der),
	}, nil
}

// fingerprint returns the identity's certificate fingerprint.
func (id *quicIdentity) fingerprint() [32]byte {
	return id.fp
}

// quicTLSConfig builds one end of the QUIC TLS handshake. Both ends present a
// certificate and pin the peer's exact DER fingerprint; there is no insecure
// mode and no fallback to ordinary X.509 verification.
func quicTLSConfig(id *quicIdentity, peerFP [32]byte, server bool) *tls.Config {
	cfg := &tls.Config{
		Certificates:          []tls.Certificate{id.cert},
		NextProtos:            []string{quicALPN},
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: pinFingerprint(peerFP),
	}
	if server {
		// Require a client certificate without CA validation: the pin below is
		// the only trust decision.
		cfg.ClientAuth = tls.RequireAnyClientCert
	} else {
		// The pin replaces the certificate-chain check entirely. Without this
		// the self-signed certificate would be rejected before the pin runs.
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

// pinFingerprint returns a VerifyPeerCertificate callback that accepts exactly
// one certificate, identified by the SHA-256 of its DER encoding. An empty
// chain is a failure, so a peer cannot omit the identity and pass the pin.
func pinFingerprint(want [32]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("quic: peer certificate missing")
		}
		got := sha256.Sum256(rawCerts[0])
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			return errors.New("quic: peer certificate fingerprint mismatch")
		}
		return nil
	}
}
