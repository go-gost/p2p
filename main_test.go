package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedPEM returns a PEM-encoded self-signed cert for a throwaway key.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "derper"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestBuildTLSConfig covers the relay TLS options: default verification,
// skip-verify, and trusting a self-signed cert via a CA file.
func TestBuildTLSConfig(t *testing.T) {
	// defaults (secure, no CA) → nil so derpclient uses Go's normal verification
	if cfg := buildTLSConfig(true, ""); cfg != nil {
		t.Fatalf("secure + no CA = %v, want nil", cfg)
	}

	// insecure → skip verification
	if cfg := buildTLSConfig(false, ""); cfg == nil || !cfg.InsecureSkipVerify {
		t.Fatalf("insecure config = %v, want InsecureSkipVerify=true", cfg)
	}

	// valid CA → trusted roots, verification kept
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, selfSignedPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := buildTLSConfig(true, caFile)
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatalf("secure + CA = %v, want RootCAs set", cfg)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("secure + CA must not skip verification")
	}

	// missing CA file → fall back to default roots, still no skip
	cfg = buildTLSConfig(true, filepath.Join(dir, "missing.pem"))
	if cfg == nil || cfg.RootCAs != nil {
		t.Fatalf("missing CA = %v, want RootCAs nil", cfg)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("missing CA must not skip verification")
	}
}
