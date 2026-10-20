package host

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

func TestNewDoesNotCreateMissingKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.key")
	h, err := New(&p2p.Config{Derp: "http://127.0.0.1:1", Key: path})
	if err == nil {
		_ = h.Close()
		t.Fatal("New succeeded with a missing key file")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("New created the key file: stat err = %v", statErr)
	}
}

func TestNewRequiresIdentity(t *testing.T) {
	h, err := New(&p2p.Config{Derp: "http://127.0.0.1:1"})
	if err == nil {
		_ = h.Close()
		t.Fatal("New succeeded without an identity")
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Fatalf("error = %v, want it to mention identity", err)
	}
}

func TestNewAcceptsInlineHexKey(t *testing.T) {
	hexKey, pub, err := p2p.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	h, err := New(&p2p.Config{Derp: "http://127.0.0.1:1", Key: hexKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer h.Close()
	if h.PublicKey() != pub {
		t.Fatalf("host public key = %q, want %q", h.PublicKey(), pub)
	}
}

func TestNewReadsExistingKeyFile(t *testing.T) {
	priv, pub, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := New(&p2p.Config{Derp: "http://127.0.0.1:1", Key: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer h.Close()
	if want := base64.RawURLEncoding.EncodeToString(pub[:]); h.PublicKey() != want {
		t.Fatalf("PublicKey = %q, want %q", h.PublicKey(), want)
	}
}
