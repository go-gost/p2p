package host

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-gost/p2p/internal/derpclient"
)

// defaultKeyPath is where the DERP key lives unless Config.Key or Config.KeyHex
// sets it.
func defaultKeyPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "p2p", "key-v1")
	}
	return "p2p-key-v1"
}

// loadOrCreateKey returns the DERP identity. hexKey (32 bytes hex) takes
// precedence and is used as-is; otherwise the hex-encoded private key is read
// from path, generating and storing a new one (0600) if the file is missing. An
// empty path falls back to defaultKeyPath. Setting both path and hexKey is an
// error: the caller must pick one source.
func loadOrCreateKey(path, hexKey string) (derpclient.PrivateKey, derpclient.PublicKey, error) {
	if hexKey != "" {
		if path != "" {
			return derpclient.PrivateKey{}, derpclient.PublicKey{},
				fmt.Errorf("p2p: set either Key or KeyHex, not both")
		}
		return keyFromHex(hexKey)
	}
	if path == "" {
		path = defaultKeyPath()
	}
	if b, err := os.ReadFile(path); err == nil {
		return keyFromHex(strings.TrimSpace(string(b)))
	}
	priv, pub, err := derpclient.Generate()
	if err != nil {
		return priv, pub, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return priv, pub, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv[:])+"\n"), 0o600); err != nil {
		return priv, pub, err
	}
	return priv, pub, nil
}

// keyFromHex decodes a hex-encoded 32-byte curve25519 private key.
func keyFromHex(s string) (derpclient.PrivateKey, derpclient.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return derpclient.PrivateKey{}, derpclient.PublicKey{}, fmt.Errorf("bad key: %w", err)
	}
	var priv derpclient.PrivateKey
	if len(raw) != len(priv) {
		return priv, derpclient.PublicKey{},
			fmt.Errorf("bad key: want %d hex bytes, got %d", len(priv), len(raw))
	}
	copy(priv[:], raw)
	return priv, priv.Public(), nil
}
