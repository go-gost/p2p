package host

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/internal/derpclient"
)

// loadKey returns the DERP identity from key: either a 64-character hex private
// key or a path to a key file. p2p never creates an identity or writes a key
// file: the caller owns generation and persistence (see p2p.GenerateKey). Bare
// mode (Derp unset) does not need an identity at all.
func loadKey(key string) (derpclient.PrivateKey, derpclient.PublicKey, error) {
	if p2p.IsHexKey(key) {
		return keyFromHex(key)
	}
	if strings.TrimSpace(key) == "" {
		return derpclient.PrivateKey{}, derpclient.PublicKey{},
			fmt.Errorf("p2p: identity required: set Key to a 64-character hex key or a key file path")
	}
	b, err := os.ReadFile(strings.TrimSpace(key))
	if err != nil {
		return derpclient.PrivateKey{}, derpclient.PublicKey{},
			fmt.Errorf("p2p: read key %s: %w", key, err)
	}
	return keyFromHex(string(b))
}

// PublicKeyFile returns the base64 public key of the identity at path,
// read-only. It never creates one, so a diagnostic can name the local identity
// without a side effect; it fails when path is empty, missing or malformed.
func PublicKeyFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("p2p: key path is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	_, pub, err := keyFromHex(string(b))
	if err != nil {
		return "", err
	}
	return keyName(pub), nil
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
