package p2p

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateKey returns a new curve25519 identity. hexKey is the 32-byte private
// key encoded as 64 hex characters; publicKey is the base64 (raw URL) public
// key used as the peer address. p2p does not store the identity: the caller
// owns persistence and passes hexKey back through Config.Key, which accepts
// either this hex form or a path to a key file.
//
// It uses crypto/ecdh from the standard library so importing the contract
// package still pulls in no engine or transport (see deps_test.go).
func GenerateKey() (hexKey, publicKey string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv.Bytes()), encodePublicKey(priv.PublicKey().Bytes()), nil
}

// PublicKeyFromHex returns the base64 (raw URL) public key of a hex-encoded
// 32-byte curve25519 private key. It is the read-only counterpart of
// GenerateKey, for callers that store the identity themselves.
func PublicKeyFromHex(hexKey string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return "", fmt.Errorf("p2p: bad key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("p2p: bad key: want 32 bytes, got %d", len(raw))
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("p2p: bad key: %w", err)
	}
	return encodePublicKey(priv.PublicKey().Bytes()), nil
}

// IsHexKey reports whether s is a 64-character hex-encoded private key, the
// inline form accepted by Config.Key. Consumers that own identity storage use
// it to tell key material from a file path without re-implementing the check.
// Surrounding whitespace is ignored, matching Config.Key parsing.
func IsHexKey(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func encodePublicKey(pub []byte) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}
