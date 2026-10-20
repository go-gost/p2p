package p2p

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateKeyRoundTrip(t *testing.T) {
	hexKey, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatalf("hex key: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("hex key decodes to %d bytes, want 32", len(raw))
	}
	if pub == "" {
		t.Fatal("public key is empty")
	}
	got, err := PublicKeyFromHex(hexKey)
	if err != nil {
		t.Fatalf("PublicKeyFromHex: %v", err)
	}
	if got != pub {
		t.Fatalf("PublicKeyFromHex = %q, want %q", got, pub)
	}
}

func TestIsHexKey(t *testing.T) {
	if !IsHexKey(strings.Repeat("11", 32)) {
		t.Fatal("IsHexKey(64 hex chars) = false, want true")
	}
	if !IsHexKey("  " + strings.Repeat("AA", 32) + "\n") {
		t.Fatal("IsHexKey should ignore surrounding whitespace and accept uppercase hex")
	}
	for _, in := range []string{
		"",
		"11",
		strings.Repeat("11", 31),
		strings.Repeat("11", 33),
		strings.Repeat("zz", 32),
	} {
		if IsHexKey(in) {
			t.Errorf("IsHexKey(%q) = true, want false", in)
		}
	}
}

func TestPublicKeyFromHexRejectsBadInput(t *testing.T) {
	cases := []string{
		"",
		"zz",
		strings.Repeat("11", 31),
		strings.Repeat("11", 33),
	}
	for _, in := range cases {
		if _, err := PublicKeyFromHex(in); err == nil {
			t.Errorf("PublicKeyFromHex(%q) succeeded, want an error", in)
		}
	}
}
