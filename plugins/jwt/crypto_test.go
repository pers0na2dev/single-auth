package jwt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
)

func TestGenerateExportedKeyPairAlgorithms(t *testing.T) {
	tests := []struct {
		config KeyPairConfig
		kty    string
		curve  string
		field  string
		length int
	}{
		{KeyPairConfig{Algorithm: EdDSA, Curve: "Ed25519"}, "OKP", "Ed25519", "x", 43},
		{KeyPairConfig{Algorithm: ES256}, "EC", "P-256", "x", 43},
		{KeyPairConfig{Algorithm: ES512}, "EC", "P-521", "x", 88},
		{KeyPairConfig{Algorithm: PS256}, "RSA", "", "n", 342},
		{KeyPairConfig{Algorithm: RS256}, "RSA", "", "n", 342},
	}
	for _, test := range tests {
		t.Run(string(test.config.Algorithm), func(t *testing.T) {
			pair, err := GenerateExportedKeyPair(Options{JWKS: JWKSOptions{
				KeyPair: &test.config, DisablePrivateKeyEncryption: true,
			}})
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []map[string]any{pair.PublicKey, pair.PrivateKey} {
				if key["kty"] != test.kty {
					t.Fatalf("kty = %#v, want %q", key["kty"], test.kty)
				}
				if len(key[test.field].(string)) != test.length {
					t.Fatalf("%s length = %d, want %d", test.field, len(key[test.field].(string)), test.length)
				}
				if test.curve != "" && key["crv"] != test.curve {
					t.Fatalf("crv = %#v, want %q", key["crv"], test.curve)
				}
			}
			if _, exists := pair.PublicKey["d"]; exists {
				t.Fatal("public JWK leaked private exponent")
			}
			if pair.PrivateKey["d"] == nil {
				t.Fatal("private JWK missing private exponent")
			}
			if _, err := json.Marshal(pair.PrivateKey); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoredPrivateJWKUsesReferenceSymmetricCiphertext(t *testing.T) {
	clock := &testClock{now: time.Now()}
	store := &keyStore{}
	options := baseTestOptions(store, clock)
	implementation, err := normalize(options, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := implementation.createJWK(nil); err != nil {
		t.Fatal(err)
	}
	stored := store.snapshot()[0]
	var ciphertext string
	if err := json.Unmarshal([]byte(stored.PrivateKey), &ciphertext); err != nil {
		t.Fatalf("private key is not JSON-stringified ciphertext: %v", err)
	}
	plaintext, err := baCrypto.Decrypt(testSecret, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plaintext), `"kty":"OKP"`) || !strings.Contains(string(plaintext), `"d":`) {
		t.Fatalf("decrypted JWK = %s", plaintext)
	}
}

func TestGenerateExportedKeyPairDefaultsToEd25519(t *testing.T) {
	pair, err := GenerateExportedKeyPair(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if pair.Algorithm != EdDSA || pair.Curve != "Ed25519" || pair.PublicKey["kty"] != "OKP" {
		t.Fatalf("default pair = %#v", pair)
	}
}
