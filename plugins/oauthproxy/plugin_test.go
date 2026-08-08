package oauthproxy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
)

func TestFactoryIdentityAndRuntimeValidation(t *testing.T) {
	if NewFactory().PluginID() != "oauth-proxy" {
		t.Fatalf("factory ID=%q", NewFactory().PluginID())
	}
	if _, err := New(Options{}); err == nil || !strings.Contains(err.Error(), "Runtime.Random is required") {
		t.Fatalf("standalone validation error=%v", err)
	}
}

func TestDedicatedSecretConfigUsesCurrentEnvelopeAndReadsRotatedKey(t *testing.T) {
	config, err := baCrypto.NewSecretConfig([]baCrypto.SecretEntry{
		{Version: 2, Value: "new-proxy-key"},
		{Version: 1, Value: "old-proxy-key"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	pluginValue := &plugin{options: Options{SecretConfig: &config}, runtime: Runtime{Random: repeatingReader(0x42)}}
	ciphertext, err := pluginValue.encryptProxy([]byte("profile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ciphertext, "$ba$2$") {
		t.Fatalf("current envelope=%q", ciphertext)
	}
	plaintext, err := pluginValue.decryptProxy(ciphertext)
	if err != nil || string(plaintext) != "profile" {
		t.Fatalf("decrypt=%q err=%v", plaintext, err)
	}
	oldCiphertext, err := baCrypto.EncryptWithReader("old-proxy-key", []byte("old-profile"), repeatingReader(0x24))
	if err != nil {
		t.Fatal(err)
	}
	oldCiphertext = baCrypto.FormatEnvelope(1, oldCiphertext)
	plaintext, err = pluginValue.decryptProxy(oldCiphertext)
	if err != nil || string(plaintext) != "old-profile" {
		t.Fatalf("rotated decrypt=%q err=%v", plaintext, err)
	}
}

func TestPassthroughDatesUseJavaScriptMillisecondISOFormat(t *testing.T) {
	value := time.Date(2026, time.August, 9, 12, 34, 56, 987654321, time.FixedZone("x", 3*60*60))
	encoded, err := json.Marshal(passthroughAccount{AccessTokenExpiresAt: isoTimePointer(&value)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"accessTokenExpiresAt":"2026-08-09T09:34:56.987Z"`) {
		t.Fatalf("date JSON=%s", encoded)
	}
	var decoded passthroughAccount
	if err := json.Unmarshal([]byte(`{"accessTokenExpiresAt":"2026-08-09T09:34:56.987Z"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if got := timePointer(decoded.AccessTokenExpiresAt); got == nil || got.Nanosecond() != 987000000 {
		t.Fatalf("decoded date=%v", got)
	}
}

type repeatingReader byte

func (reader repeatingReader) Read(target []byte) (int, error) {
	for index := range target {
		target[index] = byte(reader)
	}
	return len(target), nil
}
