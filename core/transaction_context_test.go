package core

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestPluginHostAdapterForContextReusesActiveTransaction(t *testing.T) {
	auth := MustNew(Options{Secret: "0123456789abcdef0123456789abcdef"})
	host := auth.pluginHost(&auth.options, "transaction-probe")
	if got := host.AdapterForContext(t.Context()); got != host.Adapter {
		t.Fatalf("plain adapter = %#v, want root adapter", got)
	}

	var outer storage.TransactionAdapter
	err := auth.RunInTransaction(t.Context(), func(transactionContext context.Context) error {
		outer = host.AdapterForContext(transactionContext)
		if outer == nil || outer == host.Adapter {
			t.Fatalf("active adapter = %#v, root = %#v", outer, host.Adapter)
		}
		if err := auth.RunInTransaction(transactionContext, func(nested context.Context) error {
			if current := host.AdapterForContext(nested); current != outer {
				t.Fatalf("nested adapter = %#v, want %#v", current, outer)
			}
			return nil
		}); err != nil {
			return err
		}
		now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
		_, err := outer.Create(transactionContext, storage.CreateParams{
			Model: "verification",
			Data: storage.Record{
				"identifier": "transaction-probe", "value": "created",
				"expiresAt": now.Add(time.Hour), "createdAt": now, "updatedAt": now,
			},
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	row, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "transaction-probe"}},
	})
	if err != nil || row == nil || row["value"] != "created" {
		t.Fatalf("committed row = %#v err=%v", row, err)
	}
}

func TestPluginHostSecretEncryptionSupportsRotationAndLegacy(t *testing.T) {
	legacy := "legacy-secret-0123456789abcdef0123456789"
	auth := MustNew(Options{
		Secret: legacy,
		Secrets: []baCrypto.SecretEntry{
			{Version: 2, Value: "current-secret-0123456789abcdef012345678"},
			{Version: 1, Value: "previous-secret-0123456789abcdef01234567"},
		},
	})
	host := auth.pluginHost(&auth.options, "secret-probe")
	plaintext := []byte(`{"kty":"OKP","d":"private"}`)
	encrypted, err := host.EncryptSecret(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "$ba$2$") {
		t.Fatalf("encrypted envelope = %q", encrypted)
	}
	decrypted, err := host.DecryptSecret(encrypted)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("current decrypt = %q err=%v", decrypted, err)
	}

	oldConfig, err := baCrypto.NewSecretConfig([]baCrypto.SecretEntry{{
		Version: 1, Value: "previous-secret-0123456789abcdef01234567",
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope, err := baCrypto.EncryptWithConfigAndReader(
		oldConfig, plaintext, bytes.NewReader(make([]byte, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = host.DecryptSecret(oldEnvelope)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("rotated decrypt = %q err=%v", decrypted, err)
	}

	legacyCiphertext, err := baCrypto.EncryptWithReader(
		legacy, plaintext, bytes.NewReader(make([]byte, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = host.DecryptSecret(legacyCiphertext)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("legacy decrypt = %q err=%v", decrypted, err)
	}
}
