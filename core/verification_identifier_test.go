package core

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestVerificationIdentifierHashedLifecycleAndPlainDefault(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	hashed := MustNew(Options{
		Clock: func() time.Time { return now },
		Verification: VerificationOptions{StoreIdentifier: VerificationIdentifierStorage{
			Strategy: VerificationIdentifierHashed,
		}},
	})
	identifier := "reset-password:my-token-123"
	digest := sha256.Sum256([]byte(identifier))
	wantStored := base64.RawURLEncoding.EncodeToString(digest[:])

	created, err := hashed.createStoredVerification(t.Context(), identifier, "user-1", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if created["identifier"] != wantStored {
		t.Fatalf("stored identifier = %q, want %q", created["identifier"], wantStored)
	}
	found, err := hashed.findStoredVerification(t.Context(), identifier)
	if err != nil || found == nil || found["value"] != "user-1" {
		t.Fatalf("find by original = %#v, %v", found, err)
	}
	if err := hashed.updateStoredVerification(t.Context(), identifier, storage.Record{"value": "user-2"}); err != nil {
		t.Fatal(err)
	}
	found, err = hashed.findStoredVerification(t.Context(), identifier)
	if err != nil || found == nil || found["value"] != "user-2" {
		t.Fatalf("updated verification = %#v, %v", found, err)
	}
	consumed, err := hashed.consumeStoredVerification(t.Context(), identifier)
	if err != nil || consumed == nil || consumed["value"] != "user-2" {
		t.Fatalf("consume by original = %#v, %v", consumed, err)
	}
	replay, err := hashed.consumeStoredVerification(t.Context(), identifier)
	if err != nil || replay != nil {
		t.Fatalf("replay = %#v, %v", replay, err)
	}

	if _, err := hashed.createStoredVerification(t.Context(), identifier, "delete", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := hashed.deleteStoredVerification(t.Context(), identifier); err != nil {
		t.Fatal(err)
	}
	deleted, err := hashed.findStoredVerification(t.Context(), identifier)
	if err != nil || deleted != nil {
		t.Fatalf("deleted verification = %#v, %v", deleted, err)
	}

	plain := MustNew(Options{Clock: func() time.Time { return now }})
	plainRecord, err := plain.createStoredVerification(t.Context(), "magic-link:plain", "plain", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if plainRecord["identifier"] != "magic-link:plain" {
		t.Fatalf("zero-value strategy changed plain storage: %#v", plainRecord)
	}
}

func TestVerificationIdentifierOverridesCustomHasherAndSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	overrides := []VerificationIdentifierOverride{
		{Prefix: "reset-password:", Strategy: VerificationIdentifierHashed},
		{Prefix: "custom:", Hash: func(identifier string) (string, error) {
			return "custom-hash:" + identifier, nil
		}},
	}
	auth := MustNew(Options{
		Clock: func() time.Time { return now },
		Verification: VerificationOptions{StoreIdentifier: VerificationIdentifierStorage{
			Strategy:  VerificationIdentifierPlain,
			Overrides: overrides,
		}},
	})
	// New snapshots the ordered override list.
	overrides[0] = VerificationIdentifierOverride{Prefix: "reset-password:", Strategy: VerificationIdentifierPlain}

	hashed, err := auth.createStoredVerification(t.Context(), "reset-password:token", "hashed", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if hashed["identifier"] == "reset-password:token" {
		t.Fatalf("prefix override was not snapshotted: %#v", hashed)
	}
	custom, err := auth.createStoredVerification(t.Context(), "custom:token", "custom", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if custom["identifier"] != "custom-hash:custom:token" {
		t.Fatalf("custom hash identifier = %#v", custom["identifier"])
	}
	plain, err := auth.createStoredVerification(t.Context(), "otp:token", "plain", now.Add(time.Minute))
	if err != nil || plain["identifier"] != "otp:token" {
		t.Fatalf("default plain identifier = %#v, %v", plain, err)
	}

	wantHashError := errors.New("hash failed")
	failing := MustNew(Options{Verification: VerificationOptions{StoreIdentifier: VerificationIdentifierStorage{
		Hash: func(string) (string, error) { return "", wantHashError },
	}}})
	if _, err := failing.createStoredVerification(t.Context(), "token", "value", now.Add(time.Minute)); !errors.Is(err, wantHashError) {
		t.Fatalf("custom hash error = %v", err)
	}

	for _, options := range []VerificationIdentifierStorage{
		{Strategy: "unknown"},
		{Strategy: VerificationIdentifierHashed, Hash: func(value string) (string, error) { return value, nil }},
		{Overrides: []VerificationIdentifierOverride{{Prefix: "x", Strategy: "unknown"}}},
	} {
		if _, err := New(Options{Verification: VerificationOptions{StoreIdentifier: options}}); err == nil {
			t.Fatalf("invalid identifier storage accepted: %#v", options)
		}
	}
}

func TestVerificationIdentifierHashedReadsAndConsumesLegacyPlainRows(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	database := memory.MustNew(memory.WithClock(func() time.Time { return now }))
	plain := MustNew(Options{Database: database, Clock: func() time.Time { return now }})
	identifier := "old-token:abc123"
	if _, err := plain.createStoredVerification(t.Context(), identifier, "legacy", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	hashed := MustNew(Options{
		Database: database, Clock: func() time.Time { return now },
		Verification: VerificationOptions{StoreIdentifier: VerificationIdentifierStorage{
			Strategy: VerificationIdentifierHashed,
		}},
	})
	found, err := hashed.findStoredVerification(t.Context(), identifier)
	if err != nil || found == nil || found["value"] != "legacy" {
		t.Fatalf("legacy lookup = %#v, %v", found, err)
	}
	consumed, err := hashed.consumeStoredVerification(t.Context(), identifier)
	if err != nil || consumed == nil || consumed["value"] != "legacy" {
		t.Fatalf("legacy consume = %#v, %v", consumed, err)
	}
	replay, err := hashed.findStoredVerification(t.Context(), identifier)
	if err != nil || replay != nil {
		t.Fatalf("legacy replay = %#v, %v", replay, err)
	}
}

func TestVerificationIdentifierHashedConsumeIsSingleUseUnderConcurrency(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	auth := MustNew(Options{
		Clock: func() time.Time { return now },
		Verification: VerificationOptions{StoreIdentifier: VerificationIdentifierStorage{
			Strategy: VerificationIdentifierHashed,
		}},
	})
	if _, err := auth.createStoredVerification(t.Context(), "consume:hashed", "winner", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	const racers = 32
	var successes atomic.Int32
	var wait sync.WaitGroup
	wait.Add(racers)
	for range racers {
		go func() {
			defer wait.Done()
			value, err := auth.consumeStoredVerification(t.Context(), "consume:hashed")
			if err == nil && value != nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful consumers = %d, want 1", successes.Load())
	}
}

func TestVerificationIdentifierHashedSecondaryStorageLifecycleAndLegacyFallback(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	secondary := &atomicSecondaryMemory{secondaryMemory: newSecondaryMemory()}
	storageOptions := VerificationIdentifierStorage{Strategy: VerificationIdentifierHashed}
	hashed := MustNew(Options{
		Clock: func() time.Time { return now }, SecondaryStorage: secondary,
		Verification: VerificationOptions{StoreIdentifier: storageOptions},
	})
	identifier := "secondary:hashed"
	digest := sha256.Sum256([]byte(identifier))
	stored := base64.RawURLEncoding.EncodeToString(digest[:])
	if _, err := hashed.createStoredVerification(t.Context(), identifier, "initial", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if secondary.value(verificationPrefix+stored) == "" || secondary.value(verificationPrefix+identifier) != "" {
		t.Fatalf("secondary keys = %#v", secondary.values)
	}
	if err := hashed.updateStoredVerification(t.Context(), identifier, storage.Record{"value": "updated"}); err != nil {
		t.Fatal(err)
	}
	found, err := hashed.findStoredVerification(t.Context(), identifier)
	if err != nil || found == nil || found["value"] != "updated" {
		t.Fatalf("updated secondary verification = %#v, %v", found, err)
	}
	consumed, err := hashed.consumeStoredVerification(t.Context(), identifier)
	if err != nil || consumed == nil || consumed["value"] != "updated" {
		t.Fatalf("consumed secondary verification = %#v, %v", consumed, err)
	}
	if secondary.value(verificationPrefix+stored) != "" {
		t.Fatalf("hashed secondary key survived consume")
	}

	if _, err := hashed.createStoredVerification(t.Context(), identifier, "delete", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := hashed.deleteStoredVerification(t.Context(), identifier); err != nil {
		t.Fatal(err)
	}
	if secondary.value(verificationPrefix+stored) != "" {
		t.Fatalf("hashed secondary key survived delete")
	}

	legacyIdentifier := "secondary:legacy"
	plain := MustNew(Options{
		Clock: func() time.Time { return now }, SecondaryStorage: secondary,
	})
	if _, err := plain.createStoredVerification(t.Context(), legacyIdentifier, "legacy", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	legacy, err := hashed.findStoredVerification(t.Context(), legacyIdentifier)
	if err != nil || legacy == nil || legacy["value"] != "legacy" {
		t.Fatalf("secondary legacy lookup = %#v, %v", legacy, err)
	}
	legacy, err = hashed.consumeStoredVerification(t.Context(), legacyIdentifier)
	if err != nil || legacy == nil || legacy["value"] != "legacy" {
		t.Fatalf("secondary legacy consume = %#v, %v", legacy, err)
	}
}
