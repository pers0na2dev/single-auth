package jwt

import (
	"testing"
	"time"
)

func TestKeyRotationAndGracePeriod(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)}
	store := &keyStore{}
	rotation := time.Second
	grace := time.Second
	options := baseTestOptions(store, clock)
	options.JWKS.RotationInterval = &rotation
	options.JWKS.GracePeriod = &grace
	options.Token.Issuer = String("http://localhost:3000")
	options.Token.Audience = "http://localhost:3000"
	implementation, err := normalize(options, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := implementation.signJWT(nil, map[string]any{"sub": "user1"}); err != nil {
		t.Fatal(err)
	}
	if keys := store.snapshot(); len(keys) != 1 || keys[0].ExpiresAt == nil || !keys[0].ExpiresAt.Equal(clock.Now().Add(time.Second)) {
		t.Fatalf("first key = %#v", keys)
	}
	clock.Add(1100 * time.Millisecond)
	if _, err := implementation.signJWT(nil, map[string]any{"sub": "user1"}); err != nil {
		t.Fatal(err)
	}
	keys := store.snapshot()
	if len(keys) != 2 || keys[0].ID == keys[1].ID {
		t.Fatalf("rotated keys = %#v", keys)
	}
	response, err := implementation.getJWKs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(decodeObjectResponse(t, response)["keys"].([]any)); got != 2 {
		t.Fatalf("keys within grace = %d, want 2", got)
	}
	clock.Add(time.Second)
	response, err = implementation.getJWKs(nil)
	if err != nil {
		t.Fatal(err)
	}
	visible := decodeObjectResponse(t, response)["keys"].([]any)
	if len(visible) != 1 || visible[0].(map[string]any)["kid"] != keys[1].ID {
		t.Fatalf("keys after grace = %#v", visible)
	}
}

func TestZeroRotationDisablesExpiryAndZeroGraceIsExact(t *testing.T) {
	clock := &testClock{now: time.Now()}
	store := &keyStore{}
	zero := time.Duration(0)
	options := baseTestOptions(store, clock)
	options.JWKS.RotationInterval = &zero
	options.JWKS.GracePeriod = &zero
	implementation, err := normalize(options, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := implementation.signJWT(nil, map[string]any{"sub": "user"}); err != nil {
		t.Fatal(err)
	}
	if store.snapshot()[0].ExpiresAt != nil {
		t.Fatal("explicit zero rotation created an expiration")
	}
}
