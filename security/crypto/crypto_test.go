package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestPasswordHashFormatAndNormalization(t *testing.T) {
	t.Parallel()
	salt, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPasswordWithReader("비밀번호🔑密码🔒パスワード", bytes.NewReader(salt))
	if err != nil {
		t.Fatal(err)
	}
	const passwordVector = "000102030405060708090a0b0c0d0e0f:89d2e25cf69535267cbdec4ce902a3f5584587b8b3387070bb3f17c9267ac786848ea4be3cb9b1abc2edf199ad6480dc63be8ce8ef1361e9456b01183b9c8678"
	if hash != passwordVector {
		t.Fatalf("password hash mismatch:\nwant %s\n got %s", passwordVector, hash)
	}
	if !VerifyPassword(hash, "비밀번호🔑密码🔒パスワード") {
		t.Fatal("generated hash did not verify")
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatal("wrong password verified")
	}
	composed, err := HashPasswordWithReader("Å", bytes.NewReader(salt))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(composed, "Å") {
		t.Fatal("NFKC-equivalent password did not verify")
	}
}

func TestEnvelopeAndXChaChaRotation(t *testing.T) {
	t.Parallel()
	if _, ok := ParseEnvelope("abcdef"); ok {
		t.Fatal("bare value parsed as envelope")
	}
	envelope, ok := ParseEnvelope("$ba$2$deadbeef")
	if !ok || envelope.Version != 2 || envelope.Ciphertext != "deadbeef" {
		t.Fatalf("unexpected envelope: %#v, %v", envelope, ok)
	}
	if got := FormatEnvelope(3, "deadbeef"); got != "$ba$3$deadbeef" {
		t.Fatalf("unexpected format: %q", got)
	}

	nonce := bytes.Repeat([]byte{0x42}, 24)
	ciphertext, err := EncryptWithReader("secret-a-at-least-32-chars-long!!", []byte("hello world"), bytes.NewReader(nonce))
	if err != nil {
		t.Fatal(err)
	}
	const cipherVector = "424242424242424242424242424242424242424242424242902cd73c5cd971a9c7ed108c72900f61ec81360eedee6b633419a0"
	if ciphertext != cipherVector {
		t.Fatalf("ciphertext mismatch:\nwant %s\n got %s", cipherVector, ciphertext)
	}
	plaintext, err := Decrypt("secret-a-at-least-32-chars-long!!", ciphertext)
	if err != nil || string(plaintext) != "hello world" {
		t.Fatalf("decrypt: %q, %v", plaintext, err)
	}

	config, err := NewSecretConfig([]SecretEntry{
		{Version: 2, Value: "secret-b-at-least-32-chars-long!!"},
		{Version: 1, Value: "secret-a-at-least-32-chars-long!!"},
	}, "secret-a-at-least-32-chars-long!!")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := DecryptWithConfig(config, ciphertext)
	if err != nil || string(legacy) != "hello world" {
		t.Fatalf("legacy decrypt: %q, %v", legacy, err)
	}
}

func TestSignature(t *testing.T) {
	t.Parallel()
	signature := MakeSignature("session-token", "secret-at-least-32-characters-long")
	const signatureVector = "HSUilDsF/4P9cO3bi3vy0MP8pvUiwteom6MRcX57XHo="
	if signature != signatureVector {
		t.Fatalf("HMAC mismatch: want %q, got %q", signatureVector, signature)
	}
	if !VerifySignature("session-token", signature, "secret-at-least-32-characters-long") {
		t.Fatal("signature did not verify")
	}
	if VerifySignature("tampered", signature, "secret-at-least-32-characters-long") {
		t.Fatal("tampered value verified")
	}
	urlSignature := MakeURLSignature("session-json", "secret-at-least-32-characters-long")
	if strings.ContainsAny(urlSignature, "+/=") || !VerifyURLSignature("session-json", urlSignature, "secret-at-least-32-characters-long") {
		t.Fatalf("invalid base64url signature: %q", urlSignature)
	}
}

func TestJWT(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	token, err := SignJWTAt(map[string]any{"sub": "user-1"}, "secret", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyJWTAt(token, "secret", now.Add(time.Minute), 0)
	if err != nil || claims["sub"] != "user-1" {
		t.Fatalf("verify: %#v, %v", claims, err)
	}
	if _, err := VerifyJWTAt(token, "wrong", now, 0); err == nil {
		t.Fatal("wrong secret verified")
	}
	if _, err := VerifyJWTAt(token, "secret", now.Add(2*time.Hour), 0); err != ErrExpiredJWT {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func TestJWERoundTripRotationAndTamper(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	random := bytes.NewReader(bytes.Repeat([]byte{0x23}, 32))
	token, err := EncodeJWEAt(
		map[string]any{"foo": "bar"},
		"secret-a-at-least-32-chars-long!!",
		"test-salt",
		time.Hour,
		now,
		random,
	)
	if err != nil {
		t.Fatal(err)
	}
	const goJWEVector = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiQ2Y0Yk1KcUVzVC11MF9tS3h1ajFuN2tGX0JqNHd0OGNERXp4OHFGRmFGayJ9..IyMjIyMjIyMjIyMjIyMjIw.vSKMzYKfwyyXjGEukLQI_HcjYKOZ2ZStRXZMmmEJtB1cDqZ91J_AwP9-dKknVwvkPzUQ7p-4EcQFUkYVbotFqNFCbomwcuoBA7H3vPBSzUAegPXGPo5ksjSFNOt2Nr6C.9wGnGAkycTHoZjGQzY3NGtVVZQh2XWm4YzYu-PMAp2I"
	if token != goJWEVector {
		t.Fatalf("deterministic JWE vector changed:\nwant %s\n got %s", goJWEVector, token)
	}
	claims, err := DecodeJWEAt(token, "secret-a-at-least-32-chars-long!!", "test-salt", now)
	if err != nil || claims["foo"] != "bar" {
		t.Fatalf("decode: %#v, %v", claims, err)
	}

	config, err := NewSecretConfig([]SecretEntry{
		{Version: 2, Value: "secret-b-at-least-32-chars-long!!"},
		{Version: 1, Value: "secret-a-at-least-32-chars-long!!"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	claims, err = decodeJWEWithSecrets(token, orderedSecrets(config), "test-salt", now)
	if err != nil || claims["foo"] != "bar" {
		t.Fatalf("rotated decode: %#v, %v", claims, err)
	}

	parts := strings.Split(token, ".")
	parts[3] = parts[3][:len(parts[3])-1] + "A"
	if _, err := DecodeJWEAt(strings.Join(parts, "."), "secret-a-at-least-32-chars-long!!", "test-salt", now); err == nil {
		t.Fatal("tampered JWE verified")
	}
}

func TestDecodeJWEFromReferenceJose(t *testing.T) {
	t.Parallel()
	// Generated by the reference implementation 1.6.26's exact hkdf + jose EncryptJWT pipeline
	// using @noble/hashes 2.0.1 and jose 6.1.3.
	const joseVector = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiQ2Y0Yk1KcUVzVC11MF9tS3h1ajFuN2tGX0JqNHd0OGNERXp4OHFGRmFGayJ9..4RdRk60chi9WMdWxnxUQpQ.aIofAPzE9Wi4IInJdMxsaGAbtzrC0INxrYvVJmZKsxIIeW2YqwRjMO9TYxjfK9pCFOjUvaEWgP_60UjivbTK4rrGcBjnuDS4SwIZJqXBqE63nPmK7H1VRjfaD3mKpiIzx_HBI06jCgGZ02yfr_LSbw.6yotX3VSqWJA9Y_oXbBIOcIHSK3sxQINzDkJlsUIOjM"
	claims, err := DecodeJWEAt(
		joseVector,
		"secret-a-at-least-32-chars-long!!",
		"test-salt",
		time.Unix(1_700_000_100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims["foo"] != "from-js" || claims["jti"] != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("unexpected jose claims: %#v", claims)
	}
}

func TestSecretParsing(t *testing.T) {
	t.Parallel()
	entries, err := ParseSecretsEnv("1: foo , 2:bar ")
	if err != nil || len(entries) != 2 || entries[0].Version != 1 || entries[1].Value != "bar" {
		t.Fatalf("unexpected entries: %#v, %v", entries, err)
	}
	if _, err := ParseSecretsEnv("noseparator"); err == nil {
		t.Fatal("invalid entry accepted")
	}
	if _, err := ParseSecretsEnv("-1:secret"); err == nil {
		t.Fatal("negative version accepted")
	}
}
