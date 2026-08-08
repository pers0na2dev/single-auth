package oauth2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type validateTokenOracleFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type validateTokenOracle struct {
	SchemaVersion   int                       `json:"schemaVersion"`
	UpstreamVersion string                    `json:"upstreamVersion"`
	OracleKind      string                    `json:"oracleKind"`
	Sources         []validateTokenOracleFile `json:"sources"`
	Runtimes        []validateTokenOracleFile `json:"runtimes"`
	ManifestTestIDs []string                  `json:"manifestTestIDs"`
	Tests           []struct {
		ID          string         `json:"id"`
		File        string         `json:"file"`
		Suite       string         `json:"suite"`
		Title       string         `json:"title"`
		Observation map[string]any `json:"observation"`
	} `json:"tests"`
}

type validateTokenTestKey struct {
	algorithm string
	keyID     string
	publicJWK map[string]any
	private   crypto.PrivateKey
}

type validateTokenKeyPool struct {
	rsa1 validateTokenTestKey
	rsa2 validateTokenTestKey
	rsa3 validateTokenTestKey
	ec   validateTokenTestKey
	ed   validateTokenTestKey
}

func TestValidateTokenHTTPBehavior(t *testing.T) {
	oracle := loadValidateTokenOracle(t)
	pool := newValidateTokenKeyPool(t)
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			actual := executeValidateTokenVector(t, vector.Title, pool)
			if !reflect.DeepEqual(actual, vector.Observation) {
				t.Fatalf("validateToken observation = %#v, the reference implementation = %#v", actual, vector.Observation)
			}
		})
	}
}

func TestValidateTokenClaimArraysAndTemporalGuards(t *testing.T) {
	key := newValidateTokenRSAKey(t, "claim-guards")
	server := newJWKSServer(t, http.StatusOK, map[string]any{"keys": []map[string]any{key.publicJWK}}, "")
	defer server.Close()
	validate := func(claims map[string]any, options ValidateTokenOptions) error {
		t.Helper()
		token := signValidateTokenJWT(t, key, key.keyID, claims)
		_, err := ValidateToken(t.Context(), server.Client(), token, server.URL, options)
		return err
	}

	if err := validate(map[string]any{
		"sub": "user-123", "aud": []string{"other", "expected"}, "iss": "issuer-b",
	}, ValidateTokenOptions{
		Audience: []string{"missing", "expected"}, Issuer: []string{"issuer-a", "issuer-b"},
	}); err != nil {
		t.Fatalf("multi-value audience/issuer rejected: %v", err)
	}
	if err := validate(map[string]any{
		"sub": "user-123", "exp": time.Now().Add(-time.Minute).Unix(),
	}, ValidateTokenOptions{}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token error = %v", err)
	}
	if err := validate(map[string]any{
		"sub": "user-123", "nbf": time.Now().Add(time.Minute).Unix(),
	}, ValidateTokenOptions{}); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("future nbf token error = %v", err)
	}
}

func executeValidateTokenVector(t *testing.T, title string, pool validateTokenKeyPool) map[string]any {
	t.Helper()
	validToken := func(key validateTokenTestKey, keyID string) string {
		return signValidateTokenJWT(t, key, keyID, map[string]any{
			"sub": "user-123", "email": "test@example.com",
			"iss": "https://example.com", "aud": "test-client",
		})
	}
	call := func(key validateTokenTestKey, keys []map[string]any, options ValidateTokenOptions) (VerifiedToken, error) {
		server := newJWKSServer(t, http.StatusOK, map[string]any{"keys": keys}, "")
		defer server.Close()
		return ValidateToken(context.Background(), server.Client(), validToken(key, key.keyID), server.URL, options)
	}
	rejected := func(err error) map[string]any { return map[string]any{"rejected": err != nil} }

	switch title {
	case "should verify RS256 signed token":
		result, err := call(pool.rsa1, []map[string]any{pool.rsa1.publicJWK}, ValidateTokenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"verified": true, "sub": result.Payload["sub"], "email": result.Payload["email"]}
	case "should verify ES256 signed token":
		result, err := call(pool.ec, []map[string]any{pool.ec.publicJWK}, ValidateTokenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"verified": true, "sub": result.Payload["sub"]}
	case "should verify EdDSA (Ed25519) signed token":
		result, err := call(pool.ed, []map[string]any{pool.ed.publicJWK}, ValidateTokenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"verified": true, "sub": result.Payload["sub"]}
	case "should throw when kid doesn't match any key":
		jwk := cloneValidateTokenMap(pool.rsa1.publicJWK)
		jwk["kid"] = "different-kid"
		server := newJWKSServer(t, http.StatusOK, map[string]any{"keys": []map[string]any{jwk}}, "")
		defer server.Close()
		_, err := ValidateToken(
			context.Background(), server.Client(), validToken(pool.rsa1, "original-kid"),
			server.URL, ValidateTokenOptions{},
		)
		return rejected(err)
	case "should find correct key when multiple keys exist":
		result, err := call(pool.rsa2, []map[string]any{
			pool.rsa1.publicJWK, pool.rsa2.publicJWK, pool.ec.publicJWK,
		}, ValidateTokenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"verified": true, "sub": result.Payload["sub"]}
	case "should throw when JWKS returns empty keys array":
		_, err := call(pool.rsa1, []map[string]any{}, ValidateTokenOptions{})
		return rejected(err)
	case "should throw when JWKS fetch fails":
		server := newJWKSServer(t, http.StatusInternalServerError, "Internal Server Error", "")
		defer server.Close()
		_, err := ValidateToken(
			context.Background(), server.Client(), validToken(pool.rsa1, pool.rsa1.keyID),
			server.URL, ValidateTokenOptions{},
		)
		return rejected(err)
	case "refuses a redirecting JWKS endpoint and fetches with redirects disabled":
		var internalHits atomic.Int64
		internal := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			internalHits.Add(1)
		}))
		defer internal.Close()
		redirect := newJWKSServer(t, http.StatusFound, nil, internal.URL)
		defer redirect.Close()
		_, err := ValidateToken(
			context.Background(), redirect.Client(), validToken(pool.rsa1, pool.rsa1.keyID),
			redirect.URL, ValidateTokenOptions{},
		)
		manual := errors.Is(err, ErrOAuthRedirect) && internalHits.Load() == 0
		return map[string]any{
			"rejected": err != nil, "redirect": map[bool]string{true: "manual"}[manual],
			"ssrfMessage": err != nil && strings.Contains(err.Error(), "refuse redirects to prevent SSRF"),
		}
	case "should verify token with matching audience":
		result, err := call(pool.rsa1, []map[string]any{pool.rsa1.publicJWK}, ValidateTokenOptions{Audience: []string{"test-client"}})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"verified": true, "aud": result.Payload["aud"]}
	case "should reject token with mismatched audience":
		_, err := call(pool.rsa1, []map[string]any{pool.rsa1.publicJWK}, ValidateTokenOptions{Audience: []string{"wrong-client"}})
		return rejected(err)
	case "should verify token with matching issuer":
		result, err := call(pool.rsa1, []map[string]any{pool.rsa1.publicJWK}, ValidateTokenOptions{Issuer: []string{"https://example.com"}})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"verified": true, "iss": result.Payload["iss"]}
	case "should reject token with mismatched issuer":
		_, err := call(pool.rsa1, []map[string]any{pool.rsa1.publicJWK}, ValidateTokenOptions{Issuer: []string{"https://wrong-issuer.com"}})
		return rejected(err)
	case "should verify token with both audience and issuer":
		result, err := call(pool.rsa1, []map[string]any{pool.rsa1.publicJWK}, ValidateTokenOptions{
			Audience: []string{"test-client"}, Issuer: []string{"https://example.com"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"verified": true, "aud": result.Payload["aud"], "iss": result.Payload["iss"]}
	default:
		t.Fatalf("unknown validateToken vector %q", title)
		return nil
	}
}

func newValidateTokenKeyPool(t *testing.T) validateTokenKeyPool {
	t.Helper()
	return validateTokenKeyPool{
		rsa1: newValidateTokenRSAKey(t, "rsa-1"),
		rsa2: newValidateTokenRSAKey(t, "rsa-2"),
		rsa3: newValidateTokenRSAKey(t, "rsa-3"),
		ec:   newValidateTokenECKey(t, "ec-1"),
		ed:   newValidateTokenEdKey(t, "ed-1"),
	}
}

func newValidateTokenRSAKey(t *testing.T, keyID string) validateTokenTestKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return validateTokenTestKey{
		algorithm: "RS256", keyID: keyID, private: privateKey,
		publicJWK: map[string]any{
			"kty": "RSA", "alg": "RS256", "kid": keyID,
			"n": base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
		},
	}
}

func newValidateTokenECKey(t *testing.T, keyID string) validateTokenTestKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return validateTokenTestKey{
		algorithm: "ES256", keyID: keyID, private: privateKey,
		publicJWK: map[string]any{
			"kty": "EC", "alg": "ES256", "kid": keyID, "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(privateKey.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(privateKey.Y.FillBytes(make([]byte, 32))),
		},
	}
}

func newValidateTokenEdKey(t *testing.T, keyID string) validateTokenTestKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return validateTokenTestKey{
		algorithm: "EdDSA", keyID: keyID, private: privateKey,
		publicJWK: map[string]any{
			"kty": "OKP", "alg": "EdDSA", "kid": keyID, "crv": "Ed25519",
			"x": base64.RawURLEncoding.EncodeToString(publicKey),
		},
	}
}

func signValidateTokenJWT(t *testing.T, key validateTokenTestKey, keyID string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": key.algorithm, "kid": keyID}
	payload := cloneValidateTokenMap(claims)
	if _, exists := payload["iat"]; !exists {
		payload["iat"] = time.Now().Unix()
	}
	if _, exists := payload["exp"]; !exists {
		payload["exp"] = time.Now().Add(time.Hour).Unix()
	}
	encodedHeader := encodeValidateTokenJSON(t, header)
	encodedPayload := encodeValidateTokenJSON(t, payload)
	input := []byte(encodedHeader + "." + encodedPayload)
	var signature []byte
	switch privateKey := key.private.(type) {
	case *rsa.PrivateKey:
		digest := sha256.Sum256(input)
		var err error
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		signature = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case ed25519.PrivateKey:
		signature = ed25519.Sign(privateKey, input)
	default:
		t.Fatalf("unsupported test key %T", key.private)
	}
	return encodedHeader + "." + encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeValidateTokenJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func cloneValidateTokenMap(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func newJWKSServer(t *testing.T, status int, payload any, redirect string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if redirect != "" {
			writer.Header().Set("Location", redirect)
		}
		if payload != nil {
			writer.Header().Set("Content-Type", "application/json")
		}
		writer.WriteHeader(status)
		if payload == nil {
			return
		}
		if text, ok := payload.(string); ok {
			_, _ = writer.Write([]byte(text))
			return
		}
		_ = json.NewEncoder(writer).Encode(payload)
	}))
}

func loadValidateTokenOracle(t *testing.T) validateTokenOracle {
	t.Helper()
	return validateTokenOracle{Tests: validateTokenCases}
}
