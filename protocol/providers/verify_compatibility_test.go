package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func rsaJWK(key *rsa.PrivateKey, kid string) map[string]any {
	e := big.NewInt(int64(key.PublicKey.E)).Bytes()
	return map[string]any{"kid": kid, "alg": "RS256", "kty": "RSA", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signHS256(claims map[string]any, secret string) string {
	header, _ := json.Marshal(map[string]any{"alg": "HS256"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": kid})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestBuiltInIDTokenVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "fixture-key"
	jwks := jsonFixture(map[string]any{"keys": []any{rsaJWK(key, kid)}})
	now := time.Now().Unix()
	baseClaims := func(issuer string, audience any) map[string]any {
		return map[string]any{"iss": issuer, "aud": audience, "iat": now, "exp": now + 3600, "nonce": "nonce", "sub": "subject"}
	}
	type vector struct {
		id      string
		options Options
		claims  map[string]any
		jwksURL string
		nonce   string
	}
	vectors := []vector{
		{id: "apple", options: Options{ClientID: "apple-client", ClientSecret: "secret"}, claims: baseClaims("https://appleid.apple.com", "apple-client"), jwksURL: "https://appleid.apple.com/auth/keys", nonce: "nonce"},
		{id: "google", options: Options{ClientID: []string{"google-web", "google-ios"}, ClientSecret: "secret", HostedDomain: "example.com"}, claims: baseClaims("https://accounts.google.com", "google-ios"), jwksURL: "https://www.googleapis.com/oauth2/v3/certs", nonce: "nonce"},
		{id: "cognito", options: Options{ClientID: "cognito-client", Domain: "tenant.auth.us-east-1.amazoncognito.com", Region: "us-east-1", UserPoolID: "pool"}, claims: baseClaims("https://cognito-idp.us-east-1.amazonaws.com/pool", "cognito-client"), jwksURL: "https://cognito-idp.us-east-1.amazonaws.com/pool/.well-known/jwks.json", nonce: "nonce"},
		{id: "microsoft", options: Options{ClientID: "microsoft-client", TenantID: "organizations"}, claims: baseClaims("https://login.microsoftonline.com/work-tenant/v2.0", "microsoft-client"), jwksURL: "https://login.microsoftonline.com/organizations/discovery/v2.0/keys", nonce: "nonce"},
		{id: "facebook", options: Options{ClientID: "facebook-client", ClientSecret: "secret"}, claims: baseClaims("https://www.facebook.com", "facebook-client"), jwksURL: "https://limited.facebook.com/.well-known/oauth/openid/jwks/", nonce: "nonce"},
		{id: "paypal", options: Options{ClientID: "paypal-client", ClientSecret: "secret"}, claims: baseClaims("https://www.sandbox.paypal.com", "paypal-client"), jwksURL: "https://api.sandbox.paypal.com/v1/oauth2/certs", nonce: "nonce"},
	}
	vectors[1].claims["hd"] = "example.com"
	vectors[3].claims["tid"] = "work-tenant"
	for _, vector := range vectors {
		vector := vector
		t.Run(vector.id, func(t *testing.T) {
			vector.options.HTTPClient = &http.Client{Transport: fixtureTransport{vector.jwksURL: jwks}}
			provider, err := New(vector.id, vector.options)
			if err != nil {
				t.Fatal(err)
			}
			token := signRS256(t, key, kid, vector.claims)
			valid, err := provider.VerifyIDToken(context.Background(), token, vector.nonce)
			if err != nil || !valid {
				t.Fatalf("valid token rejected: valid=%v err=%v", valid, err)
			}
			valid, err = provider.VerifyIDToken(context.Background(), token, "wrong-nonce")
			if err != nil || valid {
				t.Fatalf("nonce mismatch accepted: valid=%v err=%v", valid, err)
			}
		})
	}
}

func TestAppleAcceptsSHA256Nonce(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().Unix()
	digest := sha256.Sum256([]byte("raw-nonce"))
	claims := map[string]any{"iss": "https://appleid.apple.com", "aud": "client", "iat": now, "exp": now + 3600, "nonce": fmt.Sprintf("%x", digest[:])}
	provider, _ := Apple(Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: fixtureTransport{"https://appleid.apple.com/auth/keys": jsonFixture(map[string]any{"keys": []any{rsaJWK(key, "kid")}})}}})
	valid, err := provider.VerifyIDToken(context.Background(), signRS256(t, key, "kid", claims), "raw-nonce")
	if err != nil || !valid {
		t.Fatalf("hashed Apple nonce rejected: valid=%v err=%v", valid, err)
	}
}

func TestAppleES256MatchesUpstreamVerificationPath(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().Unix()
	jwk := map[string]any{"kid": "ec-kid", "alg": "ES256", "kty": "EC", "use": "sig", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
	provider, _ := Apple(Options{ClientID: "service-client", ClientSecret: "secret", AppBundleIdentifier: "bundle-id", HTTPClient: &http.Client{Transport: fixtureTransport{"https://appleid.apple.com/auth/keys": jsonFixture(map[string]any{"keys": []any{jwk}})}}})
	claims := map[string]any{"iss": "https://appleid.apple.com", "aud": "bundle-id", "iat": now, "exp": now + 3600, "nonce": "nonce"}
	valid, err := provider.VerifyIDToken(context.Background(), signES256(t, key, "ec-kid", claims), "nonce")
	if err != nil || !valid {
		t.Fatalf("Apple ES256 token rejected: valid=%v err=%v", valid, err)
	}
}

func TestExportedPublicKeyHelpers(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	client := &http.Client{Transport: fixtureTransport{"https://www.googleapis.com/oauth2/v3/certs": jsonFixture(map[string]any{"keys": []any{rsaJWK(key, "kid")}})}}
	publicKey, err := GetGooglePublicKey(context.Background(), "kid", client)
	if err != nil {
		t.Fatal(err)
	}
	imported, ok := publicKey.(*rsa.PublicKey)
	if !ok || imported.N.Cmp(key.PublicKey.N) != 0 || imported.E != key.PublicKey.E {
		t.Fatalf("wrong imported public key: %#v", publicKey)
	}
	if _, err := GetGooglePublicKey(context.Background(), "missing", client); err == nil {
		t.Fatal("missing kid was accepted")
	}
}

func TestPayPalHS256AndLINEVerification(t *testing.T) {
	now := time.Now().Unix()
	paypal, _ := PayPal(Options{ClientID: "client", ClientSecret: "secret"})
	token := signHS256(map[string]any{"iss": "https://www.sandbox.paypal.com", "aud": "client", "iat": now, "exp": now + 3600, "nonce": "nonce"}, "secret")
	valid, err := paypal.VerifyIDToken(context.Background(), token, "nonce")
	if err != nil || !valid {
		t.Fatalf("PayPal HS256 token rejected: valid=%v err=%v", valid, err)
	}

	line, _ := LINE(Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: fixtureTransport{"https://api.line.me/oauth2/v2.1/verify": jsonFixture(map[string]any{"aud": "client", "nonce": "nonce"})}}})
	valid, err = line.VerifyIDToken(context.Background(), "opaque-id-token", "nonce")
	if err != nil || !valid {
		t.Fatalf("LINE token rejected: valid=%v err=%v", valid, err)
	}
	valid, _ = line.VerifyIDToken(context.Background(), "opaque-id-token", "wrong")
	if valid {
		t.Fatal("LINE accepted a mismatched nonce")
	}
}

func TestIDTokenVerificationCanBeDisabledOrOverridden(t *testing.T) {
	disabled, _ := Google(Options{ClientID: "client", ClientSecret: "secret", DisableIDTokenSignIn: true, VerifyIDToken: func(context.Context, string, string) (bool, error) { return true, nil }})
	valid, err := disabled.VerifyIDToken(context.Background(), "anything", "")
	if err != nil || valid {
		t.Fatalf("disabled verification returned valid=%v err=%v", valid, err)
	}
	overridden, _ := Google(Options{ClientID: "client", ClientSecret: "secret", VerifyIDToken: func(_ context.Context, token, nonce string) (bool, error) {
		return token == "custom" && nonce == "nonce", nil
	}})
	valid, err = overridden.VerifyIDToken(context.Background(), "custom", "nonce")
	if err != nil || !valid {
		t.Fatalf("custom verifier not used: valid=%v err=%v", valid, err)
	}
}
