package oauthprovider

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

type revokeJWTErrorCase struct {
	Title     string
	Status    int
	WireError string
}

type revokeJWTWireObservation struct {
	Status    int
	WireError string
}

func TestOAuthProviderRevokeJWTErrors(t *testing.T) {
	for _, vector := range revokeJWTErrorCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber", "direct"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					harness := newRevokeHarness(
						t,
						transportName,
						"should pass verification with token_type_hint access_token and sent jwt access_token",
					)
					harness.input.Token = revokeJWTErrorToken(t, harness, vector.Title)
					actual := runRevokeJWTError(t, harness)
					want := revokeJWTWireObservation{
						Status: vector.Status, WireError: vector.WireError,
					}
					if !reflect.DeepEqual(actual, want) {
						t.Fatalf("JWT revoke observation = %#v, want %#v", actual, want)
					}
					harness.assertMutation(
						t,
						"should pass verification with token_type_hint access_token and sent jwt access_token",
					)
				})
			}
		})
	}
}

func revokeJWTErrorToken(t *testing.T, harness *revokeHarness, title string) string {
	t.Helper()
	switch title {
	case "non-JWT":
		return "not-a-jwt"
	case "malformed protected header":
		return "%%%.e30.signature"
	case "invalid compact JWS signature encoding":
		return "eyJhbGciOiJFZERTQSJ9.e30.invalid*"
	}

	rows, err := harness.adapter.FindMany(t.Context(), storage.FindManyParams{Model: "jwks"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("persisted JWK rows = %d, want 1", len(rows))
	}
	row := rows[0]
	kid, _ := row["id"].(string)
	privateJSON, _ := row["privateKey"].(string)
	if kid == "" || privateJSON == "" {
		t.Fatalf("persisted JWK is incomplete: %#v", row)
	}
	var privateJWK map[string]any
	if err := json.Unmarshal([]byte(privateJSON), &privateJWK); err != nil {
		t.Fatal(err)
	}
	seedText, _ := privateJWK["d"].(string)
	seed, err := base64.RawURLEncoding.DecodeString(seedText)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("persisted Ed25519 seed length=%d err=%v", len(seed), err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	now := time.Date(2028, time.January, 2, 3, 4, 5, 987654321, time.UTC)
	payload := map[string]any{
		"sub": "revoke-user", "iss": revokeIssuerBaseURL,
		"aud": revokeIssuerAudience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}

	switch title {
	case "valid no-kid":
		return signRevokeJWTErrorToken(t, privateKey, "", payload)
	case "tampered signature":
		parts := strings.Split(harness.jwtToken, ".")
		if len(parts) != 3 {
			t.Fatalf("production JWT has %d compact parts", len(parts))
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || len(signature) == 0 {
			t.Fatalf("decode production signature: length=%d err=%v", len(signature), err)
		}
		signature[0] ^= 1
		return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
	case "wrong audience":
		payload["aud"] = "https://wrong.test"
	case "wrong issuer":
		payload["iss"] = "https://wrong.test"
	case "expired":
		payload["iat"] = now.Add(-2 * time.Hour).Unix()
		payload["exp"] = now.Add(-time.Hour).Unix()
	case "non-object JWT claims set":
		return signRevokeJWTErrorPayload(t, privateKey, kid, []byte("[]"))
	default:
		t.Fatalf("unknown OAuth revoke JWT error vector %q", title)
	}
	return signRevokeJWTErrorToken(t, privateKey, kid, payload)
}

func signRevokeJWTErrorToken(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	kid string,
	payload map[string]any,
) string {
	t.Helper()
	header := struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid,omitempty"`
	}{Algorithm: "EdDSA", KeyID: kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	return signRevokeJWTErrorInput(privateKey, signingInput)
}

func signRevokeJWTErrorPayload(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	kid string,
	payloadJSON []byte,
) string {
	t.Helper()
	header := struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid,omitempty"`
	}{Algorithm: "EdDSA", KeyID: kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	return signRevokeJWTErrorInput(privateKey, signingInput)
}

func signRevokeJWTErrorInput(privateKey ed25519.PrivateKey, signingInput string) string {
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func runRevokeJWTError(
	t *testing.T,
	harness *revokeHarness,
) revokeJWTWireObservation {
	t.Helper()
	values := make(url.Values)
	values.Set("client_id", harness.input.ClientID)
	values.Set("client_secret", harness.input.ClientSecret)
	values.Set("token", harness.input.Token)
	values.Set("token_type_hint", string(RevokeAccessToken))
	status, encoded, err := harness.exchange([]byte(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	observation := revokeJWTWireObservation{Status: status}
	if status == http.StatusOK {
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil || value != nil {
			t.Fatalf("successful JWT revoke response=%s value=%#v err=%v", encoded, value, err)
		}
		return observation
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatalf("decode JWT revoke error %q: %v", encoded, err)
	}
	if value, _ := body["error"].(string); value != "" {
		observation.WireError = value
	} else if value, _ := body["code"].(string); value != "" {
		observation.WireError = value
	} else {
		t.Fatalf("JWT revoke error body has no wire code: %#v", body)
	}
	return observation
}
