package oauthproxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

func TestProfileEndpointFailureTaxonomyAndAgeValidation(t *testing.T) {
	auth := testAuth(t, previewBase, previewSecret, Options{MaxAge: 5 * time.Second},
		singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	endpoint := previewBase + "/api/auth/oauth-proxy-callback?callbackURL=/dashboard"

	missing := exchange(t, auth, http.MethodGet, endpoint, nil, nil)
	if missing.Status != http.StatusFound || !strings.Contains(missing.Header.Get("Location"), "error=missing_profile") {
		t.Fatalf("missing profile=%d location=%q", missing.Status, missing.Header.Get("Location"))
	}
	invalid := exchange(t, auth, http.MethodGet, endpoint+"&profile=not-ciphertext", nil, nil)
	if !strings.Contains(invalid.Header.Get("Location"), "error=invalid_profile") {
		t.Fatalf("invalid profile location=%q", invalid.Header.Get("Location"))
	}
	invalidJSON, err := baCrypto.Encrypt(previewSecret, []byte("not-json"))
	if err != nil {
		t.Fatal(err)
	}
	malformed := exchange(t, auth, http.MethodGet, endpoint+"&profile="+url.QueryEscape(invalidJSON), nil, nil)
	if !strings.Contains(malformed.Header.Get("Location"), "error=invalid_payload") {
		t.Fatalf("malformed payload location=%q", malformed.Header.Get("Location"))
	}
	validThenTrailing, err := baCrypto.Encrypt(previewSecret, []byte(`{"timestamp":1} {}`))
	if err != nil {
		t.Fatal(err)
	}
	trailing := exchange(t, auth, http.MethodGet,
		endpoint+"&profile="+url.QueryEscape(validThenTrailing), nil, nil)
	if !strings.Contains(trailing.Header.Get("Location"), "error=invalid_payload") {
		t.Fatalf("trailing payload location=%q", trailing.Header.Get("Location"))
	}

	basePayload := map[string]any{
		"userInfo": map[string]any{"id": "123", "email": "user@email.com", "name": "Test", "emailVerified": true},
		"account":  map[string]any{"providerId": "google", "accountId": "123"},
		"state":    "not-issued", "callbackURL": "/dashboard",
	}
	defaultAgeAuth := testAuth(t, previewBase, previewSecret, Options{},
		singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	defaultExpired := cloneObject(basePayload)
	defaultExpired["timestamp"] = time.Now().Add(-2 * time.Minute).UnixMilli()
	defaultResponse := exchange(t, defaultAgeAuth, http.MethodGet,
		endpoint+"&profile="+url.QueryEscape(encryptJSON(t, previewSecret, defaultExpired)), nil, nil)
	if !strings.Contains(defaultResponse.Header.Get("Location"), "error=payload_expired") {
		t.Fatalf("default maxAge location=%q", defaultResponse.Header.Get("Location"))
	}
	for name, timestamp := range map[string]int64{
		"older than custom maxAge":            time.Now().Add(-10 * time.Second).UnixMilli(),
		"more than ten seconds in the future": time.Now().Add(11 * time.Second).UnixMilli(),
	} {
		t.Run(name, func(t *testing.T) {
			payload := cloneObject(basePayload)
			payload["timestamp"] = timestamp
			encrypted := encryptJSON(t, previewSecret, payload)
			response := exchange(t, auth, http.MethodGet, endpoint+"&profile="+url.QueryEscape(encrypted), nil, nil)
			if !strings.Contains(response.Header.Get("Location"), "error=payload_expired") {
				t.Fatalf("location=%q", response.Header.Get("Location"))
			}
		})
	}
	fractional := cloneObject(basePayload)
	fractional["timestamp"] = float64(time.Now().UnixMilli()) + 0.5
	fractionalResponse := exchange(t, auth, http.MethodGet,
		endpoint+"&profile="+url.QueryEscape(encryptJSON(t, previewSecret, fractional)), nil, nil)
	if !strings.Contains(fractionalResponse.Header.Get("Location"), "error=state_mismatch") {
		t.Fatalf("numeric fractional timestamp was rejected before state validation: %q", fractionalResponse.Header.Get("Location"))
	}

	for _, mutation := range []func(map[string]any){
		func(payload map[string]any) { delete(payload, "timestamp") },
		func(payload map[string]any) { delete(payload, "userInfo") },
		func(payload map[string]any) { payload["timestamp"] = "not-a-number" },
	} {
		payload := cloneObject(basePayload)
		payload["timestamp"] = time.Now().UnixMilli()
		mutation(payload)
		encrypted := encryptJSON(t, previewSecret, payload)
		response := exchange(t, auth, http.MethodGet, endpoint+"&profile="+url.QueryEscape(encrypted), nil, nil)
		if !strings.Contains(response.Header.Get("Location"), "error=invalid_payload") {
			t.Fatalf("invalid required field location=%q", response.Header.Get("Location"))
		}
	}
}

func TestUnissuedDatabaseStateCannotCreateOrLinkUser(t *testing.T) {
	auth := testAuth(t, previewBase, previewSecret, Options{},
		singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	payload := map[string]any{
		"userInfo": map[string]any{"id": "google-user", "email": "user@email.com", "name": "New", "emailVerified": true},
		"account":  map[string]any{"providerId": "google", "accountId": "google-user", "accessToken": "test"},
		"state":    "never-issued", "callbackURL": "/dashboard", "timestamp": time.Now().UnixMilli(),
	}
	encrypted := encryptJSON(t, previewSecret, payload)
	response := exchange(t, auth, http.MethodGet,
		previewBase+"/api/auth/oauth-proxy-callback?callbackURL=/dashboard&profile="+url.QueryEscape(encrypted), nil, nil)
	if response.Status != http.StatusFound || !strings.Contains(response.Header.Get("Location"), "error=state_mismatch") {
		t.Fatalf("unissued state=%d location=%q", response.Status, response.Header.Get("Location"))
	}
	if len(records(t, auth, "user")) != 0 || len(records(t, auth, "account")) != 0 {
		t.Fatalf("unissued state wrote identity data")
	}
}

func TestProfileCallbackRejectsUntrustedCallbackQuery(t *testing.T) {
	auth := testAuth(t, previewBase, previewSecret, Options{},
		singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	response := exchange(t, auth, http.MethodGet,
		previewBase+"/api/auth/oauth-proxy-callback?callbackURL="+
			url.QueryEscape("https://evil.example.com/steal"), nil, nil)
	if response.Status != http.StatusForbidden || !strings.Contains(string(response.Body), "INVALID_CALLBACK_URL") {
		t.Fatalf("untrusted callback=%d body=%s", response.Status, response.Body)
	}
}

func TestDifferentEnvironmentSecretsFailClosedWithoutSharedProxySecret(t *testing.T) {
	preview := testAuth(t, previewBase, previewSecret,
		Options{ProductionURL: productionBase},
		singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	production := testAuth(t, productionBase, productionSecret, Options{},
		singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	authorizationURL := startSocial(t, preview, previewBase, "google", nil)
	callback := exchange(t, production, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+
			url.QueryEscape(authorizationURL.Query().Get("state")), nil, nil)
	location := callback.Header.Get("Location")
	if !strings.Contains(location, "state") && !strings.Contains(location, "please_restart") {
		t.Fatalf("different-secret fallback location=%q", location)
	}
	if strings.Contains(location, "profile=") {
		t.Fatalf("different-secret flow emitted a profile: %q", location)
	}
}

func TestProviderDisableSignUpErrorIsForwardedVerbatim(t *testing.T) {
	disabledProvider := testGoogleProvider(t, providers.Options{
		ClientID: "test", ClientSecret: "test", DisableSignUp: true,
	})
	production := testAuth(t, productionBase, productionSecret,
		Options{Secret: sharedSecret}, singleauth.AccountOptions{StoreStateStrategy: "database"}, disabledProvider)
	preview := testAuth(t, previewBase, previewSecret,
		Options{ProductionURL: productionBase, Secret: sharedSecret},
		singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	authorizationURL := startSocial(t, preview, previewBase, "google", nil)
	callback := exchange(t, production, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+
			url.QueryEscape(authorizationURL.Query().Get("state")), nil, nil)
	final := exchange(t, preview, http.MethodGet, callback.Header.Get("Location"), nil, nil)
	parsed, err := url.Parse(final.Header.Get("Location"))
	if err != nil || parsed.Query().Get("error") != "signup_disabled" {
		t.Fatalf("disable-sign-up redirect=%q err=%v", final.Header.Get("Location"), err)
	}
}

func encryptJSON(t *testing.T, secret string, payload any) string {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := baCrypto.Encrypt(secret, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

func cloneObject(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
