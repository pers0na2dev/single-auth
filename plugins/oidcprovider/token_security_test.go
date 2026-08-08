package oidcprovider

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestRefreshTokenGrantConfidentialClientAuthentication(t *testing.T) {
	harness := newHarness(t, func(options *Options) { options.RequirePKCE = false })
	userID, _ := harness.signUp(t, 40)
	const clientID = "confidential-client"
	const clientSecret = "secret-only-the-client-knows"
	const refreshToken = "refresh-token"
	seedClient(t, harness, Client{
		ClientID: clientID, ClientSecret: clientSecret, Type: "web", Name: "Confidential",
		RedirectURLs: []string{"http://localhost/callback"},
	})
	seedAccessToken(
		t, harness, userID, clientID, "stale-access", refreshToken,
		"openid profile email offline_access", harness.clock.Now().Add(-time.Minute),
		harness.clock.Now().Add(7*24*time.Hour),
	)

	missing, missingErr := harness.call(t, "oAuth2token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": clientID,
	}, nil)
	oauthErrorObject(t, missing, missingErr, http.StatusUnauthorized, "invalid_client")

	wrong, wrongErr := harness.call(t, "oAuth2token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "refresh_token", "refresh_token": refreshToken,
		"client_id": clientID, "client_secret": "wrong-secret",
	}, nil)
	oauthErrorObject(t, wrong, wrongErr, http.StatusUnauthorized, "invalid_client")

	basic := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	basicHeaders := contract.NewHeaders(contract.HeaderField{Name: "Authorization", Value: "Basic " + basic})
	accepted, err := harness.call(t, "oAuth2token", http.MethodPost, basicHeaders, map[string]any{
		"grant_type": "refresh_token", "refresh_token": refreshToken,
	}, nil)
	if err != nil || responseObject(t, accepted)["access_token"] == "" ||
		responseObject(t, accepted)["refresh_token"] == "" {
		t.Fatalf("basic status=%d err=%v body=%s", accepted.Response.Status(), err, accepted.Response.Body())
	}

	matching, err := harness.call(t, "oAuth2token", http.MethodPost, basicHeaders, map[string]any{
		"grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": clientID,
	}, nil)
	if err != nil || responseObject(t, matching)["access_token"] == "" {
		t.Fatalf("matching status=%d err=%v body=%s", matching.Response.Status(), err, matching.Response.Body())
	}

	mismatch, mismatchErr := harness.call(t, "oAuth2token", http.MethodPost, basicHeaders, map[string]any{
		"grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": "other-client",
	}, nil)
	oauthErrorObject(t, mismatch, mismatchErr, http.StatusUnauthorized, "invalid_client")

	if _, err := harness.auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "oauthApplication", Where: []storage.Where{{Field: "clientId", Value: clientID}},
		Update: storage.Record{"disabled": true},
	}); err != nil {
		t.Fatal(err)
	}
	disabled, disabledErr := harness.call(t, "oAuth2token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "refresh_token", "refresh_token": refreshToken,
		"client_id": clientID, "client_secret": clientSecret,
	}, nil)
	oauthErrorObject(t, disabled, disabledErr, http.StatusUnauthorized, "invalid_client")
}

func TestAuthorizationCodeIsAtomicallySingleUse(t *testing.T) {
	harness := newHarness(t, func(options *Options) { options.RequirePKCE = false })
	userID, _ := harness.signUp(t, 41)
	client := Client{
		ClientID: "single-use-client", ClientSecret: "single-use-secret", Type: "web",
		Name: "single-use", RedirectURLs: []string{"https://client.example/callback"},
	}
	seedClient(t, harness, client)
	seedCode(t, harness, "single-use-code", AuthorizationCodeValue{
		ClientID: client.ClientID, RedirectURI: client.RedirectURLs[0],
		Scope: []string{"openid", "profile", "email"}, UserID: userID,
	})
	const racers = 32
	type outcome struct {
		result map[string]any
		err    error
	}
	results := make(chan outcome, racers)
	var start sync.WaitGroup
	start.Add(1)
	for range racers {
		go func() {
			start.Wait()
			result, err := harness.call(t, "oAuth2token", http.MethodPost, contract.Headers{}, map[string]any{
				"grant_type": "authorization_code", "code": "single-use-code",
				"redirect_uri": client.RedirectURLs[0], "client_id": client.ClientID,
				"client_secret": client.ClientSecret,
			}, nil)
			var object map[string]any
			if result.Value != nil {
				object, _ = result.Value.(map[string]any)
			}
			results <- outcome{result: object, err: err}
		}()
	}
	start.Done()
	successes := 0
	failures := 0
	for range racers {
		result := <-results
		if result.err == nil && result.result["access_token"] != nil {
			successes++
			continue
		}
		if result.err != nil && result.result["error"] == "invalid_grant" {
			failures++
			continue
		}
		t.Fatalf("unexpected outcome=%#v", result)
	}
	if successes != 1 || failures != racers-1 {
		t.Fatalf("successes=%d failures=%d", successes, failures)
	}
}

func TestClientSecretStorageModesCompleteTokenExchange(t *testing.T) {
	for _, mode := range []ClientSecretStorageMode{
		ClientSecretPlain, ClientSecretHashed, ClientSecretEncrypted,
	} {
		t.Run(string(mode), func(t *testing.T) {
			harness := newHarness(t, func(options *Options) {
				options.RequirePKCE = false
				options.StoreClientSecret = mode
				options.GenerateClientID = func() string { return "storage-client" }
				options.GenerateClientSecret = func() string { return "storage-secret" }
			})
			userID, headers := harness.signUp(t, 42)
			registered := harness.register(t, headers, "storage", []string{"https://client.example/callback"})
			if registered["client_secret"] != "storage-secret" {
				t.Fatalf("registration=%#v", registered)
			}
			record, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
				Model: "oauthApplication", Where: []storage.Where{{Field: "clientId", Value: "storage-client"}},
			})
			if err != nil || record == nil {
				t.Fatalf("record=%#v err=%v", record, err)
			}
			stored, _ := recordString(record, "clientSecret")
			if mode == ClientSecretPlain && stored != "storage-secret" {
				t.Fatalf("plain stored=%q", stored)
			}
			if mode != ClientSecretPlain && stored == "storage-secret" {
				t.Fatalf("mode=%s stored plaintext", mode)
			}
			seedCode(t, harness, "storage-code", AuthorizationCodeValue{
				ClientID: "storage-client", RedirectURI: "https://client.example/callback",
				Scope: []string{"openid"}, UserID: userID,
			})
			exchanged, err := harness.call(t, "oAuth2token", http.MethodPost, contract.Headers{}, map[string]any{
				"grant_type": "authorization_code", "code": "storage-code",
				"redirect_uri": "https://client.example/callback", "client_id": "storage-client",
				"client_secret": "storage-secret",
			}, nil)
			if err != nil || responseObject(t, exchanged)["access_token"] == "" {
				t.Fatalf("exchange status=%d err=%v body=%s", exchanged.Response.Status(), err, exchanged.Response.Body())
			}
		})
	}
}

func TestJWTPluginSignsOIDCIDTokenWithEdDSA(t *testing.T) {
	harness := newHarness(t, func(options *Options) {
		options.RequirePKCE = false
		options.UseJWTPlugin = true
	}, jwtplugin.NewFactory(jwtplugin.Options{}))
	userID, headers := harness.signUp(t, 43)
	registered := harness.register(t, headers, "jwt-client", []string{"https://client.example/callback"})
	clientID := registered["client_id"].(string)
	seedCode(t, harness, "jwt-code", AuthorizationCodeValue{
		ClientID: clientID, RedirectURI: "https://client.example/callback",
		Scope: []string{"openid", "profile", "email"}, UserID: userID,
	})
	exchanged, err := harness.call(t, "oAuth2token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "authorization_code", "code": "jwt-code",
		"redirect_uri": "https://client.example/callback", "client_id": clientID,
		"client_secret": registered["client_secret"],
	}, nil)
	if err != nil {
		t.Fatalf("exchange: %v body=%s", err, exchanged.Response.Body())
	}
	token := responseObject(t, exchanged)["id_token"].(string)
	header := decodeJWTHeader(t, token)
	if header["alg"] != "EdDSA" || header["kid"] == "" {
		t.Fatalf("header=%#v", header)
	}
	jwksResult, err := harness.call(t, "getJwks", http.MethodGet, contract.Headers{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := responseObject(t, jwksResult)["keys"].([]any)
	var key map[string]any
	for _, raw := range keys {
		candidate := raw.(map[string]any)
		if candidate["kid"] == header["kid"] {
			key = candidate
			break
		}
	}
	if key == nil {
		t.Fatalf("kid=%v keys=%#v", header["kid"], keys)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(key["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicBytes), []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatalf("EdDSA signature invalid: %v", err)
	}
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil || payload["sub"] != userID || payload["aud"] != clientID {
		t.Fatalf("payload=%#v err=%v", payload, err)
	}
}
