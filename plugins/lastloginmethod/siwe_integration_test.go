package lastloginmethod

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/plugins/siwe"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestSIWESetsCookieAndDatabaseMethod(t *testing.T) {
	const (
		wallet = "0x000000000000000000000000000000000000dEaD"
		nonce  = "A1b2C3d4E5f6G7h8J"
		email  = "last-login-siwe@example.com"
	)
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "https://example.com", Secret: integrationSecret,
		PluginFactories: []singleauth.PluginFactory{
			NewFactory(Options{StoreInDatabase: true}),
			siwe.NewFactory(siwe.Options{
				Domain:   "example.com",
				GetNonce: func(context.Context) (string, error) { return nonce, nil },
				VerifyMessage: func(_ context.Context, args siwe.VerifyMessageArgs) (bool, error) {
					return args.Signature == "valid_signature", nil
				},
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	nonceResponse := serveLastLoginJSON(t, auth, "/api/auth/siwe/nonce", map[string]any{
		"walletAddress": wallet, "chainId": 1,
	})
	if nonceResponse.Code != http.StatusOK {
		t.Fatalf("nonce status=%d body=%s", nonceResponse.Code, nonceResponse.Body.String())
	}

	message := "example.com wants you to sign in with your Ethereum account:\n" +
		wallet + "\n\nSign in.\n\n" +
		"URI: https://example.com\n" +
		"Version: 1\n" +
		"Chain ID: 1\n" +
		"Nonce: " + nonce + "\n" +
		"Issued At: " + time.Now().UTC().Format(time.RFC3339)
	verifyResponse := serveLastLoginJSON(t, auth, "/api/auth/siwe/verify", map[string]any{
		"message": message, "signature": "valid_signature", "walletAddress": wallet,
		"chainId": 1, "email": email,
	})
	if verifyResponse.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verifyResponse.Code, verifyResponse.Body.String())
	}
	response := contract.NewResponse(verifyResponse.Code, headersFromHTTP(verifyResponse.Header()), nil)
	methodCookie, exists := responseCookie(response, DefaultCookieName)
	if !exists || methodCookie.Attributes.Value != "siwe" {
		t.Fatalf("SIWE cookies=%#v", verifyResponse.Header().Values("Set-Cookie"))
	}
	var verified map[string]any
	if err := json.Unmarshal(verifyResponse.Body.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	verifiedUser, ok := verified["user"].(map[string]any)
	if !ok || verifiedUser["id"] == "" {
		t.Fatalf("verify response=%#v", verified)
	}
	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: verifiedUser["id"]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || user["lastLoginMethod"] != "siwe" {
		t.Fatalf("stored SIWE user=%#v", user)
	}
}

func serveLastLoginJSON(t *testing.T, auth *singleauth.Auth, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://example.com"+path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://example.com")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	return recorder
}
