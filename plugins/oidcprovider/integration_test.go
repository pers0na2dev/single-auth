package oidcprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestAuthorizationConsentTokenUserInfoAndRefreshFlow(t *testing.T) {
	harness := newHarness(t, func(options *Options) {
		options.GetAdditionalUserInfoClaim = func(
			_ context.Context, user storage.Record, _ []string, _ Client,
		) (map[string]any, error) {
			userID, _ := recordString(user, "id")
			return map[string]any{"custom": "custom value", "userId": userID}, nil
		}
	})
	userID, headers := harness.signUp(t, 10)
	redirectURI := "http://localhost:3000/api/auth/oauth2/callback/test"
	registered := harness.register(t, headers, "test", []string{redirectURI})
	clientID := registered["client_id"].(string)
	clientSecret := registered["client_secret"].(string)
	verifier := "correct-horse-battery-staple-verifier-for-oidc"
	challenge := pkceChallenge(verifier)

	authorized, err := harness.call(t, "oAuth2authorize", http.MethodGet, headers, nil, url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid profile email offline_access"}, "state": {"state-123"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "nonce": {"nonce-123"},
	})
	if err != nil || authorized.Response.Status() != http.StatusFound {
		t.Fatalf("authorize status=%d err=%v body=%s", authorized.Response.Status(), err, authorized.Response.Body())
	}
	consentLocation := headerValue(authorized.Response.Headers(), "Location")
	consentURL, err := url.Parse(consentLocation)
	if err != nil || !strings.Contains(consentURL.Path, "/oauth2/authorize") {
		t.Fatalf("consent location=%q err=%v", consentLocation, err)
	}
	consentCode := consentURL.Query().Get("consent_code")
	if consentCode == "" || consentURL.Query().Get("client_id") != clientID ||
		consentURL.Query().Get("scope") != "openid profile email offline_access" {
		t.Fatalf("consent URL=%s", consentURL)
	}
	consented, err := harness.call(t, "oAuthConsent", http.MethodPost, headers, map[string]any{
		"accept": true, "consent_code": consentCode,
	}, nil)
	if err != nil {
		t.Fatalf("consent: %v body=%s", err, consented.Response.Body())
	}
	callback := responseObject(t, consented)["redirectURI"].(string)
	callbackURL, err := url.Parse(callback)
	if err != nil || callbackURL.Query().Get("state") != "state-123" {
		t.Fatalf("callback=%q err=%v", callback, err)
	}
	code := callbackURL.Query().Get("code")
	if code == "" {
		t.Fatalf("callback has no code: %q", callback)
	}

	exchanged, err := harness.call(t, "oAuth2token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "authorization_code", "code": code, "redirect_uri": redirectURI,
		"client_id": clientID, "client_secret": clientSecret, "code_verifier": verifier,
	}, nil)
	if err != nil {
		t.Fatalf("exchange: %v body=%s", err, exchanged.Response.Body())
	}
	token := responseObject(t, exchanged)
	if token["access_token"] == "" || token["refresh_token"] == "" ||
		token["id_token"] == "" || token["token_type"] != "Bearer" ||
		token["expires_in"] != json.Number("3600") ||
		token["scope"] != "openid profile email offline_access" {
		t.Fatalf("token=%#v", token)
	}
	if headerValue(exchanged.Response.Headers(), "Cache-Control") != "no-store" ||
		headerValue(exchanged.Response.Headers(), "Pragma") != "no-cache" {
		t.Fatalf("token headers=%#v", exchanged.Response.Headers())
	}
	claims := verifyHS256(token["id_token"].(string), clientSecret, harness.clock.Now())
	if claims == nil || claims["sub"] != userID || claims["aud"] != clientID ||
		claims["nonce"] != "nonce-123" || claims["email"] == "" ||
		claims["custom"] != "custom value" || claims["userId"] != userID {
		t.Fatalf("claims=%#v", claims)
	}

	info, err := harness.call(t, "oAuth2userInfo", http.MethodGet, contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer " + token["access_token"].(string)},
	), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	userInfo := responseObject(t, info)
	if userInfo["sub"] != userID || userInfo["email"] == "" || userInfo["name"] == "" ||
		userInfo["custom"] != "custom value" || userInfo["userId"] != userID {
		t.Fatalf("userinfo=%#v", userInfo)
	}

	refreshed, err := harness.call(t, "oAuth2token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "refresh_token", "refresh_token": token["refresh_token"],
		"client_id": clientID, "client_secret": clientSecret,
	}, nil)
	if err != nil {
		t.Fatalf("refresh: %v body=%s", err, refreshed.Response.Body())
	}
	refresh := responseObject(t, refreshed)
	if refresh["access_token"] == "" || refresh["refresh_token"] == "" ||
		refresh["token_type"] != "Bearer" || refresh["scope"] != "openid profile email offline_access" {
		t.Fatalf("refresh=%#v", refresh)
	}
}

func TestConsentCanUseSignedCookieAndDenialIsSingleUse(t *testing.T) {
	harness := newHarness(t, nil)
	_, headers := harness.signUp(t, 11)
	redirectURI := "https://client.example/callback"
	registered := harness.register(t, headers, "cookie-consent", []string{redirectURI})
	authorized, err := harness.call(t, "oAuth2authorize", http.MethodGet, headers, nil, url.Values{
		"client_id": {registered["client_id"].(string)}, "redirect_uri": {redirectURI},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"deny-state"},
		"code_challenge": {"challenge"}, "code_challenge_method": {"S256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookies.ApplySetCookies("", authorized.Response.Headers().Values("Set-Cookie"))
	consentHeaders := headers.Clone()
	consentHeaders.Set("Cookie", headerValue(headers, "Cookie")+"; "+cookie)
	denied, err := harness.call(t, "oAuthConsent", http.MethodPost, consentHeaders, map[string]any{
		"accept": false,
	}, nil)
	if err != nil {
		t.Fatalf("deny: %v body=%s", err, denied.Response.Body())
	}
	location := responseObject(t, denied)["redirectURI"].(string)
	if !strings.Contains(location, "error=access_denied") {
		t.Fatalf("denial=%q", location)
	}
	replay, replayErr := harness.call(t, "oAuthConsent", http.MethodPost, consentHeaders, map[string]any{
		"accept": false,
	}, nil)
	oauthErrorObject(t, replay, replayErr, http.StatusUnauthorized, "invalid_request")
}

func decodeJWTHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token=%q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]any{}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
