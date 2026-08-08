package core

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestSocialIDTokenAccountAndRefreshRoutes(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	refreshCalls := 0
	lastUserInfoToken := ""
	email := "social@example.com"
	provider, err := providers.Google(providers.Options{
		ClientID: "client", ClientSecret: "secret",
		VerifyIDToken: func(context.Context, string, string) (bool, error) { return true, nil },
		GetUserInfo: func(_ context.Context, tokens oauth2.Tokens) (*providers.UserInfoResult, error) {
			lastUserInfoToken = tokens.AccessToken
			return &providers.UserInfoResult{User: oauth2.UserInfo{
				ID: "google-user", Name: "Social User", Email: &email,
				Image: "https://example.com/avatar.png", EmailVerified: true,
			}, Data: map[string]any{"sub": "google-user"}}, nil
		},
		RefreshAccessToken: func(_ context.Context, token string) (oauth2.Tokens, error) {
			refreshCalls++
			wantToken := "old-refresh"
			if refreshCalls > 1 {
				wantToken = "rotated-refresh"
			}
			if token != wantToken {
				t.Fatalf("refresh token = %q", token)
			}
			expires := now.Add(time.Hour)
			return oauth2.Tokens{
				AccessToken: "new-access", RefreshToken: "rotated-refresh",
				AccessTokenExpiresAt: &expires, Scopes: []string{"openid", "profile"},
				IDToken: "new-id-token",
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := MustNew(Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		Clock: func() time.Time { return now },
		Account: AccountOptions{
			EncryptOAuthTokens: true, StoreAccountCookie: storage.Bool(true),
		},
		SocialProviders: map[string]*providers.Provider{"google": provider},
	})

	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token": "provider-id-token", "accessToken": "initial-access",
			"refreshToken": "must-not-be-persisted-by-sign-in-id-token",
		},
	})
	if status != http.StatusOK {
		t.Fatalf("social id token status=%d value=%#v", status, value)
	}
	result := value.(map[string]any)
	if result["redirect"] != false || objectString(t, result, "token") == "" {
		t.Fatalf("social result = %#v", result)
	}
	cookieHeader := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	if !strings.Contains(cookieHeader, auth.options.cookie.accountDataName+"=") {
		t.Fatalf("account cookie was not stored: %s", cookieHeader)
	}
	account, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{
			{Field: "providerId", Value: "google"}, {Field: "accountId", Value: "google-user"},
		},
	})
	if err != nil || account == nil {
		t.Fatalf("social account = %#v err=%v", account, err)
	}
	storedAccess, _ := recordString(account, "accessToken")
	if storedAccess == "initial-access" || storedAccess == "" {
		t.Fatalf("access token was not encrypted: %q", storedAccess)
	}
	if _, exists := account["refreshToken"]; exists {
		t.Fatalf("id-token sign-in persisted refresh token unlike upstream: %#v", account)
	}
	storedRefresh, err := auth.storeOAuthToken("old-refresh")
	if err != nil {
		t.Fatal(err)
	}
	accountID := mustRecordString(account, "id")
	if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "account", Where: []storage.Where{{Field: "id", Value: accountID}},
		Update: storage.Record{
			"refreshToken": storedRefresh, "accessTokenExpiresAt": now.Add(-time.Second),
		},
	}); err != nil {
		t.Fatal(err)
	}
	// The account cookie is a five-minute snapshot. This synthetic DB mutation
	// intentionally bypassed its writer, so remove only that snapshot and keep
	// the authoritative session cookie for the refresh request.
	requestCookies := cookies.Parsed{}
	for _, pair := range cookies.Parse(cookieHeader).Pairs() {
		if !strings.HasPrefix(pair.Name, auth.options.cookie.accountDataName) {
			requestCookies.Set(pair.Name, pair.Value)
		}
	}
	cookieHeader = requestCookies.Header()
	status, headers, value = sessionTestRequest(t, auth, http.MethodPost, "/get-access-token", cookieHeader, map[string]any{
		"providerId": "google", "accountId": "google-user",
	})
	if status != http.StatusOK || value.(map[string]any)["accessToken"] != "new-access" || refreshCalls != 1 {
		t.Fatalf("get access token status=%d value=%#v refreshCalls=%d", status, value, refreshCalls)
	}
	cookieHeader = cookies.ApplySetCookies(cookieHeader, headers.Values("Set-Cookie"))
	status, _, value = sessionTestRequest(
		t, auth, http.MethodGet,
		"/account-info?accountId=google-user&providerId=google", cookieHeader, nil,
	)
	if status != http.StatusOK {
		t.Fatalf("account info status=%d value=%#v", status, value)
	}
	info := value.(map[string]any)
	if objectString(t, objectValue(t, info, "user"), "id") != "google-user" || lastUserInfoToken != "new-access" {
		t.Fatalf("account info=%#v last token=%q", info, lastUserInfoToken)
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/refresh-token", cookieHeader, map[string]any{
		"providerId": "google", "accountId": "google-user",
	})
	if status != http.StatusOK || value.(map[string]any)["refreshToken"] != "rotated-refresh" || refreshCalls != 2 {
		t.Fatalf("refresh status=%d value=%#v calls=%d", status, value, refreshCalls)
	}
}

func TestOAuthDatabaseStateCallbackIsBoundAndSingleUse(t *testing.T) {
	email := "callback@example.com"
	provider, err := providers.Google(providers.Options{
		ClientID: "client", ClientSecret: "secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://oauth2.googleapis.com/token" {
				t.Fatalf("unexpected outbound URL %s", request.URL)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					`{"access_token":"callback-access","refresh_token":"callback-refresh","expires_in":3600,"scope":"openid profile"}`,
				)),
				Request: request,
			}, nil
		})},
		GetUserInfo: func(context.Context, oauth2.Tokens) (*providers.UserInfoResult, error) {
			return &providers.UserInfoResult{User: oauth2.UserInfo{
				ID: "callback-user", Name: "Callback User", Email: &email, EmailVerified: true,
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := MustNew(Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		Account:         AccountOptions{StoreStateStrategy: "database"},
		SocialProviders: map[string]*providers.Provider{"google": provider},
	})
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
		"provider": "google", "callbackURL": "http://auth.test/done",
	})
	if status != http.StatusOK || value.(map[string]any)["redirect"] != true {
		t.Fatalf("authorize status=%d value=%#v", status, value)
	}
	authorizeURL, err := url.Parse(objectString(t, value.(map[string]any), "url"))
	if err != nil {
		t.Fatal(err)
	}
	state := authorizeURL.Query().Get("state")
	if state == "" || authorizeURL.Query().Get("code_challenge") == "" {
		t.Fatalf("authorize URL missing state/PKCE: %s", authorizeURL)
	}
	cookieHeader := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, callbackHeaders, value := sessionTestRequest(
		t, auth, http.MethodGet,
		"/callback/google?code=valid-code&state="+url.QueryEscape(state), cookieHeader, nil,
	)
	if status != http.StatusFound || callbackHeaders.Get("Location") != "http://auth.test/done" || value != nil {
		t.Fatalf("callback status=%d location=%q value=%#v", status, callbackHeaders.Get("Location"), value)
	}
	if len(callbackHeaders.Values("Set-Cookie")) < 2 {
		t.Fatalf("callback did not expire state and create session: %#v", callbackHeaders)
	}
	status, callbackHeaders, _ = sessionTestRequest(
		t, auth, http.MethodGet,
		"/callback/google?code=valid-code&state="+url.QueryEscape(state), cookieHeader, nil,
	)
	location, _ := url.Parse(callbackHeaders.Get("Location"))
	if status != http.StatusFound || location.Query().Get("error") != "state_mismatch" {
		t.Fatalf("replayed state status=%d location=%q", status, callbackHeaders.Get("Location"))
	}
}

func TestLinkSocialIDTokenProviderScopedAccount(t *testing.T) {
	email := "link@example.com"
	provider, err := providers.Google(providers.Options{
		ClientID: "client", ClientSecret: "secret",
		VerifyIDToken: func(context.Context, string, string) (bool, error) { return true, nil },
		GetUserInfo: func(context.Context, oauth2.Tokens) (*providers.UserInfoResult, error) {
			return &providers.UserInfoResult{User: oauth2.UserInfo{
				ID: "linked-google", Name: "Linked", Email: &email, EmailVerified: true,
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		SocialProviders:  map[string]*providers.Provider{"google": provider},
	})
	cookieHeader, _, _ := createSessionTestUser(t, auth, email)
	body := map[string]any{
		"provider": "google",
		"idToken":  map[string]any{"token": "valid", "accessToken": "linked-access"},
	}
	status, _, value := sessionTestRequest(t, auth, http.MethodPost, "/link-social", cookieHeader, body)
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("link status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/link-social", cookieHeader, body)
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("idempotent link status=%d value=%#v", status, value)
	}
	accounts, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "providerId", Value: "google"}},
	})
	if err != nil || len(accounts) != 1 || mustRecordString(accounts[0], "accountId") != "linked-google" {
		t.Fatalf("linked accounts=%#v err=%v", accounts, err)
	}
}

func TestOAuthVerificationEmailKeepsLegacyRootCallbackWhenCallerOmitsCallbackURL(t *testing.T) {
	email := "unverified-social@example.com"
	provider, err := providers.Google(providers.Options{
		ClientID: "client", ClientSecret: "secret",
		VerifyIDToken: func(context.Context, string, string) (bool, error) { return true, nil },
		GetUserInfo: func(context.Context, oauth2.Tokens) (*providers.UserInfoResult, error) {
			return &providers.UserInfoResult{User: oauth2.UserInfo{
				ID: "unverified-social", Name: "Unverified Social", Email: &email,
				EmailVerified: false,
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var delivered EmailVerificationMessage
	auth := MustNew(Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{RequireEmailVerification: true},
		EmailVerification: EmailVerificationOptions{
			SendOnSignUp: storage.Bool(true),
			SendVerificationEmail: func(_ context.Context, message EmailVerificationMessage) error {
				delivered = message
				return nil
			},
		},
		SocialProviders: map[string]*providers.Provider{"google": provider},
	})
	status, _, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
		"provider": "google", "idToken": map[string]any{"token": "provider-token"},
	})
	if status != http.StatusOK {
		t.Fatalf("social sign-in status=%d value=%#v", status, value)
	}
	verificationURL, err := url.Parse(delivered.URL)
	if err != nil {
		t.Fatal(err)
	}
	if verificationURL.Query().Get("callbackURL") != "/" {
		t.Fatalf("legacy verification callbackURL=%q URL=%q", verificationURL.Query().Get("callbackURL"), delivered.URL)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
