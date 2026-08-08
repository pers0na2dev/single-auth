package admin

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestBannedSocialIDTokenReturnsTypedAdminError(t *testing.T) {
	const email = "banned-id-token@example.com"
	provider := newAdminGoogleProvider(t, email, nil)
	auth := newRootAuthConfigured(t, Options{BannedUserMessage: "Custom banned user message"}, func(options *singleauth.Options) {
		options.SocialProviders = map[string]*providers.Provider{"google": provider}
		previous := options.DatabaseHooks["user"].Create.Before
		options.DatabaseHooks = singleauth.DatabaseHooks{"user": {
			Create: singleauth.DatabaseOperationHooks{Before: func(data storage.Record, hook singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
				result, err := previous(data, hook)
				if err != nil {
					return result, err
				}
				if data["email"] == email {
					if result.Data == nil {
						result.Data = storage.Record{}
					}
					result.Data["banned"] = true
					result.Data["emailVerified"] = true
				}
				return result, nil
			}},
		}}
	})
	status, _, body := exchange(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
		"provider": "google", "idToken": map[string]any{"token": "valid-id-token", "accessToken": "access"},
	})
	assertError(t, status, body, http.StatusForbidden, ErrorBannedUser)
	if body["message"] != "Custom banned user message" {
		t.Fatalf("id-token banned body=%#v", body)
	}
}

func TestBannedSocialCallbackUsesCrossOriginErrorCallback(t *testing.T) {
	const (
		email            = "banned-social-callback@example.com"
		errorCallbackURL = "https://frontend.example.com/auth-error"
	)
	provider := newAdminGoogleProvider(t, email, &http.Client{Transport: adminSocialRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"callback-access","expires_in":3600,"scope":"openid profile"}`)),
			Request:    request,
		}, nil
	})})
	auth := newRootAuthConfigured(t, Options{BannedUserMessage: "Custom banned user message"}, func(options *singleauth.Options) {
		options.SocialProviders = map[string]*providers.Provider{"google": provider}
		options.TrustedOrigins = append(options.TrustedOrigins, "https://frontend.example.com")
	})
	admin := signUpIdentity(t, auth, "Admin", "social-callback-admin@example.com", "password123")
	user := signUpIdentity(t, auth, "User", email, "password123")
	if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: user.ID}},
		Update: storage.Record{"emailVerified": true},
	}); err != nil {
		t.Fatal(err)
	}
	status, _, body := exchange(t, auth, http.MethodPost, "/admin/ban-user", admin.Cookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK {
		t.Fatalf("ban status=%d body=%#v", status, body)
	}

	status, headers, body := exchange(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
		"provider": "google", "callbackURL": "http://auth.example.test/done", "errorCallbackURL": errorCallbackURL,
	})
	if status != http.StatusOK {
		t.Fatalf("social start status=%d body=%#v", status, body)
	}
	authorizeURL, err := url.Parse(body["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	state := authorizeURL.Query().Get("state")
	stateCookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, headers, body = exchange(t, auth, http.MethodGet, "/callback/google?code=valid-code&state="+url.QueryEscape(state), stateCookie, nil)
	if status != http.StatusFound {
		t.Fatalf("social callback status=%d body=%#v headers=%#v", status, body, headers)
	}
	location, err := url.Parse(firstHeader(headers, "Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Scheme+"://"+location.Host+location.Path != errorCallbackURL ||
		location.Query().Get("error") != ErrorBannedUser ||
		location.Query().Get("error_description") != "Custom banned user message" {
		t.Fatalf("social callback location=%q", location.String())
	}
}

func newAdminGoogleProvider(t *testing.T, email string, client *http.Client) *providers.Provider {
	t.Helper()
	provider, err := providers.Google(providers.Options{
		ClientID: "admin-client", ClientSecret: "admin-secret", HTTPClient: client,
		VerifyIDToken: func(context.Context, string, string) (bool, error) { return true, nil },
		GetUserInfo: func(context.Context, oauth2.Tokens) (*providers.UserInfoResult, error) {
			return &providers.UserInfoResult{User: oauth2.UserInfo{
				ID: "google-" + email, Name: "Banned Social", Email: &email, EmailVerified: true,
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func firstHeader(headers interface{ Values(string) []string }, name string) string {
	values := headers.Values(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

type adminSocialRoundTripFunc func(*http.Request) (*http.Response, error)

func (function adminSocialRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
