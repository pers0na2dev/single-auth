package genericoauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestGenericOAuthNewExistingSignInStateCleanupAndRootProviderIntegration(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "oauth2-user", "email": "oauth2@test.com", "name": "OAuth2 Test",
		"picture": "https://example.test/avatar.png", "email_verified": true,
	})
	auth := genericTestAuth(t, server.config("test"), func(options *singleauth.Options) {
		options.Account.EncryptOAuthTokens = true
		options.Account.StoreAccountCookie = storage.Bool(true)
	})

	flow := startGenericFlow(
		t, auth, "test", genericBaseURL+"/dashboard", genericBaseURL+"/new_user", "", nil,
	)
	if flow.AuthorizationURL.Host != strings.TrimPrefix(server.server.URL, "http://") ||
		flow.AuthorizationURL.Path != "/authorize" ||
		flow.AuthorizationURL.Query().Get("client_id") != "client-id" ||
		flow.AuthorizationURL.Query().Get("scope") != "openid profile email" ||
		flow.AuthorizationURL.Query().Get("code_challenge") == "" ||
		flow.AuthorizationURL.Query().Get("redirect_uri") != genericBaseURL+"/api/auth/oauth2/callback/test" {
		t.Fatalf("authorization URL = %s", flow.AuthorizationURL)
	}
	callback := finishGenericFlow(t, auth, "test", flow, nil)
	if callback.Status != http.StatusFound || callback.Header.Get("Location") != genericBaseURL+"/new_user" {
		t.Fatalf("new-user callback status=%d location=%q body=%s", callback.Status, callback.Header.Get("Location"), callback.Body)
	}
	setCookies := strings.Join(callback.Header.Values("Set-Cookie"), "\n")
	if !strings.Contains(setCookies, "single-auth.state=; Max-Age=0") ||
		!strings.Contains(setCookies, "Path=/") {
		t.Fatalf("state cleanup cookie = %s", setCookies)
	}
	users := genericRecords(t, auth, "user")
	accounts := genericRecords(t, auth, "account")
	sessions := genericRecords(t, auth, "session")
	if len(users) != 1 || users[0]["email"] != "oauth2@test.com" ||
		len(accounts) != 1 || accounts[0]["providerId"] != "test" ||
		accounts[0]["accountId"] != "oauth2-user" || len(sessions) != 1 {
		t.Fatalf("records users=%#v accounts=%#v sessions=%#v", users, accounts, sessions)
	}
	if accounts[0]["accessToken"] == "access-token" || accounts[0]["refreshToken"] == "refresh-token" {
		t.Fatalf("OAuth tokens were not encrypted: %#v", accounts[0])
	}

	access := genericExchange(t, auth, http.MethodPost, "/get-access-token", map[string]any{
		"providerId": "test", "accountId": "oauth2-user",
	}, flow.Jar)
	if access.Status != http.StatusOK || !strings.Contains(string(access.Body), `"accessToken":"access-token"`) {
		t.Fatalf("registered provider get-access-token status=%d body=%s", access.Status, access.Body)
	}

	second := startGenericFlow(t, auth, "test", genericBaseURL+"/dashboard", genericBaseURL+"/new_user", "", nil)
	secondCallback := finishGenericFlow(t, auth, "test", second, nil)
	if secondCallback.Status != http.StatusFound || secondCallback.Header.Get("Location") != genericBaseURL+"/dashboard" {
		t.Fatalf("existing-user callback status=%d location=%q", secondCallback.Status, secondCallback.Header.Get("Location"))
	}
	if len(genericRecords(t, auth, "user")) != 1 || len(genericRecords(t, auth, "account")) != 1 {
		t.Fatalf("repeat sign-in duplicated user/account")
	}
}

func TestGenericOAuthProfileIDResolutionMappingAndMissingFieldFailures(t *testing.T) {
	tests := []struct {
		name        string
		profile     Profile
		custom      bool
		mapProfile  MapProfileToUserFunc
		wantID      string
		wantError   string
		wantNoUsers bool
	}{
		{
			name:    "empty endpoint id falls back to sub",
			profile: Profile{"id": "", "sub": "fallback-empty", "email": "empty@test.com", "name": "Empty"},
			wantID:  "fallback-empty",
		},
		{
			name:    "null endpoint id falls back to sub",
			profile: Profile{"id": nil, "sub": "fallback-null", "email": "null@test.com", "name": "Null"},
			wantID:  "fallback-null",
		},
		{
			name:    "nonempty endpoint id wins over sub",
			profile: Profile{"id": "stable-id", "sub": "different-sub", "email": "stable@test.com", "name": "Stable"},
			wantID:  "stable-id",
		},
		{
			name:    "numeric endpoint id",
			profile: Profile{"id": 123456789, "sub": "numeric-sub", "email": "numeric@test.com", "name": "Numeric"},
			wantID:  "123456789",
		},
		{
			name: "custom empty id falls back to sub", custom: true,
			profile: Profile{"id": "", "sub": "custom-sub", "email": "custom-sub@test.com", "name": "Custom Sub"},
			wantID:  "custom-sub",
		},
		{
			name: "custom numeric id", custom: true,
			profile: Profile{"id": 987654321, "email": "custom-number@test.com", "name": "Custom Number"},
			wantID:  "987654321",
		},
		{
			name:    "map derives id from nonstandard field",
			profile: Profile{"athlete_id": 7654, "email": "strava@test.com", "name": "Strava"},
			mapProfile: func(_ context.Context, profile Profile) (Profile, error) {
				return Profile{"id": profile["athlete_id"], "email": profile["email"], "name": profile["name"]}, nil
			},
			wantID: "7654",
		},
		{
			name:    "map returns numeric id",
			profile: Profile{"sub": "ignored", "email": "mapped-number@test.com", "name": "Mapped"},
			mapProfile: func(_ context.Context, profile Profile) (Profile, error) {
				return Profile{"id": 2468, "email": profile["email"], "name": profile["name"]}, nil
			},
			wantID: "2468",
		},
		{
			name:      "missing provider id",
			profile:   Profile{"email": "missing-id@test.com", "name": "Missing ID"},
			wantError: "id_is_missing", wantNoUsers: true,
		},
		{
			name: "custom missing id", custom: true,
			profile:   Profile{"id": "", "email": "custom-missing@test.com", "name": "Custom Missing"},
			wantError: "id_is_missing", wantNoUsers: true,
		},
		{
			name:    "missing email after mapping",
			profile: Profile{"sub": "missing-email", "name": "Missing Email"},
			mapProfile: func(_ context.Context, _ Profile) (Profile, error) {
				return Profile{"id": "missing-email", "name": "Missing Email"}, nil
			},
			wantError: "email_is_missing", wantNoUsers: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newGenericOAuthServer(t, test.profile)
			config := server.config("profile-test")
			config.MapProfileToUser = test.mapProfile
			if test.custom {
				profile := cloneProfile(test.profile)
				config.GetUserInfo = func(context.Context, oauth2.Tokens) (Profile, error) {
					return cloneProfile(profile), nil
				}
			}
			auth := genericTestAuth(t, config, nil)
			flow := startGenericFlow(t, auth, "profile-test", genericBaseURL+"/done", "", "", nil)
			callback := finishGenericFlow(t, auth, "profile-test", flow, nil)
			location, err := url.Parse(callback.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if test.wantError != "" {
				if callback.Status != http.StatusFound || location.Query().Get("error") != test.wantError {
					t.Fatalf("callback status=%d location=%q", callback.Status, location)
				}
				if test.wantNoUsers && len(genericRecords(t, auth, "user")) != 0 {
					t.Fatalf("failed profile created user")
				}
				return
			}
			if callback.Status != http.StatusFound || callback.Header.Get("Location") != genericBaseURL+"/done" {
				t.Fatalf("callback status=%d location=%q body=%s", callback.Status, callback.Header.Get("Location"), callback.Body)
			}
			accounts := genericRecords(t, auth, "account")
			if len(accounts) != 1 || genericRecordString(accounts[0], "accountId") != test.wantID {
				t.Fatalf("accounts = %#v, want id %q", accounts, test.wantID)
			}
			if test.wantID == "123456789" {
				repeat := startGenericFlow(t, auth, "profile-test", genericBaseURL+"/done", "", "", nil)
				if response := finishGenericFlow(t, auth, "profile-test", repeat, nil); response.Header.Get("Location") != genericBaseURL+"/done" {
					t.Fatalf("numeric repeat callback=%q", response.Header.Get("Location"))
				}
				if len(genericRecords(t, auth, "account")) != 1 || len(genericRecords(t, auth, "user")) != 1 {
					t.Fatalf("numeric account ID duplicated records")
				}
			}
		})
	}
}

func TestGenericOAuthRegisteredProviderWrapperFallsBackFromEmptyIDToSubject(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"id": "", "sub": "wrapped-sub", "email": "wrapped@test.com", "name": "Wrapped",
	})
	auth := genericTestAuth(t, server.config("wrapped"), nil)
	flow := startGenericFlow(t, auth, "wrapped", genericBaseURL+"/done", "", "", nil)
	if callback := finishGenericFlow(t, auth, "wrapped", flow, nil); callback.Header.Get("Location") != genericBaseURL+"/done" {
		t.Fatalf("callback=%q", callback.Header.Get("Location"))
	}
	response := genericExchange(
		t, auth, http.MethodGet,
		"/account-info?providerId=wrapped&accountId=wrapped-sub", nil, flow.Jar,
	)
	if response.Status != http.StatusOK {
		t.Fatalf("account-info status=%d body=%s", response.Status, response.Body)
	}
	result := decodeGenericJSON(t, response.Body)
	user, ok := result["user"].(map[string]any)
	if !ok || user["id"] != "wrapped-sub" {
		t.Fatalf("provider wrapper user=%#v", result["user"])
	}
}

func TestGenericOAuthSignInUsesCustomRedirectURIForAuthorizationAndTokenExchange(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "custom-redirect", "email": "custom-redirect@test.com", "name": "Custom Redirect",
	})
	config := server.config("custom-redirect")
	config.RedirectURI = "https://oauth.example.test/dedicated-callback"
	auth := genericTestAuth(t, config, nil)
	flow := startGenericFlow(
		t, auth, "custom-redirect", genericBaseURL+"/dashboard", genericBaseURL+"/new", "", nil,
	)
	if flow.AuthorizationURL.Query().Get("redirect_uri") != config.RedirectURI {
		t.Fatalf("authorization redirect_uri=%q", flow.AuthorizationURL.Query().Get("redirect_uri"))
	}
	callback := finishGenericFlow(t, auth, "custom-redirect", flow, nil)
	if callback.Header.Get("Location") != genericBaseURL+"/new" {
		t.Fatalf("callback location=%q", callback.Header.Get("Location"))
	}
	_, body := server.lastTokenRequest()
	if body.Get("redirect_uri") != config.RedirectURI {
		t.Fatalf("token redirect_uri=%q", body.Get("redirect_uri"))
	}
}

func TestGenericOAuthCustomTokenProfileCallbacksParametersAndFailures(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "callback-user", "email": "callback@test.com", "name": "Callback User",
	})
	var tokenInput TokenRequest
	var mapCalls atomic.Int32
	config := server.config("callbacks")
	config.AuthorizationURLParams = ParamSource{Static: map[string]string{"prompt": "custom", "audience": "api"}}
	config.TokenURLParams = ParamSource{Resolve: func(ctx *engine.Context) map[string]string {
		if ctx.Request().Method() != http.MethodGet {
			t.Fatalf("token param resolver method = %q", ctx.Request().Method())
		}
		return map[string]string{"resource": "custom-resource"}
	}}
	config.AuthorizationHeaders = map[string]string{"X-Custom-Header": "test-value"}
	config.MapProfileToUser = func(_ context.Context, profile Profile) (Profile, error) {
		mapCalls.Add(1)
		return Profile{"id": profile["sub"], "email": profile["email"], "name": "Mapped Name"}, nil
	}
	auth := genericTestAuth(t, config, nil)
	flow := startGenericFlow(t, auth, "callbacks", genericBaseURL+"/done", "", "", map[string]any{
		"scopes": []string{"extra"},
	})
	query := flow.AuthorizationURL.Query()
	if query.Get("prompt") != "custom" || query.Get("audience") != "api" || query.Get("scope") != "extra openid profile email" {
		t.Fatalf("authorization params = %s", flow.AuthorizationURL)
	}
	callback := finishGenericFlow(t, auth, "callbacks", flow, nil)
	if callback.Header.Get("Location") != genericBaseURL+"/done" || mapCalls.Load() != 1 {
		t.Fatalf("callback=%q map calls=%d", callback.Header.Get("Location"), mapCalls.Load())
	}
	request, body := server.lastTokenRequest()
	if request == nil || request.Header.Get("X-Custom-Header") != "test-value" ||
		body.Get("resource") != "custom-resource" || body.Get("code_verifier") == "" {
		t.Fatalf("token request=%#v body=%#v", request, body)
	}

	custom := server.config("custom-token")
	custom.GetToken = func(_ context.Context, input TokenRequest) (oauth2.Tokens, error) {
		tokenInput = input
		return oauth2.Tokens{AccessToken: "custom-access"}, nil
	}
	custom.GetUserInfo = func(_ context.Context, tokens oauth2.Tokens) (Profile, error) {
		if tokens.AccessToken != "custom-access" {
			t.Fatalf("custom user-info tokens = %#v", tokens)
		}
		return Profile{"id": "custom-id", "email": "custom-token@test.com", "name": "Custom Token"}, nil
	}
	customAuth := genericTestAuth(t, custom, nil)
	customFlow := startGenericFlow(t, customAuth, "custom-token", genericBaseURL+"/done", "", "", nil)
	customCallback := finishGenericFlow(t, customAuth, "custom-token", customFlow, nil)
	if customCallback.Header.Get("Location") != genericBaseURL+"/done" || tokenInput.Code != "valid-code" ||
		tokenInput.CodeVerifier == "" || tokenInput.RedirectURI != genericBaseURL+"/api/auth/oauth2/callback/custom-token" {
		t.Fatalf("custom token callback=%q input=%#v", customCallback.Header.Get("Location"), tokenInput)
	}

	failing := server.config("failing-token")
	failing.GetToken = func(context.Context, TokenRequest) (oauth2.Tokens, error) {
		return oauth2.Tokens{}, errors.New("token exchange failed")
	}
	failingAuth := genericTestAuth(t, failing, nil)
	failingFlow := startGenericFlow(t, failingAuth, "failing-token", genericBaseURL+"/done", "", genericBaseURL+"/oauth-error", nil)
	failingCallback := finishGenericFlow(t, failingAuth, "failing-token", failingFlow, nil)
	location, _ := url.Parse(failingCallback.Header.Get("Location"))
	if location.Path != "/oauth-error" || location.Query().Get("error") != "oauth_code_verification_failed" {
		t.Fatalf("custom token failure location=%q", failingCallback.Header.Get("Location"))
	}
}

func TestGenericOAuthInvalidProviderAndServerError(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "server-error", "email": "server@test.com", "name": "Server",
	})
	auth := genericTestAuth(t, server.config("test"), nil)
	invalid := genericExchange(t, auth, http.MethodPost, "/sign-in/oauth2", map[string]any{
		"providerId": "invalid-provider", "callbackURL": genericBaseURL + "/done",
	}, nil)
	if invalid.Status != http.StatusBadRequest || !strings.Contains(string(invalid.Body), ErrorMessages[ErrorProviderConfigNotFound]) {
		t.Fatalf("invalid provider status=%d body=%s", invalid.Status, invalid.Body)
	}
	server.mu.Lock()
	server.userInfoStatus = http.StatusInternalServerError
	server.mu.Unlock()
	flow := startGenericFlow(t, auth, "test", genericBaseURL+"/done", "", "", nil)
	callback := finishGenericFlow(t, auth, "test", flow, nil)
	location, _ := url.Parse(callback.Header.Get("Location"))
	if callback.Status != http.StatusFound || location.Query().Get("error") != "user_info_is_missing" {
		t.Fatalf("server error callback status=%d location=%q body=%s", callback.Status, callback.Header.Get("Location"), callback.Body)
	}
}

func TestGenericOAuthEmptyCallbackURLFallsBackToConfiguredBaseURL(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "default-callback", "email": "default-callback@test.com", "name": "Default Callback",
	})
	auth := genericTestAuth(t, server.config("test"), nil)
	flow := startGenericFlow(t, auth, "test", "", "", "", nil)
	callback := finishGenericFlow(t, auth, "test", flow, nil)
	if callback.Status != http.StatusFound || callback.Header.Get("Location") != genericBaseURL {
		t.Fatalf("callback status=%d location=%q", callback.Status, callback.Header.Get("Location"))
	}
}

func TestGenericOAuthRootFactoryRejectsProviderIDCollision(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "collision", "email": "collision@test.com", "name": "Collision",
	})
	_, err := singleauth.New(singleauth.Options{
		BaseURL: genericBaseURL,
		Secret:  genericSecret,
		SocialProviders: map[string]*providers.Provider{
			"test": {ID: "test", Name: "Existing provider"},
		},
		PluginFactories: []singleauth.PluginFactory{
			NewFactory(Options{Config: []Config{server.config("test")}}),
		},
	})
	if err == nil || !strings.Contains(err.Error(), `social provider "test" is already registered`) {
		t.Fatalf("provider collision error=%v", err)
	}
}

func decodeGenericJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
