package genericoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestGenericOAuthDisableImplicitSignUpAndExplicitRequest(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "signup-control", "email": "signup-control@test.com", "name": "Signup Control",
	})
	config := server.config("signup-control")
	config.DisableImplicitSignUp = true
	auth := genericTestAuth(t, config, nil)

	blocked := startGenericFlow(
		t, auth, "signup-control", genericBaseURL+"/dashboard", "", genericBaseURL+"/error", nil,
	)
	blockedCallback := finishGenericFlow(t, auth, "signup-control", blocked, nil)
	blockedURL, _ := url.Parse(blockedCallback.Header.Get("Location"))
	if blockedURL.Path != "/error" || blockedURL.Query().Get("error") != "signup_disabled" ||
		len(genericRecords(t, auth, "user")) != 0 {
		t.Fatalf("implicit signup response=%q users=%#v", blockedCallback.Header.Get("Location"), genericRecords(t, auth, "user"))
	}

	requested := startGenericFlow(
		t, auth, "signup-control", genericBaseURL+"/dashboard", "", genericBaseURL+"/error",
		map[string]any{"requestSignUp": true},
	)
	requestedCallback := finishGenericFlow(t, auth, "signup-control", requested, nil)
	if requestedCallback.Header.Get("Location") != genericBaseURL+"/dashboard" || len(genericRecords(t, auth, "user")) != 1 {
		t.Fatalf("explicit signup response=%q users=%#v", requestedCallback.Header.Get("Location"), genericRecords(t, auth, "user"))
	}

	permanentlyDisabled := server.config("disabled")
	permanentlyDisabled.DisableSignUp = true
	disabledAuth := genericTestAuth(t, permanentlyDisabled, nil)
	disabled := startGenericFlow(
		t, disabledAuth, "disabled", genericBaseURL+"/dashboard", "", genericBaseURL+"/error",
		map[string]any{"requestSignUp": true},
	)
	disabledCallback := finishGenericFlow(t, disabledAuth, "disabled", disabled, nil)
	disabledURL, _ := url.Parse(disabledCallback.Header.Get("Location"))
	if disabledURL.Query().Get("error") != "signup_disabled" || len(genericRecords(t, disabledAuth, "user")) != 0 {
		t.Fatalf("disableSignUp response=%q users=%#v", disabledCallback.Header.Get("Location"), genericRecords(t, disabledAuth, "user"))
	}
}

func TestGenericOAuthCrossOriginAPIErrorRedirect(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "hook-reject", "email": "hook-reject@test.com", "name": "Hook Reject",
	})
	auth := genericTestAuth(t, server.config("hook-reject"), func(options *singleauth.Options) {
		options.TrustedOrigins = []string{"https://frontend.example.com"}
		options.DatabaseHooks = singleauth.DatabaseHooks{
			"session": {Create: singleauth.DatabaseOperationHooks{
				Before: func(storage.Record, singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
					return singleauth.DatabaseHookResult{}, contract.NewAPIError(
						contract.StatusForbidden, "HOOK_REJECTED", "Session hook rejected this user",
					)
				},
			}},
		}
	})
	flow := startGenericFlow(
		t, auth, "hook-reject", "https://frontend.example.com/dashboard", "",
		"https://frontend.example.com/auth-error", nil,
	)
	callback := finishGenericFlow(t, auth, "hook-reject", flow, nil)
	location, _ := url.Parse(callback.Header.Get("Location"))
	if location.Scheme != "https" || location.Host != "frontend.example.com" ||
		location.Path != "/auth-error" || location.Query().Get("error") != "HOOK_REJECTED" ||
		location.Query().Get("error_description") != "Session hook rejected this user" {
		t.Fatalf("hook error redirect=%q", callback.Header.Get("Location"))
	}
}

func TestGenericOAuthLinkAccountUsesRootTokenLifecycleAndProfileUpdate(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "linked-provider-id", "email": "link@test.com", "name": "Provider Name",
		"picture": "https://example.test/provider.png", "email_verified": true,
	})
	config := server.config("link-provider")
	config.RedirectURI = "https://oauth.example.test/dedicated-callback"
	auth := genericTestAuth(t, config, func(options *singleauth.Options) {
		options.EmailAndPassword.Enabled = true
		options.Account.EncryptOAuthTokens = true
		options.Account.AccountLinking.UpdateUserInfoOnLink = true
	})
	jar := make(map[string]string)
	signUp := genericExchange(t, auth, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Local Name", "email": "link@test.com", "password": "password123",
	}, jar)
	if signUp.Status != http.StatusOK {
		t.Fatalf("sign up status=%d body=%s", signUp.Status, signUp.Body)
	}
	link := genericExchange(t, auth, http.MethodPost, "/oauth2/link", map[string]any{
		"providerId": "link-provider", "callbackURL": genericBaseURL + "/linked",
		"scopes": []string{"link-scope"},
	}, jar)
	if link.Status != http.StatusOK {
		t.Fatalf("link start status=%d body=%s", link.Status, link.Body)
	}
	linkBody := decodeGenericJSON(t, link.Body)
	authorizationURL, err := url.Parse(linkBody["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if authorizationURL.Query().Get("redirect_uri") != config.RedirectURI ||
		authorizationURL.Query().Get("scope") != "link-scope" {
		t.Fatalf("link authorization URL=%s", authorizationURL)
	}
	flow := genericStartedFlow{
		AuthorizationURL: authorizationURL, State: authorizationURL.Query().Get("state"), Jar: jar,
	}
	callback := finishGenericFlow(t, auth, "link-provider", flow, nil)
	if callback.Status != http.StatusFound || callback.Header.Get("Location") != genericBaseURL+"/linked" {
		t.Fatalf("link callback status=%d location=%q body=%s", callback.Status, callback.Header.Get("Location"), callback.Body)
	}
	accounts := genericRecords(t, auth, "account")
	if len(accounts) != 2 {
		t.Fatalf("linked accounts=%#v", accounts)
	}
	var linked storage.Record
	for _, account := range accounts {
		if account["providerId"] == "link-provider" {
			linked = account
		}
	}
	if linked == nil || linked["accountId"] != "linked-provider-id" ||
		linked["accessToken"] == "access-token" || linked["refreshToken"] == "refresh-token" {
		t.Fatalf("linked account=%#v", linked)
	}
	users := genericRecords(t, auth, "user")
	if len(users) != 1 || users[0]["name"] != "Provider Name" || users[0]["image"] != "https://example.test/provider.png" {
		t.Fatalf("provider profile was not applied: %#v", users)
	}
	request, body := server.lastTokenRequest()
	if request == nil || body.Get("redirect_uri") != config.RedirectURI {
		t.Fatalf("token redirect URI body=%#v", body)
	}

	// Re-linking the same provider account updates tokens instead of creating a duplicate.
	relink := genericExchange(t, auth, http.MethodPost, "/oauth2/link", map[string]any{
		"providerId": "link-provider", "callbackURL": genericBaseURL + "/linked-again",
	}, jar)
	relinkURL, _ := url.Parse(decodeGenericJSON(t, relink.Body)["url"].(string))
	relinkCallback := finishGenericFlow(t, auth, "link-provider", genericStartedFlow{
		AuthorizationURL: relinkURL, State: relinkURL.Query().Get("state"), Jar: jar,
	}, nil)
	if relinkCallback.Header.Get("Location") != genericBaseURL+"/linked-again" || len(genericRecords(t, auth, "account")) != 2 {
		t.Fatalf("relink location=%q accounts=%#v", relinkCallback.Header.Get("Location"), genericRecords(t, auth, "account"))
	}
}

func TestGenericOAuthVerificationEmailPreservesEncodedCallbackURL(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "unverified-oauth", "email": "unverified@test.com", "name": "Unverified",
		"email_verified": false,
	})
	var delivered singleauth.EmailVerificationMessage
	auth := genericTestAuth(t, server.config("unverified"), func(options *singleauth.Options) {
		options.EmailAndPassword.RequireEmailVerification = true
		options.EmailVerification.SendOnSignUp = storage.Bool(true)
		options.EmailVerification.SendVerificationEmail = func(_ context.Context, message singleauth.EmailVerificationMessage) error {
			delivered = message
			return nil
		}
	})
	callbackURL := genericBaseURL + "/dashboard?tab=security&source=oauth"
	flow := startGenericFlow(t, auth, "unverified", callbackURL, "", "", nil)
	callback := finishGenericFlow(t, auth, "unverified", flow, nil)
	if callback.Header.Get("Location") != callbackURL || delivered.URL == "" {
		t.Fatalf("callback=%q verification=%#v", callback.Header.Get("Location"), delivered)
	}
	verificationURL, err := url.Parse(delivered.URL)
	if err != nil {
		t.Fatal(err)
	}
	if verificationURL.Query().Get("callbackURL") != callbackURL {
		t.Fatalf("verification callbackURL=%q URL=%q", verificationURL.Query().Get("callbackURL"), delivered.URL)
	}
}

func TestGenericOAuthDeleteUserVerificationWithoutPassword(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "delete-oauth", "email": "delete@test.com", "name": "Delete OAuth", "email_verified": true,
	})
	var token string
	auth := genericTestAuth(t, server.config("delete-provider"), func(options *singleauth.Options) {
		options.User.DeleteUser.Enabled = true
		options.User.DeleteUser.SendDeleteAccountVerification = func(_ context.Context, message singleauth.DeleteAccountMessage) error {
			token = message.Token
			return nil
		}
	})
	flow := startGenericFlow(t, auth, "delete-provider", genericBaseURL+"/done", "", "", nil)
	if callback := finishGenericFlow(t, auth, "delete-provider", flow, nil); callback.Header.Get("Location") != genericBaseURL+"/done" {
		t.Fatalf("sign-in callback=%q", callback.Header.Get("Location"))
	}
	requestDelete := genericExchange(t, auth, http.MethodPost, "/delete-user", map[string]any{}, flow.Jar)
	if requestDelete.Status != http.StatusOK || token == "" {
		t.Fatalf("delete request status=%d body=%s token=%q", requestDelete.Status, requestDelete.Body, token)
	}
	confirm := genericExchange(t, auth, http.MethodPost, "/delete-user", map[string]any{"token": token}, flow.Jar)
	if confirm.Status != http.StatusOK || len(genericRecords(t, auth, "user")) != 0 || len(genericRecords(t, auth, "account")) != 0 {
		t.Fatalf("delete confirm status=%d body=%s users=%#v accounts=%#v", confirm.Status, confirm.Body, genericRecords(t, auth, "user"), genericRecords(t, auth, "account"))
	}
}

func TestGenericOAuthAccessTokenExpiryFallbackAndRefresh(t *testing.T) {
	baseTime := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name             string
		fallback         time.Duration
		advance          time.Duration
		wantRefreshCalls int
		wantExpiry       bool
	}{
		{name: "fallback expires and refreshes", fallback: time.Hour, advance: 2 * time.Hour, wantRefreshCalls: 1, wantExpiry: true},
		{name: "unset fallback stays non-expiring", advance: 24 * time.Hour, wantRefreshCalls: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newGenericOAuthServer(t, Profile{
				"sub": "expiry-" + test.name, "email": strings.ReplaceAll(test.name, " ", "-") + "@test.com", "name": "Expiry",
			})
			var clockLock sync.Mutex
			now := baseTime
			config := server.config("expiry")
			config.DiscoveryURL = ""
			config.AuthorizationURL = server.server.URL + "/authorize"
			config.TokenURL = server.server.URL + "/token"
			config.UserInfoURL = server.server.URL + "/userinfo"
			config.AccessTokenExpiresIn = test.fallback
			config.GetToken = func(context.Context, TokenRequest) (oauth2.Tokens, error) {
				return oauth2.Tokens{AccessToken: "custom-access", RefreshToken: "refresh-token"}, nil
			}
			auth := genericTestAuth(t, config, func(options *singleauth.Options) {
				options.Clock = func() time.Time {
					clockLock.Lock()
					defer clockLock.Unlock()
					return now
				}
			})
			flow := startGenericFlow(t, auth, "expiry", genericBaseURL+"/done", "", "", nil)
			if callback := finishGenericFlow(t, auth, "expiry", flow, nil); callback.Header.Get("Location") != genericBaseURL+"/done" {
				t.Fatalf("sign-in callback=%q", callback.Header.Get("Location"))
			}
			accounts := genericRecords(t, auth, "account")
			_, hasExpiry := accounts[0]["accessTokenExpiresAt"]
			if hasExpiry != test.wantExpiry {
				t.Fatalf("account expiry=%#v", accounts[0]["accessTokenExpiresAt"])
			}
			clockLock.Lock()
			now = now.Add(test.advance)
			clockLock.Unlock()
			access := genericExchange(t, auth, http.MethodPost, "/get-access-token", map[string]any{
				"providerId": "expiry", "accountId": genericRecordString(accounts[0], "accountId"),
			}, flow.Jar)
			if access.Status != http.StatusOK {
				t.Fatalf("get access status=%d body=%s", access.Status, access.Body)
			}
			server.mu.Lock()
			refreshCalls := server.refreshCalls
			server.mu.Unlock()
			if refreshCalls != test.wantRefreshCalls {
				t.Fatalf("refresh calls=%d want=%d", refreshCalls, test.wantRefreshCalls)
			}
		})
	}
}

func TestGenericOAuthGETBasedCustomTokenEndpoint(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"id": "get-token", "email": "get-token@test.com", "name": "GET Token",
	})
	config := server.config("get-token")
	config.GetToken = func(ctx context.Context, input TokenRequest) (oauth2.Tokens, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.server.URL+"/token-get?code="+url.QueryEscape(input.Code), nil)
		if err != nil {
			return oauth2.Tokens{}, err
		}
		response, err := server.server.Client().Do(request)
		if err != nil {
			return oauth2.Tokens{}, err
		}
		defer response.Body.Close()
		var raw map[string]any
		if err := json.NewDecoder(response.Body).Decode(&raw); err != nil {
			return oauth2.Tokens{}, err
		}
		return oauth2.Tokens{AccessToken: raw["access_token"].(string)}, nil
	}
	auth := genericTestAuth(t, config, nil)
	flow := startGenericFlow(t, auth, "get-token", genericBaseURL+"/done", "", "", nil)
	callback := finishGenericFlow(t, auth, "get-token", flow, nil)
	request, _ := server.lastTokenRequest()
	if callback.Header.Get("Location") != genericBaseURL+"/done" || request == nil || request.Method != http.MethodGet {
		t.Fatalf("callback=%q token request=%#v", callback.Header.Get("Location"), request)
	}
}
