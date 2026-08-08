package onetap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestImplicitLinkingGateMatchesReference(t *testing.T) {
	t.Run("rejects implicit linking when the local user is unverified", func(t *testing.T) {
		claims := defaultClaims()
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(claims, nil),
		}, singleauth.AccountLinkingOptions{})
		seedUser(t, auth, "unverified-user", claims["email"].(string), false)

		response, _ := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
		}
		assertAccountCount(t, auth, "google", claims["sub"].(string), 0)
	})

	t.Run("allows implicit linking once the local user is verified", func(t *testing.T) {
		claims := defaultClaims()
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(claims, nil),
		}, singleauth.AccountLinkingOptions{})
		seedUser(t, auth, "verified-user", claims["email"].(string), true)

		response, body := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		assertSuccessfulUser(t, response, body, "verified-user")
		assertAccountCount(t, auth, "google", claims["sub"].(string), 1)
	})

	t.Run("links when requireLocalEmailVerified is opted out", func(t *testing.T) {
		claims := defaultClaims()
		requireVerified := false
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(claims, nil),
		}, singleauth.AccountLinkingOptions{RequireLocalEmailVerified: &requireVerified})
		seedUser(t, auth, "opted-out-user", claims["email"].(string), false)

		response, body := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		assertSuccessfulUser(t, response, body, "opted-out-user")
		assertAccountCount(t, auth, "google", claims["sub"].(string), 1)
	})

	t.Run("links Google when another provider has the same account ID", func(t *testing.T) {
		claims := defaultClaims()
		claims["email"] = "one-tap-provider-collision@example.com"
		claims["sub"] = "shared-one-tap-provider-account-id"
		requireVerified := false
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(claims, nil),
		}, singleauth.AccountLinkingOptions{RequireLocalEmailVerified: &requireVerified})
		seedUser(t, auth, "other-provider-user", "one-tap-other-provider@example.com", false)
		seedAccount(t, auth, "github-collision", "other-provider-user", "github", claims["sub"].(string))
		seedUser(t, auth, "local-collision-user", claims["email"].(string), false)

		response, body := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		assertSuccessfulUser(t, response, body, "local-collision-user")
		assertAccountCount(t, auth, "google", claims["sub"].(string), 1)
	})

	t.Run("does not duplicate the Google account for a returning user", func(t *testing.T) {
		claims := defaultClaims()
		claims["email"] = "one-tap-returning-user@example.com"
		claims["sub"] = "returning-user-google-sub"
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(claims, nil),
		}, singleauth.AccountLinkingOptions{})

		first, firstBody := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		assertSuccessfulUser(t, first, firstBody, "")
		second, secondBody := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		assertSuccessfulUser(t, second, secondBody, userID(firstBody))
		assertAccountCount(t, auth, "google", claims["sub"].(string), 1)
	})

	t.Run("resolves identity by Google sub before token email", func(t *testing.T) {
		claims := defaultClaims()
		claims["email"] = "one-tap-email-collision-b@example.com"
		claims["sub"] = "one-tap-sub-owned-by-user-a"
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(claims, nil),
		}, singleauth.AccountLinkingOptions{})
		seedUser(t, auth, "sub-owner-a", "one-tap-sub-owner-a@example.com", false)
		seedAccount(t, auth, "google-owner", "sub-owner-a", "google", claims["sub"].(string))
		seedUser(t, auth, "email-match-b", claims["email"].(string), false)

		response, body := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		assertSuccessfulUser(t, response, body, "sub-owner-a")
		if got := userID(body); got == "email-match-b" {
			t.Fatal("One Tap authenticated the email-matched user instead of the Google sub owner")
		}
	})

	t.Run("honors disableImplicitLinking for a verified local user", func(t *testing.T) {
		claims := defaultClaims()
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(claims, nil),
		}, singleauth.AccountLinkingOptions{DisableImplicitLinking: true})
		seedUser(t, auth, "linking-disabled-user", claims["email"].(string), true)

		response, _ := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
		}
		assertAccountCount(t, auth, "google", claims["sub"].(string), 0)
	})
}

func TestCallbackURLOriginValidationMatchesReference(t *testing.T) {
	claims := defaultClaims()
	var verificationCalls atomic.Int64
	verify := func(_ context.Context, _ VerifyIDTokenInput) (map[string]any, error) {
		verificationCalls.Add(1)
		return cloneClaims(claims), nil
	}

	t.Run("rejects an untrusted callbackURL", func(t *testing.T) {
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: verify,
		}, singleauth.AccountLinkingOptions{})
		response, _ := callOneTap(t, auth, map[string]any{
			"idToken": "stub-id-token", "callbackURL": "https://untrusted.example/callback",
		})
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
		}
		if got := verificationCalls.Load(); got != 0 {
			t.Fatalf("verification ran before origin rejection: %d calls", got)
		}
	})

	t.Run("accepts a relative callbackURL", func(t *testing.T) {
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: verify,
		}, singleauth.AccountLinkingOptions{})
		response, body := callOneTap(t, auth, map[string]any{
			"idToken": "stub-id-token", "callbackURL": "/dashboard",
		})
		assertSuccessfulUser(t, response, body, "")
	})
}

func TestAudienceEnforcementMatchesReference(t *testing.T) {
	t.Run("rejects a missing Google client ID before verification", func(t *testing.T) {
		var calls atomic.Int64
		auth := newTestAuth(t, nil, Options{VerifyIDToken: func(
			context.Context, VerifyIDTokenInput,
		) (map[string]any, error) {
			calls.Add(1)
			return defaultClaims(), nil
		}}, singleauth.AccountLinkingOptions{})
		response, _ := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		if response.Code != http.StatusBadRequest ||
			!strings.Contains(response.Body.String(), "Google client ID is required") {
			t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
		}
		if calls.Load() != 0 {
			t.Fatal("token verifier ran without a configured audience")
		}
	})

	t.Run("accepts the plugin clientId without a Google provider", func(t *testing.T) {
		claims := defaultClaims()
		var seenAudience any
		auth := newTestAuth(t, nil, Options{
			ClientID:      "explicit-one-tap-client",
			VerifyIDToken: claimsVerifier(claims, &seenAudience),
		}, singleauth.AccountLinkingOptions{})
		response, body := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
		assertSuccessfulUser(t, response, body, "")
		if seenAudience != "explicit-one-tap-client" {
			t.Fatalf("verification audience = %#v", seenAudience)
		}
	})
}

func TestHostedDomainValidationMatchesReference(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		claim      any
		wantStatus int
	}{
		{"rejects a mismatched hd", "company.com", "other.com", http.StatusBadRequest},
		{"rejects a missing configured hd", "company.com", nil, http.StatusBadRequest},
		{"accepts an exact hd", "company.com", "company.com", http.StatusOK},
		{"accepts any present hd for wildcard", "*", "company.com", http.StatusOK},
		{"rejects a missing hd for wildcard", "*", nil, http.StatusBadRequest},
		{"ignores token hd without configuration", "", "anywhere.com", http.StatusOK},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := defaultClaims()
			claims["email"] = fmt.Sprintf("hd-%d@example.com", index)
			claims["sub"] = fmt.Sprintf("hd-sub-%d", index)
			if test.claim != nil {
				claims["hd"] = test.claim
			}
			provider := googleProvider(t, providers.Options{HostedDomain: test.configured})
			auth := newTestAuth(t, provider, Options{
				VerifyIDToken: claimsVerifier(claims, nil),
			}, singleauth.AccountLinkingOptions{})
			response, body := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantStatus == http.StatusOK && token(body) == "" {
				t.Fatalf("successful body has no token: %#v", body)
			}
		})
	}
}

func TestDisableSignupMatchesReference(t *testing.T) {
	for _, test := range []struct {
		name          string
		pluginDisable bool
	}{
		{"rejects provider-disabled sign-up without creating a user", false},
		{"provider disableSignUp wins over plugin false", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := defaultClaims()
			claims["email"] = strings.ReplaceAll(test.name, " ", "-") + "@example.com"
			claims["sub"] = strings.ReplaceAll(test.name, " ", "-")
			provider := googleProvider(t, providers.Options{DisableSignUp: true})
			auth := newTestAuth(t, provider, Options{
				DisableSignup: test.pluginDisable,
				VerifyIDToken: claimsVerifier(claims, nil),
			}, singleauth.AccountLinkingOptions{})
			response, _ := callOneTap(t, auth, map[string]any{"idToken": "stub-id-token"})
			if response.Code != http.StatusUnauthorized ||
				!strings.Contains(response.Body.String(), "signup disabled") {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			users := findRecords(t, auth, "user", []storage.Where{{Field: "email", Value: claims["email"]}})
			if len(users) != 0 {
				t.Fatalf("disabled sign-up created users: %#v", users)
			}
		})
	}
}

func TestOneTapConcurrentCallbacksAreIsolated(t *testing.T) {
	verify := func(_ context.Context, input VerifyIDTokenInput) (map[string]any, error) {
		parts := strings.SplitN(input.Token, "|", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid test token")
		}
		return map[string]any{
			"sub": parts[0], "email": parts[1], "email_verified": true, "name": parts[0],
		}, nil
	}
	auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
		VerifyIDToken: verify,
	}, singleauth.AccountLinkingOptions{})

	const callbacks = 24
	type result struct {
		status int
		body   string
	}
	results := make(chan result, callbacks)
	var group sync.WaitGroup
	for index := range callbacks {
		group.Add(1)
		go func() {
			defer group.Done()
			token := fmt.Sprintf("sub-%d|user-%d@example.com", index, index)
			body, _ := json.Marshal(map[string]any{"idToken": token})
			request := httptest.NewRequest(
				http.MethodPost, "http://localhost:3000/api/auth/one-tap/callback", bytes.NewReader(body),
			)
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, request)
			results <- result{status: recorder.Code, body: recorder.Body.String()}
		}()
	}
	group.Wait()
	close(results)
	for result := range results {
		if result.status != http.StatusOK {
			t.Fatalf("concurrent status = %d body=%s", result.status, result.body)
		}
	}
	if users := findRecords(t, auth, "user", nil); len(users) != callbacks {
		t.Fatalf("user count = %d, want %d", len(users), callbacks)
	}
	if accounts := findRecords(t, auth, "account", []storage.Where{{Field: "providerId", Value: "google"}}); len(accounts) != callbacks {
		t.Fatalf("Google account count = %d, want %d", len(accounts), callbacks)
	}
}

func newTestAuth(
	t *testing.T,
	google *providers.Provider,
	pluginOptions Options,
	accountLinking singleauth.AccountLinkingOptions,
) *singleauth.Auth {
	t.Helper()
	socialProviders := map[string]*providers.Provider{}
	if google != nil {
		socialProviders["google"] = google
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: testSecret,
		SocialProviders: socialProviders,
		Account:         singleauth.AccountOptions{AccountLinking: accountLinking},
		PluginFactories: []singleauth.PluginFactory{NewFactory(pluginOptions)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func googleProvider(t *testing.T, overrides providers.Options) *providers.Provider {
	t.Helper()
	overrides.ClientID = "test-client"
	overrides.ClientSecret = "test-secret"
	provider, err := providers.Google(overrides)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func defaultClaims() map[string]any {
	return map[string]any{
		"email": "one-tap-user@example.com", "email_verified": true,
		"name": "One Tap User", "picture": "https://example.com/photo.jpg",
		"sub": "google_oauth_sub_one_tap",
	}
}

func cloneClaims(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func claimsVerifier(claims map[string]any, seenAudience *any) VerifyIDTokenFunc {
	return func(_ context.Context, input VerifyIDTokenInput) (map[string]any, error) {
		if seenAudience != nil {
			*seenAudience = input.Audience
		}
		return cloneClaims(claims), nil
	}
}

func callOneTap(
	t *testing.T,
	auth *singleauth.Auth,
	body map[string]any,
) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "http://localhost:3000/api/auth/one-tap/callback", bytes.NewReader(encoded),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	decoded := map[string]any{}
	if recorder.Body.Len() != 0 {
		_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	}
	return recorder, decoded
}

func seedUser(t *testing.T, auth *singleauth.Auth, id, email string, verified bool) storage.Record {
	t.Helper()
	now := time.Now().UTC()
	user, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "user", ForceAllowID: true,
		Data: storage.Record{
			"id": id, "name": id, "email": email, "emailVerified": verified,
			"createdAt": now, "updatedAt": now,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func seedAccount(t *testing.T, auth *singleauth.Auth, id, userID, providerID, accountID string) storage.Record {
	t.Helper()
	now := time.Now().UTC()
	account, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "account", ForceAllowID: true,
		Data: storage.Record{
			"id": id, "userId": userID, "providerId": providerID, "accountId": accountID,
			"createdAt": now, "updatedAt": now,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func findRecords(t *testing.T, auth *singleauth.Auth, model string, where []storage.Where) []storage.Record {
	t.Helper()
	records, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: model, Where: where})
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func assertAccountCount(t *testing.T, auth *singleauth.Auth, providerID, accountID string, want int) {
	t.Helper()
	records := findRecords(t, auth, "account", []storage.Where{
		{Field: "providerId", Value: providerID}, {Field: "accountId", Value: accountID},
	})
	if len(records) != want {
		t.Fatalf("account count = %d, want %d: %#v", len(records), want, records)
	}
}

func assertSuccessfulUser(
	t *testing.T,
	response *httptest.ResponseRecorder,
	body map[string]any,
	wantUserID string,
) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if token(body) == "" {
		t.Fatalf("response token is empty: %#v", body)
	}
	if wantUserID != "" && userID(body) != wantUserID {
		t.Fatalf("response user id = %q, want %q: %#v", userID(body), wantUserID, body)
	}
}

func token(body map[string]any) string {
	value, _ := body["token"].(string)
	return value
}

func userID(body map[string]any) string {
	user, _ := body["user"].(map[string]any)
	value, _ := user["id"].(string)
	return value
}
