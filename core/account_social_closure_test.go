package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"
	_ "modernc.org/sqlite"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	authlogger "github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type accountWireResult struct {
	status int
	header http.Header
	value  any
}

type accountWireExchange func(
	*testing.T,
	string,
	string,
	string,
	any,
) accountWireResult

type accountWireTransport struct {
	name string
	bind func(*testing.T, *Auth) accountWireExchange
}

func TestAccountLifecycleAcrossDirectNetHTTPFastHTTPAndFiber(t *testing.T) {
	for _, transport := range accountWireTransports() {
		transport := transport
		t.Run(transport.name, func(t *testing.T) {
			now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
			var refreshCalls atomic.Int64
			email := "account-wire-" + transport.name + "@example.com"
			provider := accountTestProvider(t, func(tokens oauth2.Tokens) oauth2.UserInfo {
				if tokens.IDToken == "link-id-token" {
					return oauth2.UserInfo{
						ID: "linked-provider-user", Name: "Linked User", Email: &email,
						EmailVerified: true,
					}
				}
				return oauth2.UserInfo{
					ID: "existing-provider-user", Name: "Existing User", Email: &email,
					EmailVerified: true,
				}
			}, func(_ string) oauth2.Tokens {
				call := refreshCalls.Add(1)
				expires := now.Add(time.Duration(call) * time.Hour)
				return oauth2.Tokens{
					AccessToken: "rotated-access", RefreshToken: "rotated-refresh",
					AccessTokenExpiresAt: &expires, Scopes: []string{"openid", "profile"},
					IDToken: "rotated-id-token",
				}
			})
			auth := MustNew(Options{
				BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
				Clock:            func() time.Time { return now },
				EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
				Account: AccountOptions{
					EncryptOAuthTokens: true,
					AccountLinking:     AccountLinkingOptions{AllowDifferentEmails: true},
				},
				SocialProviders: map[string]*providers.Provider{"google": provider},
			})
			cookie, _, session := createSessionTestUser(t, auth, email)
			userID := objectString(t, objectValue(t, session, "user"), "id")
			storedAccess, err := auth.storeOAuthToken("existing-access")
			if err != nil {
				t.Fatal(err)
			}
			storedRefresh, err := auth.storeOAuthToken("existing-refresh")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
				Model: "account",
				Data: storage.Record{
					"id": "existing-social-" + transport.name, "userId": userID,
					"providerId": "google", "accountId": "existing-provider-user",
					"accessToken": storedAccess, "refreshToken": storedRefresh,
					"idToken": "existing-id-token", "scope": "openid,email",
					"accessTokenExpiresAt": now.Add(time.Hour),
					"createdAt":            now, "updatedAt": now,
				},
				ForceAllowID: true,
			}); err != nil {
				t.Fatal(err)
			}

			exchange := transport.bind(t, auth)
			listed := exchange(t, http.MethodGet, "/api/auth/list-accounts", cookie, nil)
			accounts, ok := listed.value.([]any)
			if listed.status != http.StatusOK || !ok || len(accounts) != 2 {
				t.Fatalf("list status=%d value=%#v", listed.status, listed.value)
			}
			for _, raw := range accounts {
				account := raw.(map[string]any)
				for _, secret := range []string{"accessToken", "refreshToken", "idToken", "password"} {
					if _, leaked := account[secret]; leaked {
						t.Fatalf("list leaked %s: %#v", secret, account)
					}
				}
			}

			access := exchange(t, http.MethodPost, "/api/auth/get-access-token", cookie, map[string]any{
				"providerId": "google", "accountId": "existing-provider-user",
			})
			if access.status != http.StatusOK || accountObjectString(access.value, "accessToken") != "existing-access" {
				t.Fatalf("access status=%d value=%#v", access.status, access.value)
			}

			info := exchange(t, http.MethodGet,
				"/api/auth/account-info?providerId=google&accountId=existing-provider-user", cookie, nil,
			)
			if info.status != http.StatusOK || accountObjectString(accountObject(info.value, "user"), "id") != "existing-provider-user" {
				t.Fatalf("info status=%d value=%#v", info.status, info.value)
			}

			refreshed := exchange(t, http.MethodPost, "/api/auth/refresh-token", cookie, map[string]any{
				"providerId": "google", "accountId": "existing-provider-user",
			})
			if refreshed.status != http.StatusOK || accountObjectString(refreshed.value, "accessToken") != "rotated-access" ||
				accountObjectString(refreshed.value, "refreshToken") != "rotated-refresh" {
				t.Fatalf("refresh status=%d value=%#v", refreshed.status, refreshed.value)
			}

			linked := exchange(t, http.MethodPost, "/api/auth/link-social", cookie, map[string]any{
				"provider": "google",
				"idToken": map[string]any{
					"token": "link-id-token", "accessToken": "link-access",
					"refreshToken": "link-refresh", "scopes": []string{"drive.read"},
				},
			})
			if linked.status != http.StatusOK || accountObject(linked.value)["status"] != true {
				t.Fatalf("link status=%d value=%#v", linked.status, linked.value)
			}
			linkedRecord, err := auth.findAccountByProvider(t.Context(), "google", "linked-provider-user")
			if err != nil || linkedRecord == nil || mustRecordString(linkedRecord, "scope") != "drive.read" {
				t.Fatalf("linked record=%#v err=%v", linkedRecord, err)
			}
			if mustRecordString(linkedRecord, "accessToken") == "link-access" ||
				mustRecordString(linkedRecord, "refreshToken") == "link-refresh" {
				t.Fatalf("linked OAuth secrets were not encrypted: %#v", linkedRecord)
			}

			unlinked := exchange(t, http.MethodPost, "/api/auth/unlink-account", cookie, map[string]any{
				"providerId": "google", "accountId": "linked-provider-user",
			})
			if unlinked.status != http.StatusOK || accountObject(unlinked.value)["status"] != true {
				t.Fatalf("unlink status=%d value=%#v", unlinked.status, unlinked.value)
			}
			if refreshCalls.Load() != 1 {
				t.Fatalf("refresh calls=%d", refreshCalls.Load())
			}
		})
	}
}

func TestAccountLifecycleWithSQLiteStorage(t *testing.T) {
	sequence := time.Now().UnixNano()
	database, err := sql.Open("sqlite", fmt.Sprintf("file:account_closure_%d?mode=memory&cache=shared", sequence))
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close SQLite: %v", err)
		}
	})
	email := "sqlite-account@example.com"
	provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
		return oauth2.UserInfo{ID: "sqlite-provider-user", Name: "SQLite", Email: &email, EmailVerified: true}
	}, nil)
	auth, err := NewWithSQLiteDatabase(Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		SocialProviders:  map[string]*providers.Provider{"google": provider},
	}, database)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := auth.Context()
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.RunMigrationsContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	cookie, _, _ := createSessionTestUser(t, auth, email)
	result := accountWireDirect(t, auth)(t, http.MethodPost, "/api/auth/link-social", cookie, map[string]any{
		"provider": "google", "idToken": map[string]any{"token": "sqlite-id", "accessToken": "sqlite-access"},
	})
	if result.status != http.StatusOK {
		t.Fatalf("SQLite link status=%d value=%#v", result.status, result.value)
	}
	listed := accountWireDirect(t, auth)(t, http.MethodGet, "/api/auth/list-accounts", cookie, nil)
	if accounts, ok := listed.value.([]any); listed.status != http.StatusOK || !ok || len(accounts) != 2 {
		t.Fatalf("SQLite list status=%d value=%#v", listed.status, listed.value)
	}
	access := accountWireDirect(t, auth)(t, http.MethodPost, "/api/auth/get-access-token", cookie, map[string]any{
		"providerId": "google", "accountId": "sqlite-provider-user",
	})
	if access.status != http.StatusOK || accountObjectString(access.value, "accessToken") != "sqlite-access" {
		t.Fatalf("SQLite access status=%d value=%#v", access.status, access.value)
	}
}

func TestSocialAccountTrustOwnershipAndImplicitLinkingMatrix(t *testing.T) {
	type explicitCase struct {
		name                string
		remoteVerified      bool
		trusted             bool
		allowDifferentEmail bool
		linkingEnabled      *bool
		remoteEmail         string
		wantStatus          int
		wantCode            string
	}
	for _, test := range []explicitCase{
		{name: "unverified untrusted", wantStatus: http.StatusUnauthorized, wantCode: "LINKING_NOT_ALLOWED"},
		{name: "unverified trusted", trusted: true, wantStatus: http.StatusOK},
		{name: "verified untrusted", remoteVerified: true, wantStatus: http.StatusOK},
		{name: "different email rejected", remoteVerified: true, remoteEmail: "other@example.com", wantStatus: http.StatusUnauthorized, wantCode: "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED"},
		{name: "different email allowed", remoteVerified: true, remoteEmail: "other@example.com", allowDifferentEmail: true, wantStatus: http.StatusOK},
		{name: "linking disabled", remoteVerified: true, linkingEnabled: storage.Bool(false), wantStatus: http.StatusUnauthorized, wantCode: "LINKING_NOT_ALLOWED"},
	} {
		test := test
		t.Run("explicit/"+test.name, func(t *testing.T) {
			localEmail := "explicit-" + accountSafeName(test.name) + "@example.com"
			remoteEmail := test.remoteEmail
			if remoteEmail == "" {
				remoteEmail = localEmail
			}
			provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
				return oauth2.UserInfo{
					ID: "explicit-provider-user", Name: "Remote", Email: &remoteEmail,
					EmailVerified: test.remoteVerified,
				}
			}, nil)
			linking := AccountLinkingOptions{
				Enabled: test.linkingEnabled, AllowDifferentEmails: test.allowDifferentEmail,
			}
			if test.trusted {
				linking.TrustedProviders = []string{"google"}
			}
			auth := MustNew(Options{
				BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
				EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
				Account:          AccountOptions{AccountLinking: linking},
				SocialProviders:  map[string]*providers.Provider{"google": provider},
			})
			cookie, _, _ := createSessionTestUser(t, auth, localEmail)
			result := sessionAccountRequest(t, auth, http.MethodPost, "/link-social", cookie, map[string]any{
				"provider": "google", "idToken": map[string]any{"token": "valid"},
			})
			if result.status != test.wantStatus {
				t.Fatalf("status=%d value=%#v want=%d", result.status, result.value, test.wantStatus)
			}
			if test.wantCode != "" && accountObjectString(result.value, "code") != test.wantCode {
				t.Fatalf("code=%q value=%#v", accountObjectString(result.value, "code"), result.value)
			}
			account, err := auth.findAccountByProvider(t.Context(), "google", "explicit-provider-user")
			if err != nil {
				t.Fatal(err)
			}
			if (test.wantStatus == http.StatusOK) != (account != nil) {
				t.Fatalf("linked account=%#v status=%d", account, result.status)
			}
		})
	}

	type implicitCase struct {
		name                  string
		newUser               bool
		localVerified         bool
		remoteVerified        bool
		trusted               bool
		disableImplicit       bool
		requireLocalVerified  *bool
		wantStatus            int
		wantOAuthErrorMessage string
	}
	for _, test := range []implicitCase{
		{name: "local unverified default", remoteVerified: true, wantStatus: http.StatusUnauthorized, wantOAuthErrorMessage: "account not linked"},
		{name: "local verification opt out", remoteVerified: true, requireLocalVerified: storage.Bool(false), wantStatus: http.StatusOK},
		{name: "trusted provider and verified local", localVerified: true, trusted: true, wantStatus: http.StatusOK},
		{name: "implicit linking disabled", localVerified: true, remoteVerified: true, disableImplicit: true, wantStatus: http.StatusUnauthorized, wantOAuthErrorMessage: "account not linked"},
		{name: "new user still provisions", newUser: true, remoteVerified: true, disableImplicit: true, wantStatus: http.StatusOK},
	} {
		test := test
		t.Run("implicit/"+test.name, func(t *testing.T) {
			email := "implicit-" + accountSafeName(test.name) + "@example.com"
			provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
				return oauth2.UserInfo{
					ID: "implicit-provider-user", Name: "Remote", Email: &email,
					EmailVerified: test.remoteVerified,
				}
			}, nil)
			linking := AccountLinkingOptions{
				DisableImplicitLinking:    test.disableImplicit,
				RequireLocalEmailVerified: test.requireLocalVerified,
			}
			if test.trusted {
				linking.TrustedProviders = []string{"google"}
			}
			auth := MustNew(Options{
				BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
				EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
				Account:          AccountOptions{AccountLinking: linking},
				SocialProviders:  map[string]*providers.Provider{"google": provider},
			})
			if !test.newUser {
				_, _, session := createSessionTestUser(t, auth, email)
				if test.localVerified {
					userID := objectString(t, objectValue(t, session, "user"), "id")
					if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
						Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
						Update: storage.Record{"emailVerified": true},
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
			result := sessionAccountRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
				"provider": "google", "idToken": map[string]any{"token": "valid", "accessToken": "access"},
			})
			if result.status != test.wantStatus {
				t.Fatalf("status=%d value=%#v want=%d", result.status, result.value, test.wantStatus)
			}
			if test.wantOAuthErrorMessage != "" && accountObjectString(result.value, "message") != test.wantOAuthErrorMessage {
				t.Fatalf("error=%#v", result.value)
			}
		})
	}

	t.Run("provider account remains owned by its first user", func(t *testing.T) {
		remoteEmail := "first-owner@example.com"
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "owned-provider-account", Name: "Owned", Email: &remoteEmail, EmailVerified: true}
		}, nil)
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			Account:          AccountOptions{AccountLinking: AccountLinkingOptions{AllowDifferentEmails: true}},
			SocialProviders:  map[string]*providers.Provider{"google": provider},
		})
		firstCookie, _, firstSession := createSessionTestUser(t, auth, "first-owner@example.com")
		secondCookie, _, _ := createSessionTestUser(t, auth, "second-owner@example.com")
		body := map[string]any{"provider": "google", "idToken": map[string]any{"token": "valid"}}
		first := sessionAccountRequest(t, auth, http.MethodPost, "/link-social", firstCookie, body)
		second := sessionAccountRequest(t, auth, http.MethodPost, "/link-social", secondCookie, body)
		if first.status != http.StatusOK || second.status != 422 ||
			accountObjectString(second.value, "code") != string(ErrorSocialAccountAlreadyLinked) {
			t.Fatalf("first=%d %#v second=%d %#v", first.status, first.value, second.status, second.value)
		}
		account, err := auth.findAccountByProvider(t.Context(), "google", "owned-provider-account")
		if err != nil || account == nil || mustRecordString(account, "userId") != objectString(t, objectValue(t, firstSession, "user"), "id") {
			t.Fatalf("owned account=%#v err=%v", account, err)
		}
	})
}

func TestAccountMalformedAuthorizationAndProviderBoundaryCases(t *testing.T) {
	email := "boundary@example.com"
	provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
		return oauth2.UserInfo{ID: "boundary-provider", Name: "Boundary", Email: &email, EmailVerified: true}
	}, nil)
	auth := MustNew(Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		SocialProviders:  map[string]*providers.Provider{"google": provider},
	})
	cookie, sessionToken, session := createSessionTestUser(t, auth, email)
	userID := objectString(t, objectValue(t, session, "user"), "id")
	now := time.Now().UTC()
	if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "account", Data: storage.Record{
			"id": "boundary-account", "providerId": "google", "accountId": "boundary-provider",
			"userId": userID, "accessToken": "access", "createdAt": now, "updatedAt": now,
		}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}

	for _, request := range []struct {
		name   string
		method string
		path   string
		cookie string
		body   map[string]any
		status int
		code   string
	}{
		{name: "list requires session", method: http.MethodGet, path: "/list-accounts", status: http.StatusUnauthorized, code: "UNAUTHORIZED"},
		{name: "HTTP userId cannot bypass session", method: http.MethodPost, path: "/get-access-token", body: map[string]any{"providerId": "google", "userId": userID}, status: http.StatusUnauthorized, code: "UNAUTHORIZED"},
		{name: "null account id", method: http.MethodPost, path: "/get-access-token", cookie: cookie, body: map[string]any{"providerId": "google", "accountId": nil}, status: http.StatusBadRequest, code: string(ErrorValidation)},
		{name: "numeric user id", method: http.MethodPost, path: "/refresh-token", cookie: cookie, body: map[string]any{"providerId": "google", "userId": 42}, status: http.StatusBadRequest, code: string(ErrorValidation)},
		{name: "null id token", method: http.MethodPost, path: "/link-social", cookie: cookie, body: map[string]any{"provider": "google", "idToken": nil}, status: http.StatusBadRequest, code: string(ErrorValidation)},
		{name: "malformed id token scopes", method: http.MethodPost, path: "/link-social", cookie: cookie, body: map[string]any{"provider": "google", "idToken": map[string]any{"token": "valid", "scopes": []any{"ok", 1}}}, status: http.StatusBadRequest, code: string(ErrorValidation)},
		{name: "malformed sign-in token expiry", method: http.MethodPost, path: "/sign-in/social", body: map[string]any{"provider": "google", "idToken": map[string]any{"token": "valid", "expiresAt": "soon"}}, status: http.StatusBadRequest, code: string(ErrorValidation)},
		{name: "malformed authorization user", method: http.MethodPost, path: "/sign-in/social", body: map[string]any{"provider": "google", "idToken": map[string]any{"token": "valid", "user": map[string]any{"name": map[string]any{"firstName": 42}}}}, status: http.StatusBadRequest, code: string(ErrorValidation)},
		{name: "unknown token provider", method: http.MethodPost, path: "/get-access-token", cookie: cookie, body: map[string]any{"providerId": "unknown"}, status: http.StatusBadRequest, code: "PROVIDER_NOT_SUPPORTED"},
	} {
		request := request
		t.Run(request.name, func(t *testing.T) {
			result := sessionAccountRequest(t, auth, request.method, request.path, request.cookie, request.body)
			if result.status != request.status || accountObjectString(result.value, "code") != request.code {
				t.Fatalf("status=%d value=%#v want status=%d code=%s", result.status, result.value, request.status, request.code)
			}
		})
	}

	direct, err := auth.API().GetAccessToken(t.Context(), AccountTokenInput{
		ProviderID: "google", AccountID: "boundary-provider", UserID: userID,
	})
	if err != nil || direct.AccessToken != "access" {
		t.Fatalf("server-side direct access=%#v err=%v", direct, err)
	}
	if err := auth.Adapter().Delete(t.Context(), storage.DeleteParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: sessionToken}},
	}); err != nil {
		t.Fatal(err)
	}
	revoked := sessionAccountRequest(t, auth, http.MethodPost, "/get-access-token", cookie, map[string]any{
		"providerId": "google", "accountId": "boundary-provider",
	})
	if revoked.status != http.StatusUnauthorized || accountObjectString(revoked.value, "code") != "UNAUTHORIZED" {
		t.Fatalf("revoked session status=%d value=%#v", revoked.status, revoked.value)
	}

	missingIDProvider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
		return oauth2.UserInfo{Name: "Missing ID", Email: &email, EmailVerified: true}
	}, nil)
	missingIDAuth := MustNew(Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		SocialProviders:  map[string]*providers.Provider{"google": missingIDProvider},
	})
	missingCookie, _, _ := createSessionTestUser(t, missingIDAuth, email)
	missing := sessionAccountRequest(t, missingIDAuth, http.MethodPost, "/link-social", missingCookie, map[string]any{
		"provider": "google", "idToken": map[string]any{"token": "valid"},
	})
	if missing.status != http.StatusUnauthorized || accountObjectString(missing.value, "code") != string(ErrorFailedToGetUserInfo) {
		t.Fatalf("missing provider ID status=%d value=%#v", missing.status, missing.value)
	}
	accounts, err := missingIDAuth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "providerId", Value: "google"}},
	})
	if err != nil || len(accounts) != 0 {
		t.Fatalf("missing-ID accounts=%#v err=%v", accounts, err)
	}
}

func TestAccountConcurrencyPreservesLastMethodOwnershipAndSingleRefresh(t *testing.T) {
	t.Run("concurrent unlink preserves one method", func(t *testing.T) {
		base := memory.MustNew()
		adapter := &slowAccountAdapter{Adapter: base, findDelay: 15 * time.Millisecond}
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			Database: adapter, EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		})
		cookie, _, session := createSessionTestUser(t, auth, "unlink-race@example.com")
		userID := objectString(t, objectValue(t, session, "user"), "id")
		now := time.Now().UTC()
		if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
			Model: "account", Data: storage.Record{
				"id": "unlink-race-social", "providerId": "google", "accountId": "race-social",
				"userId": userID, "createdAt": now, "updatedAt": now,
			}, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
		bodies := []map[string]any{{"providerId": "credential"}, {"providerId": "google"}}
		results := make([]accountWireResult, len(bodies))
		var wait sync.WaitGroup
		wait.Add(len(bodies))
		for index := range bodies {
			index := index
			go func() {
				defer wait.Done()
				results[index] = concurrentAccountRequest(auth, http.MethodPost, "/unlink-account", cookie, bodies[index])
			}()
		}
		wait.Wait()
		successes := 0
		for _, result := range results {
			if result.status == http.StatusOK {
				successes++
			} else if result.status != http.StatusBadRequest || accountObjectString(result.value, "code") != string(ErrorFailedToUnlinkLastAccount) {
				t.Fatalf("unexpected unlink result=%#v", result)
			}
		}
		accounts, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
			Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
		})
		if err != nil || successes != 1 || len(accounts) != 1 {
			t.Fatalf("successes=%d accounts=%#v err=%v results=%#v", successes, accounts, err, results)
		}
	})

	t.Run("same provider account links once", func(t *testing.T) {
		base := memory.MustNew()
		adapter := &slowAccountAdapter{Adapter: base, findDelay: 15 * time.Millisecond}
		email := "link-race@example.com"
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "link-race-provider", Name: "Race", Email: &email, EmailVerified: true}
		}, nil)
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			Database: adapter, EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			SocialProviders: map[string]*providers.Provider{"google": provider},
		})
		cookie, _, _ := createSessionTestUser(t, auth, email)
		body := map[string]any{"provider": "google", "idToken": map[string]any{"token": "valid"}}
		results := make([]accountWireResult, 2)
		var wait sync.WaitGroup
		wait.Add(2)
		for index := range results {
			index := index
			go func() {
				defer wait.Done()
				results[index] = concurrentAccountRequest(auth, http.MethodPost, "/link-social", cookie, body)
			}()
		}
		wait.Wait()
		for _, result := range results {
			if result.status != http.StatusOK {
				t.Fatalf("link result=%#v", result)
			}
		}
		accounts, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
			Model: "account", Where: []storage.Where{
				{Field: "providerId", Value: "google"}, {Field: "accountId", Value: "link-race-provider"},
			},
		})
		if err != nil || len(accounts) != 1 {
			t.Fatalf("linked accounts=%#v err=%v", accounts, err)
		}
	})

	t.Run("expired access token refreshes once", func(t *testing.T) {
		now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
		email := "refresh-race@example.com"
		var calls atomic.Int64
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "refresh-race-provider", Name: "Race", Email: &email, EmailVerified: true}
		}, func(token string) oauth2.Tokens {
			if token != "old-refresh" {
				t.Errorf("refresh token=%q", token)
			}
			calls.Add(1)
			time.Sleep(10 * time.Millisecond)
			expires := now.Add(time.Hour)
			return oauth2.Tokens{
				AccessToken: "new-access", RefreshToken: "new-refresh", AccessTokenExpiresAt: &expires,
			}
		})
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			Clock:            func() time.Time { return now },
			EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			SocialProviders:  map[string]*providers.Provider{"google": provider},
		})
		cookie, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
			Model: "account", Data: storage.Record{
				"id": "refresh-race-account", "providerId": "google", "accountId": "refresh-race-provider",
				"userId": userID, "accessToken": "old-access", "refreshToken": "old-refresh",
				"accessTokenExpiresAt": now.Add(-time.Minute), "createdAt": now, "updatedAt": now,
			}, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
		const workers = 12
		results := make([]accountWireResult, workers)
		var wait sync.WaitGroup
		wait.Add(workers)
		for index := range results {
			index := index
			go func() {
				defer wait.Done()
				results[index] = concurrentAccountRequest(auth, http.MethodPost, "/get-access-token", cookie, map[string]any{
					"providerId": "google", "accountId": "refresh-race-provider",
				})
			}()
		}
		wait.Wait()
		for _, result := range results {
			if result.status != http.StatusOK || accountObjectString(result.value, "accessToken") != "new-access" {
				t.Fatalf("refresh result=%#v", result)
			}
		}
		if calls.Load() != 1 {
			t.Fatalf("provider refresh calls=%d, want 1", calls.Load())
		}
	})
}

func TestAccountAutomaticRefreshPreservesScopesAndExplicitRefreshUpdatesThem(t *testing.T) {
	now := time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)
	email := "refresh-scope@example.com"
	var calls atomic.Int64
	provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
		return oauth2.UserInfo{ID: "refresh-scope-provider", Name: "Scope", Email: &email, EmailVerified: true}
	}, func(token string) oauth2.Tokens {
		if token != "scope-refresh" {
			t.Errorf("refresh token=%q", token)
		}
		call := calls.Add(1)
		expires := now.Add(time.Duration(call) * time.Hour)
		return oauth2.Tokens{
			AccessToken:          fmt.Sprintf("scope-access-%d", call),
			AccessTokenExpiresAt: &expires,
			Scopes:               []string{"provider-new", "provider-write"},
		}
	})
	auth := MustNew(Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		Clock:            func() time.Time { return now },
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		SocialProviders:  map[string]*providers.Provider{"google": provider},
	})
	cookie, _, session := createSessionTestUser(t, auth, email)
	userID := objectString(t, objectValue(t, session, "user"), "id")
	created, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "account", Data: storage.Record{
			"id": "refresh-scope-account", "providerId": "google", "accountId": "refresh-scope-provider",
			"userId": userID, "accessToken": "scope-old-access", "refreshToken": "scope-refresh",
			"scope": "original-read,original-profile", "accessTokenExpiresAt": now.Add(-time.Minute),
			"createdAt": now, "updatedAt": now,
		}, ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	automatic := sessionAccountRequest(t, auth, http.MethodPost, "/get-access-token", cookie, map[string]any{
		"providerId": "google", "accountId": "refresh-scope-provider",
	})
	if automatic.status != http.StatusOK || accountObjectString(automatic.value, "accessToken") != "scope-access-1" {
		t.Fatalf("automatic refresh status=%d value=%#v", automatic.status, automatic.value)
	}
	if got := accountStringSlice(automatic.value, "scopes"); len(got) != 2 || got[0] != "original-read" || got[1] != "original-profile" {
		t.Fatalf("automatic scopes=%#v", got)
	}
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{{Field: "id", Value: mustRecordString(created, "id")}},
	})
	if err != nil || mustRecordString(stored, "scope") != "original-read,original-profile" {
		t.Fatalf("stored automatic scope=%#v err=%v", stored, err)
	}

	explicit := sessionAccountRequest(t, auth, http.MethodPost, "/refresh-token", cookie, map[string]any{
		"providerId": "google", "accountId": "refresh-scope-provider",
	})
	if explicit.status != http.StatusOK || accountObjectString(explicit.value, "accessToken") != "scope-access-2" ||
		accountObjectString(explicit.value, "scope") != "provider-new,provider-write" {
		t.Fatalf("explicit refresh status=%d value=%#v", explicit.status, explicit.value)
	}
	stored, err = auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{{Field: "id", Value: mustRecordString(created, "id")}},
	})
	if err != nil || mustRecordString(stored, "scope") != "provider-new,provider-write" || calls.Load() != 2 {
		t.Fatalf("stored explicit account=%#v calls=%d err=%v", stored, calls.Load(), err)
	}
}

func TestSocialProviderProfileFieldsHonorInputTransformsAndNonFatalLinkUpdates(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"profileCode": {
				Type: storage.FieldString, Required: storage.Bool(false),
				Transform: storage.FieldTransform{Input: func(value any) (any, error) {
					text, ok := value.(string)
					if !ok {
						return nil, errors.New("profileCode must be a string")
					}
					if text == "reject" {
						return nil, errors.New("profileCode rejected")
					}
					return strings.ToLower(text), nil
				}},
			},
			"serverManaged": {
				Type: storage.FieldString, Required: storage.Bool(false), Input: storage.Bool(false),
				DefaultValue: storage.StaticValue("member"),
			},
			"serverManagedWithoutDefault": {
				Type: storage.FieldString, Required: storage.Bool(false), Input: storage.Bool(false),
			},
		}},
	}}

	t.Run("first social sign-up filters server fields and applies transforms", func(t *testing.T) {
		email := "provider-profile-signup@example.com"
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{
				ID: "provider-profile-signup", Name: "Provider Signup", Email: &email, EmailVerified: true,
				Extra: map[string]any{
					"profileCode": "REMOTE-CODE", "serverManaged": "admin",
					"serverManagedWithoutDefault": "root", "unknownField": "ignored",
				},
			}
		}, nil)
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			Schema: schema, SocialProviders: map[string]*providers.Provider{"google": provider},
		})
		result := sessionAccountRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
			"provider": "google", "idToken": map[string]any{"token": "provider-profile-signup-token"},
		})
		if result.status != http.StatusOK {
			t.Fatalf("sign-up status=%d value=%#v", result.status, result.value)
		}
		user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "email", Value: email}},
		})
		if err != nil || user == nil || mustRecordString(user, "profileCode") != "remote-code" ||
			mustRecordString(user, "serverManaged") != "member" {
			t.Fatalf("provider-created user=%#v err=%v", user, err)
		}
		if _, exists := user["serverManagedWithoutDefault"]; exists {
			t.Fatalf("input:false field persisted from provider: %#v", user)
		}
		if _, exists := user["unknownField"]; exists {
			t.Fatalf("unknown provider field persisted: %#v", user)
		}
	})

	t.Run("explicit link updates only provider-input fields", func(t *testing.T) {
		email := "provider-profile-link@example.com"
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{
				ID: "provider-profile-link", Name: "Provider Link", Email: &email, EmailVerified: true,
				Extra: map[string]any{"profileCode": "LINK-CODE", "serverManaged": "admin"},
			}
		}, nil)
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			Schema: schema, EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			Account:         AccountOptions{AccountLinking: AccountLinkingOptions{UpdateUserInfoOnLink: true}},
			SocialProviders: map[string]*providers.Provider{"google": provider},
		})
		cookie, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		result := sessionAccountRequest(t, auth, http.MethodPost, "/link-social", cookie, map[string]any{
			"provider": "google", "idToken": map[string]any{"token": "provider-profile-link-token"},
		})
		if result.status != http.StatusOK {
			t.Fatalf("link status=%d value=%#v", result.status, result.value)
		}
		user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if err != nil || mustRecordString(user, "name") != "Provider Link" ||
			mustRecordString(user, "profileCode") != "link-code" || mustRecordString(user, "serverManaged") != "member" {
			t.Fatalf("linked user=%#v err=%v", user, err)
		}
	})

	t.Run("OAuth callback link applies the same profile rules", func(t *testing.T) {
		email := "provider-profile-callback@example.com"
		provider, err := providers.Google(providers.Options{
			ClientID: "client", ClientSecret: "secret",
			HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.String() != "https://oauth2.googleapis.com/token" {
					return nil, fmt.Errorf("unexpected provider URL %s", request.URL)
				}
				return &http.Response{
					StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
					Body: io.NopCloser(strings.NewReader(`{"access_token":"callback-profile-access","token_type":"Bearer"}`)),
				}, nil
			})},
			GetUserInfo: func(context.Context, oauth2.Tokens) (*providers.UserInfoResult, error) {
				return &providers.UserInfoResult{User: oauth2.UserInfo{
					ID: "provider-profile-callback", Name: "Provider Callback", Email: &email, EmailVerified: true,
					Extra: map[string]any{"profileCode": "CALLBACK-CODE", "serverManaged": "admin"},
				}}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			Schema: schema, EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			Account:         AccountOptions{AccountLinking: AccountLinkingOptions{UpdateUserInfoOnLink: true}},
			SocialProviders: map[string]*providers.Provider{"google": provider},
		})
		cookie, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		started := sessionAccountRequest(t, auth, http.MethodPost, "/link-social", cookie, map[string]any{
			"provider": "google", "callbackURL": "http://auth.test/linked",
		})
		if started.status != http.StatusOK {
			t.Fatalf("callback link start status=%d value=%#v", started.status, started.value)
		}
		authorizeURL, err := url.Parse(accountObjectString(started.value, "url"))
		if err != nil || authorizeURL.Query().Get("state") == "" {
			t.Fatalf("authorize URL=%v err=%v", authorizeURL, err)
		}
		cookie = cookies.ApplySetCookies(cookie, started.header.Values("Set-Cookie"))
		callback := sessionAccountRequest(t, auth, http.MethodGet,
			"/callback/google?code=valid&state="+url.QueryEscape(authorizeURL.Query().Get("state")), cookie, nil,
		)
		if callback.status != http.StatusFound || callback.header.Get("Location") != "http://auth.test/linked" {
			t.Fatalf("callback status=%d location=%q value=%#v", callback.status, callback.header.Get("Location"), callback.value)
		}
		user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if err != nil || mustRecordString(user, "name") != "Provider Callback" ||
			mustRecordString(user, "profileCode") != "callback-code" || mustRecordString(user, "serverManaged") != "member" {
			t.Fatalf("callback-linked user=%#v err=%v", user, err)
		}
	})

	t.Run("failed mapped field update is non-fatal after account link", func(t *testing.T) {
		email := "provider-profile-invalid@example.com"
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{
				ID: "provider-profile-invalid", Name: "Should Not Replace", Email: &email, EmailVerified: true,
				Extra: map[string]any{"profileCode": "reject"},
			}
		}, nil)
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			Schema: schema, EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			Account:         AccountOptions{AccountLinking: AccountLinkingOptions{UpdateUserInfoOnLink: true}},
			SocialProviders: map[string]*providers.Provider{"google": provider},
		})
		cookie, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
			Update: storage.Record{"profileCode": "LOCAL-CODE"},
		}); err != nil {
			t.Fatal(err)
		}
		result := sessionAccountRequest(t, auth, http.MethodPost, "/link-social", cookie, map[string]any{
			"provider": "google", "idToken": map[string]any{"token": "provider-profile-invalid-token"},
		})
		if result.status != http.StatusOK {
			t.Fatalf("link status=%d value=%#v", result.status, result.value)
		}
		account, err := auth.findAccountByProvider(t.Context(), "google", "provider-profile-invalid")
		if err != nil || account == nil {
			t.Fatalf("linked account=%#v err=%v", account, err)
		}
		user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if err != nil || mustRecordString(user, "name") != "Session User" || mustRecordString(user, "profileCode") != "local-code" {
			t.Fatalf("user changed by failed provider update=%#v err=%v", user, err)
		}
	})

	t.Run("override user info uses the same provider field filter", func(t *testing.T) {
		email := "provider-profile-override@example.com"
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{
				ID: "provider-profile-override", Name: "Provider Override", Email: &email, EmailVerified: true,
				Extra: map[string]any{"profileCode": "OVERRIDE-CODE", "serverManaged": "admin"},
			}
		}, nil)
		provider.Options.OverrideUserInfo = true
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			Schema: schema, EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			SocialProviders: map[string]*providers.Provider{"google": provider},
		})
		_, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
			Update: storage.Record{"emailVerified": true},
		}); err != nil {
			t.Fatal(err)
		}
		result := sessionAccountRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
			"provider": "google", "idToken": map[string]any{"token": "provider-profile-override-token"},
		})
		if result.status != http.StatusOK {
			t.Fatalf("override status=%d value=%#v", result.status, result.value)
		}
		user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if err != nil || mustRecordString(user, "name") != "Provider Override" ||
			mustRecordString(user, "profileCode") != "override-code" || mustRecordString(user, "serverManaged") != "member" {
			t.Fatalf("overridden user=%#v err=%v", user, err)
		}
	})
}

func TestAccountSelectionOwnershipAmbiguityAndFreshnessBoundaries(t *testing.T) {
	t.Run("same provider account ID remains scoped to the authenticated user", func(t *testing.T) {
		email := "selection-provider@example.com"
		provider := accountTestProvider(t, func(tokens oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "info-" + tokens.AccessToken, Name: "Selection", Email: &email, EmailVerified: true}
		}, nil)
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			SocialProviders:  map[string]*providers.Provider{"google": provider},
		})
		firstCookie, _, firstSession := createSessionTestUser(t, auth, "selection-first@example.com")
		secondCookie, _, secondSession := createSessionTestUser(t, auth, "selection-second@example.com")
		firstUserID := objectString(t, objectValue(t, firstSession, "user"), "id")
		secondUserID := objectString(t, objectValue(t, secondSession, "user"), "id")
		now := time.Now().UTC()
		for _, account := range []storage.Record{
			{"id": "selection-first-account", "userId": firstUserID, "providerId": "google", "accountId": "shared-provider-id", "accessToken": "first-access", "createdAt": now, "updatedAt": now},
			{"id": "selection-second-account", "userId": secondUserID, "providerId": "google", "accountId": "shared-provider-id", "accessToken": "second-access", "createdAt": now, "updatedAt": now},
		} {
			if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{Model: "account", Data: account, ForceAllowID: true}); err != nil {
				t.Fatal(err)
			}
		}
		for _, test := range []struct {
			name, cookie, access, info string
		}{
			{name: "first", cookie: firstCookie, access: "first-access", info: "info-first-access"},
			{name: "second", cookie: secondCookie, access: "second-access", info: "info-second-access"},
		} {
			test := test
			t.Run(test.name, func(t *testing.T) {
				access := sessionAccountRequest(t, auth, http.MethodPost, "/get-access-token", test.cookie, map[string]any{
					"providerId": "google", "accountId": "shared-provider-id",
				})
				if access.status != http.StatusOK || accountObjectString(access.value, "accessToken") != test.access {
					t.Fatalf("access status=%d value=%#v", access.status, access.value)
				}
				info := sessionAccountRequest(t, auth, http.MethodGet,
					"/account-info?providerId=google&accountId=shared-provider-id", test.cookie, nil,
				)
				if info.status != http.StatusOK || accountObjectString(accountObject(info.value, "user"), "id") != test.info {
					t.Fatalf("info status=%d value=%#v", info.status, info.value)
				}
			})
		}

		unlinked := sessionAccountRequest(t, auth, http.MethodPost, "/unlink-account", firstCookie, map[string]any{
			"providerId": "google", "accountId": "shared-provider-id",
		})
		if unlinked.status != http.StatusOK {
			t.Fatalf("unlink first status=%d value=%#v", unlinked.status, unlinked.value)
		}
		remaining, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: "selection-second-account"}},
		})
		if err != nil || remaining == nil || mustRecordString(remaining, "userId") != secondUserID {
			t.Fatalf("second user's account=%#v err=%v", remaining, err)
		}
	})

	t.Run("provider disambiguates equal account IDs for one user", func(t *testing.T) {
		email := "selection-ambiguous@example.com"
		google := accountTestProvider(t, func(tokens oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "google-" + tokens.AccessToken, Name: "Google", Email: &email, EmailVerified: true}
		}, nil)
		github := accountTestProvider(t, func(tokens oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "github-" + tokens.AccessToken, Name: "GitHub", Email: &email, EmailVerified: true}
		}, nil)
		github.ID = "github"
		github.Name = "GitHub"
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			SocialProviders:  map[string]*providers.Provider{"google": google, "github": github},
		})
		cookie, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		now := time.Now().UTC()
		for _, account := range []storage.Record{
			{"id": "ambiguous-google", "userId": userID, "providerId": "google", "accountId": "shared-account-id", "accessToken": "google-access", "createdAt": now, "updatedAt": now},
			{"id": "ambiguous-github", "userId": userID, "providerId": "github", "accountId": "shared-account-id", "accessToken": "github-access", "createdAt": now, "updatedAt": now},
		} {
			if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{Model: "account", Data: account, ForceAllowID: true}); err != nil {
				t.Fatal(err)
			}
		}
		ambiguous := sessionAccountRequest(t, auth, http.MethodGet, "/account-info?accountId=shared-account-id", cookie, nil)
		if ambiguous.status != http.StatusBadRequest || accountObjectString(ambiguous.value, "code") != "AMBIGUOUS_ACCOUNT" {
			t.Fatalf("ambiguous status=%d value=%#v", ambiguous.status, ambiguous.value)
		}
		selected := sessionAccountRequest(t, auth, http.MethodGet,
			"/account-info?providerId=github&accountId=shared-account-id", cookie, nil,
		)
		if selected.status != http.StatusOK || accountObjectString(accountObject(selected.value, "user"), "id") != "github-github-access" {
			t.Fatalf("selected status=%d value=%#v", selected.status, selected.value)
		}
	})

	t.Run("unlink requires a fresh session and validates accountId", func(t *testing.T) {
		now := time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC)
		freshAge := 5 * time.Minute
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			Clock:            func() time.Time { return now },
			Session:          SessionOptions{FreshAge: &freshAge},
			EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		})
		cookie, _, session := createSessionTestUser(t, auth, "selection-freshness@example.com")
		userID := objectString(t, objectValue(t, session, "user"), "id")
		if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
			Model: "account", Data: storage.Record{
				"id": "freshness-social", "userId": userID, "providerId": "google", "accountId": "freshness-provider",
				"createdAt": now, "updatedAt": now,
			}, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
		malformed := sessionAccountRequest(t, auth, http.MethodPost, "/unlink-account", cookie, map[string]any{
			"providerId": "google", "accountId": 42,
		})
		if malformed.status != http.StatusBadRequest || accountObjectString(malformed.value, "code") != string(ErrorValidation) {
			t.Fatalf("malformed status=%d value=%#v", malformed.status, malformed.value)
		}
		now = now.Add(freshAge)
		stale := sessionAccountRequest(t, auth, http.MethodPost, "/unlink-account", cookie, map[string]any{
			"providerId": "google", "accountId": "freshness-provider",
		})
		if stale.status != http.StatusForbidden || accountObjectString(stale.value, "code") != string(ErrorSessionNotFresh) {
			t.Fatalf("stale status=%d value=%#v", stale.status, stale.value)
		}
		account, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: "freshness-social"}},
		})
		if err != nil || account == nil {
			t.Fatalf("stale unlink changed account=%#v err=%v", account, err)
		}
	})
}

func TestAccountWriteFailuresRollbackOrPreservePriorState(t *testing.T) {
	t.Run("new social identity rolls back user account and session", func(t *testing.T) {
		email := "rollback-social-create@example.com"
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "rollback-social-provider", Name: "Rollback", Email: &email, EmailVerified: true}
		}, nil)
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			SocialProviders: map[string]*providers.Provider{"google": provider},
			DatabaseHooks: DatabaseHooks{"account": {Create: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					return DatabaseHookResult{}, errors.New("reject OAuth account create")
				},
			}}},
		})
		result := sessionAccountRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
			"provider": "google", "idToken": map[string]any{"token": "rollback-id-token"},
		})
		if result.status != http.StatusUnauthorized || accountObjectString(result.value, "code") != "OAUTH_LINK_ERROR" {
			t.Fatalf("sign-in status=%d value=%#v", result.status, result.value)
		}
		for _, model := range []string{"user", "account", "session"} {
			count, err := auth.Adapter().Count(t.Context(), storage.CountParams{Model: model})
			if err != nil || count != 0 {
				t.Fatalf("%s count=%d err=%v", model, count, err)
			}
		}
	})

	t.Run("explicit link failure leaves credential account only", func(t *testing.T) {
		email := "rollback-explicit-link@example.com"
		var rejectAccount atomic.Bool
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "rollback-explicit-provider", Name: "Rollback", Email: &email, EmailVerified: true}
		}, nil)
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			SocialProviders:  map[string]*providers.Provider{"google": provider},
			DatabaseHooks: DatabaseHooks{"account": {Create: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					if rejectAccount.Load() {
						return DatabaseHookResult{}, errors.New("reject linked account")
					}
					return DatabaseHookResult{}, nil
				},
			}}},
		})
		cookie, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		rejectAccount.Store(true)
		result := sessionAccountRequest(t, auth, http.MethodPost, "/link-social", cookie, map[string]any{
			"provider": "google", "idToken": map[string]any{"token": "rollback-link-id-token"},
		})
		if result.status != 417 || accountObjectString(result.value, "code") != "LINKING_FAILED" {
			t.Fatalf("link status=%d value=%#v", result.status, result.value)
		}
		accounts, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
			Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
		})
		if err != nil || len(accounts) != 1 || mustRecordString(accounts[0], "providerId") != "credential" {
			t.Fatalf("accounts=%#v err=%v", accounts, err)
		}
	})

	t.Run("implicit link failure is reported to the configured logger", func(t *testing.T) {
		email := "rollback-implicit-logger@example.com"
		var rejectAccount atomic.Bool
		var logLock sync.Mutex
		var logEntries []string
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "rollback-implicit-provider", Name: "Rollback", Email: &email, EmailVerified: true}
		}, nil)
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			SocialProviders:  map[string]*providers.Provider{"google": provider},
			Logger: authlogger.Options{Level: authlogger.Debug, Log: func(level authlogger.Level, message string, _ ...any) {
				logLock.Lock()
				logEntries = append(logEntries, string(level)+":"+message)
				logLock.Unlock()
			}},
			DatabaseHooks: DatabaseHooks{"account": {Create: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					if rejectAccount.Load() {
						return DatabaseHookResult{}, errors.New("implicit link failed")
					}
					return DatabaseHookResult{}, nil
				},
			}}},
		})
		_, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
			Update: storage.Record{"emailVerified": true},
		}); err != nil {
			t.Fatal(err)
		}
		rejectAccount.Store(true)
		result := sessionAccountRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
			"provider": "google", "idToken": map[string]any{"token": "rollback-implicit-token"},
		})
		if result.status != http.StatusUnauthorized || accountObjectString(result.value, "message") != "unable to link account" {
			t.Fatalf("implicit link status=%d value=%#v", result.status, result.value)
		}
		logLock.Lock()
		gotLogs := append([]string(nil), logEntries...)
		logLock.Unlock()
		if len(gotLogs) != 1 || gotLogs[0] != "error:Unable to link account" {
			t.Fatalf("logger entries=%#v", gotLogs)
		}
	})

	t.Run("unlink delete failure preserves account", func(t *testing.T) {
		email := "rollback-unlink@example.com"
		var rejectDelete atomic.Bool
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			DatabaseHooks: DatabaseHooks{"account": {Delete: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					if rejectDelete.Load() {
						return DatabaseHookResult{}, errors.New("reject account delete")
					}
					return DatabaseHookResult{}, nil
				},
			}}},
		})
		cookie, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		now := time.Now().UTC()
		if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
			Model: "account", Data: storage.Record{
				"id": "rollback-unlink-social", "providerId": "google", "accountId": "rollback-unlink-provider",
				"userId": userID, "createdAt": now, "updatedAt": now,
			}, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
		rejectDelete.Store(true)
		result := sessionAccountRequest(t, auth, http.MethodPost, "/unlink-account", cookie, map[string]any{
			"providerId": "google", "accountId": "rollback-unlink-provider",
		})
		if result.status != http.StatusInternalServerError || accountObjectString(result.value, "code") != "INTERNAL_SERVER_ERROR" {
			t.Fatalf("unlink status=%d value=%#v", result.status, result.value)
		}
		account, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: "rollback-unlink-social"}},
		})
		if err != nil || account == nil {
			t.Fatalf("preserved account=%#v err=%v", account, err)
		}
	})

	t.Run("refresh update failure preserves old tokens", func(t *testing.T) {
		email := "rollback-refresh@example.com"
		var rejectUpdate atomic.Bool
		provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
			return oauth2.UserInfo{ID: "rollback-refresh-provider", Name: "Rollback", Email: &email, EmailVerified: true}
		}, func(string) oauth2.Tokens {
			return oauth2.Tokens{AccessToken: "new-access", RefreshToken: "new-refresh", Scopes: []string{"new-scope"}}
		})
		auth := MustNew(Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
			SocialProviders:  map[string]*providers.Provider{"google": provider},
			DatabaseHooks: DatabaseHooks{"account": {Update: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					if rejectUpdate.Load() {
						return DatabaseHookResult{}, errors.New("reject token update")
					}
					return DatabaseHookResult{}, nil
				},
			}}},
		})
		cookie, _, session := createSessionTestUser(t, auth, email)
		userID := objectString(t, objectValue(t, session, "user"), "id")
		now := time.Now().UTC()
		if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
			Model: "account", Data: storage.Record{
				"id": "rollback-refresh-account", "providerId": "google", "accountId": "rollback-refresh-provider",
				"userId": userID, "accessToken": "old-access", "refreshToken": "old-refresh", "scope": "old-scope",
				"createdAt": now, "updatedAt": now,
			}, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
		rejectUpdate.Store(true)
		result := sessionAccountRequest(t, auth, http.MethodPost, "/refresh-token", cookie, map[string]any{
			"providerId": "google", "accountId": "rollback-refresh-provider",
		})
		if result.status != http.StatusBadRequest || accountObjectString(result.value, "code") != "FAILED_TO_REFRESH_ACCESS_TOKEN" {
			t.Fatalf("refresh status=%d value=%#v", result.status, result.value)
		}
		account, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: "rollback-refresh-account"}},
		})
		if err != nil || mustRecordString(account, "accessToken") != "old-access" ||
			mustRecordString(account, "refreshToken") != "old-refresh" || mustRecordString(account, "scope") != "old-scope" {
			t.Fatalf("preserved tokens account=%#v err=%v", account, err)
		}
	})
}

func TestAccountCookieAndOAuthSecretsStayEncrypted(t *testing.T) {
	now := time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC)
	email := "account-cookie-secret@example.com"
	provider := accountTestProvider(t, func(oauth2.Tokens) oauth2.UserInfo {
		return oauth2.UserInfo{ID: "cookie-provider-user", Name: "Cookie", Email: &email, EmailVerified: true}
	}, nil)
	auth := MustNew(Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		Clock:           func() time.Time { return now },
		Account:         AccountOptions{EncryptOAuthTokens: true, StoreAccountCookie: storage.Bool(true)},
		SocialProviders: map[string]*providers.Provider{"google": provider},
	})
	result := sessionAccountRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
		"provider": "google", "idToken": map[string]any{
			"token": "provider-id", "accessToken": "plain-access-secret",
		},
	})
	if result.status != http.StatusOK {
		t.Fatalf("sign-in status=%d value=%#v", result.status, result.value)
	}
	accountCookieName := auth.options.cookie.accountDataName
	var accountToken string
	for _, line := range result.header.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Name == accountCookieName {
				accountToken = parsed.Attributes.Value
			}
		}
	}
	if accountToken == "" || bytes.Contains([]byte(accountToken), []byte("plain-access-secret")) {
		t.Fatalf("account cookie is absent or plaintext: %q", accountToken)
	}
	claims, err := baCrypto.DecodeJWEAt(accountToken, auth.options.Secret, "single-auth-account", now)
	if err != nil {
		t.Fatal(err)
	}
	storedAccess, _ := claims["accessToken"].(string)
	if storedAccess == "" || storedAccess == "plain-access-secret" {
		t.Fatalf("decoded account cookie contains plaintext OAuth secret: %#v", claims)
	}
	decoded, err := auth.loadOAuthToken(storedAccess)
	if err != nil || decoded != "plain-access-secret" {
		t.Fatalf("decoded OAuth token=%q err=%v", decoded, err)
	}
	cookieHeader := cookies.ApplySetCookies("", result.header.Values("Set-Cookie"))
	access := sessionAccountRequest(t, auth, http.MethodPost, "/get-access-token", cookieHeader, map[string]any{
		"providerId": "google", "accountId": "cookie-provider-user",
	})
	if access.status != http.StatusOK || accountObjectString(access.value, "accessToken") != "plain-access-secret" {
		t.Fatalf("access status=%d value=%#v", access.status, access.value)
	}

	tampered := accountToken[:len(accountToken)-1] + "x"
	tamperedCookies := replaceAccountCookie(cookieHeader, accountCookieName, tampered)
	// A forged account snapshot is ignored; the authenticated stateful request
	// falls back to the durable account row and still returns the owner's token.
	access = sessionAccountRequest(t, auth, http.MethodPost, "/get-access-token", tamperedCookies, map[string]any{
		"providerId": "google", "accountId": "cookie-provider-user",
	})
	if access.status != http.StatusOK || accountObjectString(access.value, "accessToken") != "plain-access-secret" {
		t.Fatalf("tampered-cookie fallback status=%d value=%#v", access.status, access.value)
	}
}

type slowAccountAdapter struct {
	storage.Adapter
	findDelay time.Duration
}

func (adapter *slowAccountAdapter) FindOne(ctx context.Context, params storage.FindOneParams) (storage.Record, error) {
	record, err := adapter.Adapter.FindOne(ctx, params)
	if params.Model == "account" && adapter.findDelay > 0 {
		time.Sleep(adapter.findDelay)
	}
	return record, err
}

func (adapter *slowAccountAdapter) FindMany(ctx context.Context, params storage.FindManyParams) ([]storage.Record, error) {
	records, err := adapter.Adapter.FindMany(ctx, params)
	if params.Model == "account" && adapter.findDelay > 0 {
		time.Sleep(adapter.findDelay)
	}
	return records, err
}

func sessionAccountRequest(
	t *testing.T,
	auth *Auth,
	method, path, cookie string,
	body map[string]any,
) accountWireResult {
	t.Helper()
	status, header, value := sessionTestRequest(t, auth, method, path, cookie, body)
	return accountWireResult{status: status, header: header, value: value}
}

func concurrentAccountRequest(
	auth *Auth,
	method, path, cookie string,
	body map[string]any,
) accountWireResult {
	encoded, _ := json.Marshal(body)
	request := httptest.NewRequest(method, "http://auth.test/api/auth"+path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
		request.Header.Set("Origin", "http://auth.test")
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	var value any
	decoder := json.NewDecoder(bytes.NewReader(recorder.Body.Bytes()))
	decoder.UseNumber()
	_ = decoder.Decode(&value)
	return accountWireResult{status: recorder.Code, header: recorder.Header().Clone(), value: value}
}

func accountSafeName(value string) string {
	result := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			result = append(result, character)
		} else {
			result = append(result, '-')
		}
	}
	return string(result)
}

func replaceAccountCookie(header, name, value string) string {
	parsed := cookies.Parse(header)
	parsed.Set(name, value)
	return parsed.Header()
}

func accountTestProvider(
	t *testing.T,
	userInfo func(oauth2.Tokens) oauth2.UserInfo,
	refresh func(string) oauth2.Tokens,
) *providers.Provider {
	t.Helper()
	options := providers.Options{
		ClientID: "client", ClientSecret: "secret",
		VerifyIDToken: func(context.Context, string, string) (bool, error) { return true, nil },
		GetUserInfo: func(_ context.Context, tokens oauth2.Tokens) (*providers.UserInfoResult, error) {
			return &providers.UserInfoResult{User: userInfo(tokens), Data: map[string]any{"source": "test"}}, nil
		},
	}
	if refresh != nil {
		options.RefreshAccessToken = func(_ context.Context, token string) (oauth2.Tokens, error) {
			return refresh(token), nil
		}
	}
	provider, err := providers.Google(options)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func accountWireTransports() []accountWireTransport {
	return []accountWireTransport{
		{name: "direct", bind: accountWireDirect},
		{name: "net-http", bind: accountWireNetHTTP},
		{name: "fasthttp", bind: accountWireFastHTTP},
		{name: "fiber", bind: accountWireFiber},
	}
}

func accountWireDirect(_ *testing.T, auth *Auth) accountWireExchange {
	return func(t *testing.T, method, target, cookie string, body any) accountWireResult {
		encoded := accountEncodeBody(t, body)
		parsed, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		headers := contract.NewHeaders()
		if body != nil {
			headers.Add("Content-Type", "application/json")
		}
		if cookie != "" {
			headers.Add("Cookie", cookie)
			if method != http.MethodGet && method != http.MethodHead {
				headers.Add("Origin", "http://auth.test")
			}
		}
		response, _ := auth.Dispatcher().Dispatch(contract.NewRequest(method, parsed.Path, contract.RequestOptions{
			Context: t.Context(), Scheme: "http", Host: "auth.test", RawQuery: parsed.RawQuery,
			Headers: headers, Body: encoded,
		}))
		return accountWireDecode(t, response.Status(), accountHTTPHeader(response.Headers()), response.Body())
	}
}

func accountWireNetHTTP(_ *testing.T, auth *Auth) accountWireExchange {
	return func(t *testing.T, method, target, cookie string, body any) accountWireResult {
		request := httptest.NewRequest(method, "http://auth.test"+target, bytes.NewReader(accountEncodeBody(t, body)))
		accountSetRequestHeaders(request.Header, method, cookie, body != nil)
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		return accountWireDecode(t, recorder.Code, recorder.Header().Clone(), recorder.Body.Bytes())
	}
}

func accountWireFastHTTP(_ *testing.T, auth *Auth) accountWireExchange {
	handler := fasthttptransport.NewHandler(auth.Dispatcher())
	return func(t *testing.T, method, target, cookie string, body any) accountWireResult {
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.Header.SetHost("auth.test")
		request.URI().SetScheme("http")
		request.SetRequestURI(target)
		if body != nil {
			request.Header.SetContentType("application/json")
			request.SetBody(accountEncodeBody(t, body))
		}
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
			if method != http.MethodGet && method != http.MethodHead {
				request.Header.Set("Origin", "http://auth.test")
			}
		}
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		header := make(http.Header)
		requestContext.Response.Header.VisitAll(func(key, value []byte) {
			header.Add(string(key), string(value))
		})
		return accountWireDecode(t, requestContext.Response.StatusCode(), header, requestContext.Response.Body())
	}
}

func accountWireFiber(t *testing.T, auth *Auth) accountWireExchange {
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(auth.Dispatcher()))
	t.Cleanup(func() { _ = app.Shutdown() })
	return func(t *testing.T, method, target, cookie string, body any) accountWireResult {
		request, err := http.NewRequest(method, "http://auth.test"+target, bytes.NewReader(accountEncodeBody(t, body)))
		if err != nil {
			t.Fatal(err)
		}
		accountSetRequestHeaders(request.Header, method, cookie, body != nil)
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return accountWireDecode(t, response.StatusCode, response.Header.Clone(), payload)
	}
}

func accountEncodeBody(t *testing.T, value any) []byte {
	t.Helper()
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func accountSetRequestHeaders(header http.Header, method, cookie string, hasBody bool) {
	if hasBody {
		header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		header.Set("Cookie", cookie)
		if method != http.MethodGet && method != http.MethodHead {
			header.Set("Origin", "http://auth.test")
		}
	}
}

func accountWireDecode(t *testing.T, status int, header http.Header, body []byte) accountWireResult {
	t.Helper()
	var value any
	if len(bytes.TrimSpace(body)) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatalf("decode status=%d body=%q: %v", status, body, err)
		}
	}
	return accountWireResult{status: status, header: header, value: value}
}

func accountHTTPHeader(headers contract.Headers) http.Header {
	result := make(http.Header)
	for _, field := range headers.Fields() {
		result.Add(field.Name, field.Value)
	}
	return result
}

func accountObject(value any, keys ...string) map[string]any {
	current, _ := value.(map[string]any)
	for _, key := range keys {
		current, _ = current[key].(map[string]any)
	}
	return current
}

func accountObjectString(value any, key string) string {
	object, _ := value.(map[string]any)
	text, _ := object[key].(string)
	return text
}

func accountStringSlice(value any, key string) []string {
	object, _ := value.(map[string]any)
	raw, _ := object[key].([]any)
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		text, _ := item.(string)
		result = append(result, text)
	}
	return result
}
