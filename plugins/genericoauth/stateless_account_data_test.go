package genericoauth

import (
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/storage"
)

type statelessAccountExpectations struct {
	ProviderID         string
	AccountID          string
	CallbackURL        string
	NewUserCallbackURL string
	JWESalt            string
	Resolution         statelessAccountResolution
}

type statelessAccountResolution struct {
	Secret                              string
	ProviderID                          string
	AccountID                           string
	AccessToken                         string
	RefreshToken                        string
	RefreshedAccessToken                string
	RotatedRefreshToken                 string
	SessionCacheStrategy                string
	SessionCacheMaxAgeSeconds           int
	SessionCacheRefreshUpdateAgeSeconds int
}

var statelessAccountCases = statelessAccountExpectations{
	ProviderID:         "test-stateless",
	AccountID:          "first-time-stateless-sub",
	CallbackURL:        "http://localhost:3000/dashboard",
	NewUserCallbackURL: "http://localhost:3000/new_user",
	JWESalt:            "single-auth-account",
	Resolution: statelessAccountResolution{
		Secret:                              "stateless-test-secret-stateless-test-secret",
		ProviderID:                          "idp",
		AccountID:                           "shared-idp-user",
		AccessToken:                         "idp-access-token",
		RefreshToken:                        "idp-refresh-token",
		RefreshedAccessToken:                "idp-refreshed-access-token",
		RotatedRefreshToken:                 "idp-rotated-refresh-token",
		SessionCacheStrategy:                "jwe",
		SessionCacheMaxAgeSeconds:           60,
		SessionCacheRefreshUpdateAgeSeconds: 3600,
	},
}

func TestStatelessFirstOAuthCallbackEmitsDecodableAccountDataCookie(t *testing.T) {
	expected := statelessAccountCases

	server := newGenericOAuthServer(t, Profile{
		"sub": expected.AccountID, "email": "first-time-stateless@test.com",
		"email_verified": true, "name": "First Time Stateless",
	})
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: genericBaseURL, Secret: genericSecret,
		Clock:          func() time.Time { return now },
		TrustedOrigins: []string{"http://localhost:3000"},
		Session:        singleauth.SessionOptions{Stateless: true},
		Advanced:       singleauth.AdvancedOptions{UseSecureCookies: storage.Bool(true)},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			Config: []Config{server.config(expected.ProviderID)},
		})},
	})
	normalized := auth.Options()
	if normalized.Database != nil {
		t.Fatal("regression guard: OAuth test must run without a configured database")
	}
	if normalized.Account.StoreAccountCookie == nil || !*normalized.Account.StoreAccountCookie {
		t.Fatal("stateless mode did not default storeAccountCookie to true")
	}
	if normalized.Account.StoreStateStrategy != "cookie" {
		t.Fatalf("stateless state strategy = %q, want cookie", normalized.Account.StoreStateStrategy)
	}

	flow := startGenericFlow(
		t, auth, expected.ProviderID, expected.CallbackURL, expected.NewUserCallbackURL, "", nil,
	)
	callback := finishGenericFlow(t, auth, expected.ProviderID, flow, nil)
	if callback.Status != 302 || callback.Header.Get("Location") != expected.NewUserCallbackURL {
		t.Fatalf("first callback status=%d location=%q body=%s", callback.Status, callback.Header.Get("Location"), callback.Body)
	}

	var accountCookie *cookies.SetCookie
	for _, line := range callback.Header.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if strings.HasSuffix(parsed.Name, ".account_data") {
				copy := parsed
				accountCookie = &copy
			}
		}
	}
	if accountCookie == nil || accountCookie.Attributes.Value == "" {
		t.Fatalf("first OAuth callback omitted account_data: %#v", callback.Header.Values("Set-Cookie"))
	}
	if !strings.HasPrefix(accountCookie.Attributes.Value, "ey") {
		t.Fatalf("account_data value is not a compact JWE: %q", accountCookie.Attributes.Value)
	}
	if !accountCookie.Attributes.Secure || !accountCookie.Attributes.HTTPOnly ||
		accountCookie.Attributes.SameSite != "lax" || accountCookie.Attributes.MaxAge == nil ||
		*accountCookie.Attributes.MaxAge <= 0 {
		t.Fatalf("account_data attributes = %#v", accountCookie.Attributes)
	}

	claims, err := baCrypto.DecodeJWEAt(
		accountCookie.Attributes.Value, genericSecret, expected.JWESalt, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims["providerId"] != expected.ProviderID || claims["accountId"] != expected.AccountID {
		t.Fatalf("account_data identity claims = %#v", claims)
	}
	accessToken, ok := claims["accessToken"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("account_data access token = %#v", claims["accessToken"])
	}
}
