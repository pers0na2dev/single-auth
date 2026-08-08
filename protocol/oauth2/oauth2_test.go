package oauth2

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFormMatchesURLSearchParams(t *testing.T) {
	t.Parallel()
	form := NewForm()
	form.Set("x", "a b~!*()'")
	if got, want := form.Encode(), "x=a+b%7E%21*%28%29%27"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
	form.Append("resource", "one")
	form.Append("resource", "two")
	if values := form.Values("resource"); len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("unexpected resources: %#v", values)
	}
	form.Set("resource", "replaced")
	if values := form.Values("resource"); len(values) != 1 || values[0] != "replaced" {
		t.Fatalf("Set did not remove duplicates: %#v", values)
	}
}

func TestAuthorizationURL(t *testing.T) {
	t.Parallel()
	parsed, err := CreateAuthorizationURL(AuthorizationURLOptions{
		AuthorizationEndpoint: "https://idp.example/authorize?tenant=one",
		Options:               ProviderOptions{ClientID: []string{"primary", "mobile"}},
		RedirectURI:           "https://app.example/api/auth/callback/idp",
		State:                 "state",
		CodeVerifier:          "verifier",
		Scopes:                []string{"openid", "email"},
		Claims:                []string{"name"},
		AdditionalParams:      []Param{{Name: "prompt", Value: "consent"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "tenant=one&response_type=code&client_id=primary&state=state&scope=openid+email&redirect_uri=https%3A%2F%2Fapp.example%2Fapi%2Fauth%2Fcallback%2Fidp&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ&claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%2C%22email_verified%22%3Anull%2C%22name%22%3Anull%7D%7D&prompt=consent"
	if parsed.RawQuery != want {
		t.Fatalf("authorization query mismatch:\nwant %s\n got %s", want, parsed.RawQuery)
	}
}

func TestAuthorizationCodeAndRefreshRequests(t *testing.T) {
	t.Parallel()
	request := CreateAuthorizationCodeRequest(AuthorizationCodeRequestOptions{
		Code:           "code",
		CodeVerifier:   "verifier",
		RedirectURI:    "https://app.example/callback",
		Options:        ProviderOptions{ClientID: "client", ClientSecret: "secret"},
		Authentication: AuthenticationBasic,
		Resources:      []string{"one", "two"},
		AdditionalParams: []Param{
			{Name: "code", Value: "must-not-override"},
			{Name: "audience", Value: "api"},
		},
	})
	if got := request.Headers["authorization"]; got != "Basic "+base64.StdEncoding.EncodeToString([]byte("client:secret")) {
		t.Fatalf("unexpected basic auth: %q", got)
	}
	if code, _ := request.Body.Get("code"); code != "code" {
		t.Fatalf("reserved param overridden: %q", code)
	}
	if resources := request.Body.Values("resource"); len(resources) != 2 {
		t.Fatalf("resources lost: %#v", resources)
	}

	refresh := CreateRefreshAccessTokenRequest(RefreshTokenRequestOptions{
		RefreshToken:   "old",
		Options:        ProviderOptions{ClientSecret: "secret"},
		Authentication: AuthenticationBasic,
	})
	if got := refresh.Headers["authorization"]; got != "Basic OnNlY3JldA==" {
		t.Fatalf("missing-client basic auth mismatch: %q", got)
	}
}

func TestClientCredentialsUsesPaddedBase64URL(t *testing.T) {
	t.Parallel()
	request := CreateClientCredentialsTokenRequest(ClientCredentialsRequestOptions{
		Options:        ProviderOptions{ClientID: "client", ClientSecret: "secret"},
		Authentication: AuthenticationBasic,
	})
	if got := request.Headers["authorization"]; got != "Basic Y2xpZW50OnNlY3JldA==" {
		t.Fatalf("unexpected authorization: %q", got)
	}
}

func TestDoFormRefusesRedirect(t *testing.T) {
	t.Parallel()
	var internalCalled atomic.Bool
	internal := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		internalCalled.Store(true)
	}))
	defer internal.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", internal.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()
	_, err := DoForm(context.Background(), nil, redirect.URL, FormRequest{Body: NewForm(), Headers: map[string]string{}})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect error, got %v", err)
	}
	if internalCalled.Load() {
		t.Fatal("redirect target was called")
	}
}

func TestNormalizeTokens(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	tokens := NormalizeTokens(map[string]any{
		"access_token":             "access",
		"refresh_token":            "refresh",
		"expires_in":               float64(3600),
		"refresh_token_expires_in": float64(86400),
		"scope":                    "openid email",
		"token_type":               "Bearer",
	}, now)
	if tokens.AccessTokenExpiresAt == nil || !tokens.AccessTokenExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("bad access expiry: %v", tokens.AccessTokenExpiresAt)
	}
	if tokens.RefreshTokenExpiresAt == nil || !tokens.RefreshTokenExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("bad refresh expiry: %v", tokens.RefreshTokenExpiresAt)
	}
	if len(tokens.Scopes) != 2 {
		t.Fatalf("bad scopes: %#v", tokens.Scopes)
	}
}
