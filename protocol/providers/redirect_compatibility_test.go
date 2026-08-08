package providers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

type redirectOnceTransport struct {
	calls int
	body  string
}

func (transport *redirectOnceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls++
	if transport.calls == 1 {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://final.example/result"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(transport.body)), Request: request}, nil
}

func TestSharedTokenExchangeRefusesRedirects(t *testing.T) {
	transport := &redirectOnceTransport{body: `{"access_token":"access"}`}
	provider, _ := Google(Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: transport}})
	_, err := provider.ValidateAuthorizationCode(context.Background(), CodeInput{Code: "code", CodeVerifier: "verifier", RedirectURI: "https://app.example/callback"})
	if !errors.Is(err, oauth2.ErrOAuthRedirect) {
		t.Fatalf("error = %v, want ErrOAuthRedirect", err)
	}
	if transport.calls != 1 {
		t.Fatalf("redirect was followed: %d calls", transport.calls)
	}
}

func TestProviderSpecificBetterFetchPathsFollowRedirects(t *testing.T) {
	for _, id := range []string{"github", "reddit", "paypal", "wechat"} {
		id := id
		t.Run(id, func(t *testing.T) {
			body := `{"access_token":"access","refresh_token":"refresh","expires_in":3600,"scope":"one two","openid":"open"}`
			if id == "wechat" {
				body = `{"access_token":"access","refresh_token":"refresh","expires_in":3600,"scope":"one,two","openid":"open"}`
			}
			transport := &redirectOnceTransport{body: body}
			provider, err := New(id, Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: transport}})
			if err != nil {
				t.Fatal(err)
			}
			tokens, err := provider.ValidateAuthorizationCode(context.Background(), CodeInput{Code: "code", CodeVerifier: "verifier", RedirectURI: "https://app.example/callback"})
			if err != nil || tokens == nil || tokens.AccessToken != "access" {
				t.Fatalf("redirected exchange failed: tokens=%#v err=%v", tokens, err)
			}
			if transport.calls != 2 {
				t.Fatalf("redirect was not followed: %d calls", transport.calls)
			}
		})
	}
}

func TestUserInfoFetchFollowsRedirects(t *testing.T) {
	transport := &redirectOnceTransport{body: `{"id":"sp1","display_name":"Spotify","email":"sp@example.com","images":[]}`}
	provider, _ := Spotify(Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: transport}})
	info, err := provider.GetUserInfo(context.Background(), oauth2.Tokens{AccessToken: "access"})
	if err != nil || info == nil || info.User.ID != "sp1" {
		t.Fatalf("redirected profile fetch failed: info=%#v err=%v", info, err)
	}
	if transport.calls != 2 {
		t.Fatalf("redirect was not followed: %d calls", transport.calls)
	}
}
