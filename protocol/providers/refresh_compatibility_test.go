package providers

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestRefreshRequestsMatchReference126(t *testing.T) {
	standard := "grant_type=refresh_token&refresh_token=refresh&client_id=client&client_secret=secret"
	basic := "grant_type=refresh_token&refresh_token=refresh"
	bodies := map[string]string{}
	for _, id := range Builtins {
		bodies[id] = standard
	}
	for _, id := range []string{"figma", "twitter", "reddit", "railway"} {
		bodies[id] = basic
	}
	bodies["microsoft"] = standard + "&scope=openid+profile+email+User.Read+offline_access"
	bodies["tiktok"] = "grant_type=refresh_token&refresh_token=refresh&client_id=undefined&client_secret=secret&client_key=key"
	bodies["paypal"] = basic
	bodies["wechat"] = ""

	for _, id := range Builtins {
		id := id
		t.Run(id, func(t *testing.T) {
			transport := &captureTokenTransport{}
			options := Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: transport}}
			if id == "cognito" {
				options.Domain, options.Region, options.UserPoolID = "tenant.auth.us-east-1.amazoncognito.com", "us-east-1", "pool"
			}
			if id == "tiktok" {
				options.ClientID, options.ClientKey = nil, "key"
			}
			provider, err := New(id, options)
			if err != nil {
				t.Fatal(err)
			}
			tokens, err := provider.RefreshAccessToken(context.Background(), "refresh")
			if id == "vercel" {
				if err == nil || !strings.Contains(err.Error(), "does not support refresh") {
					t.Fatalf("Vercel refresh error = %v", err)
				}
				if provider.Metadata.SupportsRefresh {
					t.Fatal("Vercel metadata incorrectly advertises refresh")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tokens.AccessToken != "access" {
				t.Fatalf("access token = %q", tokens.AccessToken)
			}
			if tokens.Raw != nil {
				t.Fatalf("refresh tokens unexpectedly retain raw response: %#v", tokens.Raw)
			}
			if transport.request.body != bodies[id] {
				t.Fatalf("body mismatch\n got: %s\nwant: %s", transport.request.body, bodies[id])
			}
			if id == "wechat" {
				want := "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=client&grant_type=refresh_token&refresh_token=refresh"
				if transport.request.method != http.MethodGet || transport.request.url != want {
					t.Fatalf("WeChat request = %s %s", transport.request.method, transport.request.url)
				}
			}
			if (id == "figma" || id == "twitter" || id == "reddit" || id == "railway" || id == "paypal") && transport.request.headers.Get("Authorization") != "Basic Y2xpZW50OnNlY3JldA==" {
				t.Fatalf("basic authorization = %q", transport.request.headers.Get("Authorization"))
			}
		})
	}
}
