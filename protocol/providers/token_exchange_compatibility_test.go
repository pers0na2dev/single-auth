package providers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type capturedRequest struct {
	method  string
	url     string
	headers http.Header
	body    string
}

type captureTokenTransport struct{ request capturedRequest }

func (transport *captureTokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var body []byte
	if request.Body != nil {
		body, _ = io.ReadAll(request.Body)
	}
	transport.request = capturedRequest{method: request.Method, url: request.URL.String(), headers: request.Header.Clone(), body: string(body)}
	response := `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600,"scope":"one two","id_token":"id-token","openid":"wechat-openid"}`
	if strings.Contains(request.URL.Host, "weixin.qq.com") {
		response = `{"access_token":"access","refresh_token":"refresh","expires_in":3600,"scope":"one,two","openid":"wechat-openid"}`
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(response)), Request: request}, nil
}

func TestAuthorizationCodeRequestsMatchReference126(t *testing.T) {
	withVerifier := "grant_type=authorization_code&code=code&code_verifier=verifier&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&client_id=client&client_secret=secret"
	withoutVerifier := "grant_type=authorization_code&code=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&client_id=client&client_secret=secret"
	basicWithVerifier := "grant_type=authorization_code&code=code&code_verifier=verifier&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback"
	basicWithoutVerifier := "grant_type=authorization_code&code=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback"
	bodies := map[string]string{
		"apple": withVerifier, "atlassian": withVerifier, "cognito": withVerifier,
		"discord": withoutVerifier, "facebook": withoutVerifier, "figma": basicWithVerifier,
		"github": withVerifier, "microsoft": withVerifier, "google": withVerifier,
		"huggingface": withVerifier, "slack": withoutVerifier, "spotify": withVerifier,
		"twitch": withoutVerifier, "twitter": basicWithVerifier, "dropbox": withVerifier,
		"kick": withVerifier, "linear": withoutVerifier, "linkedin": withoutVerifier,
		"gitlab": withVerifier,
		"tiktok": "grant_type=authorization_code&code=code&client_key=key&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&client_id=undefined&client_secret=secret",
		"reddit": basicWithoutVerifier, "roblox": withoutVerifier, "salesforce": withVerifier,
		"vk":   "grant_type=authorization_code&code=code&code_verifier=verifier&device_id=device&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&client_id=client&client_secret=secret",
		"zoom": withVerifier, "notion": basicWithoutVerifier, "kakao": withoutVerifier,
		"naver": withoutVerifier, "line": withVerifier, "paybin": withVerifier,
		"paypal":  "grant_type=authorization_code&code=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback",
		"railway": basicWithVerifier, "vercel": withVerifier,
		"wechat": "",
	}
	basic := map[string]bool{"figma": true, "twitter": true, "reddit": true, "notion": true, "paypal": true, "railway": true}
	tokenURLs := map[string]string{
		"apple": "https://appleid.apple.com/auth/token", "atlassian": "https://auth.atlassian.com/oauth/token", "cognito": "https://tenant.auth.us-east-1.amazoncognito.com/oauth2/token",
		"discord": "https://discord.com/api/oauth2/token", "facebook": "https://graph.facebook.com/v24.0/oauth/access_token", "figma": "https://api.figma.com/v1/oauth/token",
		"github": "https://github.com/login/oauth/access_token", "microsoft": "https://login.microsoftonline.com/common/oauth2/v2.0/token", "google": "https://oauth2.googleapis.com/token",
		"huggingface": "https://huggingface.co/oauth/token", "slack": "https://slack.com/api/openid.connect.token", "spotify": "https://accounts.spotify.com/api/token",
		"twitch": "https://id.twitch.tv/oauth2/token", "twitter": "https://api.x.com/2/oauth2/token", "dropbox": "https://api.dropboxapi.com/oauth2/token",
		"kick": "https://id.kick.com/oauth/token", "linear": "https://api.linear.app/oauth/token", "linkedin": "https://www.linkedin.com/oauth/v2/accessToken",
		"gitlab": "https://gitlab.com/oauth/token", "tiktok": "https://open.tiktokapis.com/v2/oauth/token/", "reddit": "https://www.reddit.com/api/v1/access_token",
		"roblox": "https://apis.roblox.com/oauth/v1/token", "salesforce": "https://login.salesforce.com/services/oauth2/token", "vk": "https://id.vk.com/oauth2/auth",
		"zoom": "https://zoom.us/oauth/token", "notion": "https://api.notion.com/v1/oauth/token", "kakao": "https://kauth.kakao.com/oauth/token",
		"naver": "https://nid.naver.com/oauth2.0/token", "line": "https://api.line.me/oauth2/v2.1/token", "paybin": "https://idp.paybin.io/oauth2/token",
		"paypal": "https://api-m.sandbox.paypal.com/v1/oauth2/token", "railway": "https://backboard.railway.com/oauth/token",
		"vercel": "https://api.vercel.com/login/oauth/token", "wechat": "https://api.weixin.qq.com/sns/oauth2/access_token?appid=client&secret=secret&code=code&grant_type=authorization_code",
	}
	for _, id := range Builtins {
		id := id
		t.Run(id, func(t *testing.T) {
			transport := &captureTokenTransport{}
			options := Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: transport}}
			if id == "cognito" {
				options.Domain, options.Region, options.UserPoolID = "tenant.auth.us-east-1.amazoncognito.com", "us-east-1", "pool"
			}
			if id == "tiktok" {
				options.ClientID = nil
				options.ClientKey = "key"
			}
			provider, err := New(id, options)
			if err != nil {
				t.Fatal(err)
			}
			tokens, err := provider.ValidateAuthorizationCode(context.Background(), CodeInput{Code: "code", CodeVerifier: "verifier", RedirectURI: "https://app.example/callback", DeviceID: "device"})
			if err != nil {
				t.Fatal(err)
			}
			if tokens == nil || tokens.AccessToken != "access" {
				t.Fatalf("unexpected tokens: %#v", tokens)
			}
			request := transport.request
			if request.url != tokenURLs[id] {
				t.Fatalf("URL mismatch\n got: %s\nwant: %s", request.url, tokenURLs[id])
			}
			wantMethod := http.MethodPost
			if id == "wechat" {
				wantMethod = http.MethodGet
			}
			if request.method != wantMethod {
				t.Fatalf("method = %s, want %s", request.method, wantMethod)
			}
			if request.body != bodies[id] {
				t.Fatalf("body mismatch\n got: %s\nwant: %s", request.body, bodies[id])
			}
			if id != "wechat" && request.headers.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Fatalf("content-type = %q", request.headers.Get("Content-Type"))
			}
			if basic[id] && request.headers.Get("Authorization") != "Basic Y2xpZW50OnNlY3JldA==" {
				t.Fatalf("authorization = %q", request.headers.Get("Authorization"))
			}
			if id == "reddit" {
				if request.headers.Get("Accept") != "text/plain" || request.headers.Get("User-Agent") != "single-auth" {
					t.Fatalf("Reddit headers mismatch: %#v", request.headers)
				}
			}
			if id == "paypal" && (request.headers.Get("Accept-Language") != "en_US" || request.headers.Get("Accept") != "application/json") {
				t.Fatalf("PayPal headers mismatch: %#v", request.headers)
			}
		})
	}
}
