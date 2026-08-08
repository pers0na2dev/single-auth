package oauthprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type oauthServerTransportResponse struct {
	status  int
	headers http.Header
	body    []byte
}

type oauthServerRoundTrip func(method, target string, body []byte, headers http.Header) oauthServerTransportResponse

func TestOAuthAuthorizationServerAcrossNetHTTPFastHTTPAndFiber(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T, *serverIntegrationHarness) oauthServerRoundTrip
	}{
		{name: "net/http", build: oauthServerNetHTTPRoundTrip},
		{name: "fasthttp", build: oauthServerFastHTTPRoundTrip},
		{name: "fiber", build: oauthServerFiberRoundTrip},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newServerIntegrationHarness(t, nil)
			assertOAuthServerTransportFlow(t, test.build(t, harness), harness.cookie)
		})
	}
}

func assertOAuthServerTransportFlow(t *testing.T, roundTrip oauthServerRoundTrip, sessionCookie string) {
	t.Helper()
	metadata := roundTrip(http.MethodGet, "/api/auth/.well-known/openid-configuration", nil, nil)
	if metadata.status != http.StatusOK || !bytes.Contains(metadata.body, []byte(`"authorization_endpoint"`)) ||
		!bytes.Contains(metadata.body, []byte(`"introspection_endpoint"`)) {
		t.Fatalf("metadata status=%d body=%s", metadata.status, metadata.body)
	}

	redirectURI := "http://127.0.0.1:4521/callback"
	created := roundTrip(http.MethodPost, "/api/auth"+CreateClientPath, []byte(`{
		"client_name":"transport client",
		"redirect_uris":["`+redirectURI+`"],
		"scope":"openid email offline_access read:data write:data",
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"token_endpoint_auth_method":"client_secret_basic",
		"type":"web"
	}`), http.Header{
		"Content-Type": {"application/json"}, "Cookie": {sessionCookie},
	})
	if created.status != http.StatusCreated || created.headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("create client status=%d headers=%#v body=%s", created.status, created.headers, created.body)
	}
	var client map[string]any
	if err := json.Unmarshal(created.body, &client); err != nil {
		t.Fatal(err)
	}
	clientID, _ := client["client_id"].(string)
	clientSecret, _ := client["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		t.Fatalf("created client=%#v", client)
	}

	verifier := strings.Repeat("t", 64)
	authorizationQuery := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid email offline_access read:data write:data"}, "state": {"transport-state"},
		"code_challenge": {serverPKCEChallenge(verifier)}, "code_challenge_method": {"S256"},
	}
	authorized := roundTrip(http.MethodGet, "/api/auth"+AuthorizePath+"?"+authorizationQuery.Encode(), nil, http.Header{"Cookie": {sessionCookie}})
	if authorized.status != http.StatusFound {
		t.Fatalf("authorize status=%d headers=%#v body=%s", authorized.status, authorized.headers, authorized.body)
	}
	consentURL, err := url.Parse(authorized.headers.Get("Location"))
	if err != nil || consentURL.Path != "/consent" || consentURL.Query().Get("oauth_query") == "" {
		t.Fatalf("consent redirect=%q err=%v", authorized.headers.Get("Location"), err)
	}
	consentBody, _ := json.Marshal(map[string]any{
		"accept": true, "oauth_query": consentURL.Query().Get("oauth_query"),
		"scope": "openid email offline_access read:data",
	})
	consented := roundTrip(http.MethodPost, "/api/auth"+ConsentPath, consentBody, http.Header{
		"Content-Type": {"application/json"}, "Cookie": {sessionCookie},
	})
	if consented.status != http.StatusOK {
		t.Fatalf("consent status=%d body=%s", consented.status, consented.body)
	}
	var consentResult map[string]any
	if err := json.Unmarshal(consented.body, &consentResult); err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(consentResult["redirect_uri"].(string))
	if err != nil || callback.Query().Get("state") != "transport-state" || callback.Query().Get("code") == "" {
		t.Fatalf("authorization callback=%#v err=%v", consentResult, err)
	}

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {callback.Query().Get("code")}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}
	token := roundTrip(http.MethodPost, "/api/auth"+TokenPath, []byte(tokenForm.Encode()), http.Header{
		"Authorization": {basic}, "Content-Type": {"application/x-www-form-urlencoded"},
	})
	if token.status != http.StatusOK || token.headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("token status=%d headers=%#v body=%s", token.status, token.headers, token.body)
	}
	var tokenSet map[string]any
	if err := json.Unmarshal(token.body, &tokenSet); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := tokenSet["access_token"].(string)
	refreshToken, _ := tokenSet["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" || tokenSet["id_token"] == "" || tokenSet["scope"] != "openid email offline_access read:data" {
		t.Fatalf("token set=%#v", tokenSet)
	}

	userInfo := roundTrip(http.MethodGet, "/api/auth"+UserInfoPath, nil, http.Header{"Authorization": {"Bearer " + accessToken}})
	if userInfo.status != http.StatusOK || !bytes.Contains(userInfo.body, []byte(`"email":"oauth-server@test.invalid"`)) {
		t.Fatalf("userinfo status=%d body=%s", userInfo.status, userInfo.body)
	}
	introspectionForm := url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}}
	introspection := roundTrip(http.MethodPost, "/api/auth"+IntrospectPath, []byte(introspectionForm.Encode()), http.Header{
		"Authorization": {basic}, "Content-Type": {"application/x-www-form-urlencoded"},
	})
	if introspection.status != http.StatusOK || !bytes.Contains(introspection.body, []byte(`"active":true`)) {
		t.Fatalf("introspection status=%d body=%s", introspection.status, introspection.body)
	}

	refreshForm := url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID},
		"refresh_token": {refreshToken}, "scope": {"openid email read:data"},
	}
	refreshed := roundTrip(http.MethodPost, "/api/auth"+TokenPath, []byte(refreshForm.Encode()), http.Header{
		"Authorization": {basic}, "Content-Type": {"application/x-www-form-urlencoded"},
	})
	if refreshed.status != http.StatusOK || !bytes.Contains(refreshed.body, []byte(`"scope":"openid email read:data"`)) {
		t.Fatalf("refresh status=%d body=%s", refreshed.status, refreshed.body)
	}

	revokeForm := url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}}
	revoked := roundTrip(http.MethodPost, "/api/auth"+RevokePath, []byte(revokeForm.Encode()), http.Header{
		"Authorization": {basic}, "Content-Type": {"application/x-www-form-urlencoded"},
	})
	if revoked.status != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoked.status, revoked.body)
	}
	inactive := roundTrip(http.MethodPost, "/api/auth"+IntrospectPath, []byte(introspectionForm.Encode()), http.Header{
		"Authorization": {basic}, "Content-Type": {"application/x-www-form-urlencoded"},
	})
	if inactive.status != http.StatusOK || !bytes.Contains(inactive.body, []byte(`"active":false`)) {
		t.Fatalf("inactive introspection status=%d body=%s", inactive.status, inactive.body)
	}
}

func oauthServerNetHTTPRoundTrip(t *testing.T, harness *serverIntegrationHarness) oauthServerRoundTrip {
	t.Helper()
	handler := nethttptransport.NewHandler(harness.auth.Dispatcher())
	return func(method, target string, body []byte, headers http.Header) oauthServerTransportResponse {
		request := httptest.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
		request.Header.Set("Origin", "http://localhost:3000")
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return oauthServerTransportResponse{status: recorder.Code, headers: recorder.Header().Clone(), body: recorder.Body.Bytes()}
	}
}

func oauthServerFastHTTPRoundTrip(t *testing.T, harness *serverIntegrationHarness) oauthServerRoundTrip {
	t.Helper()
	handler := fasthttptransport.NewHandler(harness.auth.Dispatcher())
	return func(method, target string, body []byte, headers http.Header) oauthServerTransportResponse {
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.Header.Set("Origin", "http://localhost:3000")
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		request.SetBody(body)
		request.SetRequestURI("http://localhost:3000" + target)
		var ctx fasthttpserver.RequestCtx
		ctx.Init(&request, nil, nil)
		handler(&ctx)
		responseHeaders := make(http.Header)
		ctx.Response.Header.VisitAll(func(key, value []byte) { responseHeaders.Add(string(key), string(value)) })
		return oauthServerTransportResponse{
			status: ctx.Response.StatusCode(), headers: responseHeaders,
			body: append([]byte(nil), ctx.Response.Body()...),
		}
	}
}

func oauthServerFiberRoundTrip(t *testing.T, harness *serverIntegrationHarness) oauthServerRoundTrip {
	t.Helper()
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(harness.auth.Dispatcher()))
	return func(method, target string, body []byte, headers http.Header) oauthServerTransportResponse {
		request, err := http.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", "http://localhost:3000")
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return oauthServerTransportResponse{status: response.StatusCode, headers: response.Header.Clone(), body: responseBody}
	}
}
