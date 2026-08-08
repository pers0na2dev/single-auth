package oidcprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type transportResponse struct {
	status  int
	headers http.Header
	body    []byte
}

type transportRoundTrip func(method, target, contentType string, body []byte, headers http.Header) transportResponse

func TestOIDCProviderAcrossNetHTTPFastHTTPAndFiber(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T, *harness) transportRoundTrip
	}{
		{name: "net/http", build: netHTTPRoundTrip},
		{name: "fasthttp", build: fastHTTPRoundTrip},
		{name: "fiber", build: fiberRoundTrip},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newHarness(t, func(options *Options) {
				options.AllowDynamicClientRegistration = true
				options.RequirePKCE = false
			})
			userID, _ := harness.signUp(t, 60)
			seedClient(t, harness, Client{
				ClientID: "transport-client", ClientSecret: "transport-secret", Type: "web",
				Name: "transport", RedirectURLs: []string{"http://localhost/callback"},
			})
			seedAccessToken(
				t, harness, userID, "transport-client", "transport-access", "transport-refresh",
				"openid profile email offline_access", harness.clock.Now().Add(time.Hour),
				harness.clock.Now().Add(24*time.Hour),
			)
			assertTransportSurface(t, test.build(t, harness))
		})
	}
}

func assertTransportSurface(t *testing.T, roundTrip transportRoundTrip) {
	t.Helper()
	discovery := roundTrip(http.MethodGet, "/api/auth"+DiscoveryPath, "", nil, nil)
	if discovery.status != http.StatusOK || !bytes.Contains(discovery.body, []byte(`"authorization_endpoint"`)) ||
		!bytes.Contains(discovery.body, []byte(`"end_session_endpoint"`)) {
		t.Fatalf("discovery status=%d body=%s", discovery.status, discovery.body)
	}
	registered := roundTrip(
		http.MethodPost, "/api/auth"+RegistrationPath, "application/json",
		[]byte(`{"client_name":"transport-dynamic","redirect_uris":["http://localhost/callback"]}`), nil,
	)
	if registered.status != http.StatusCreated || registered.headers.Get("Content-Type") != "application/json" {
		t.Fatalf("register status=%d headers=%#v body=%s", registered.status, registered.headers, registered.body)
	}
	var registration map[string]any
	if err := json.Unmarshal(registered.body, &registration); err != nil || registration["client_id"] == "" {
		t.Fatalf("registration=%#v err=%v", registration, err)
	}
	authorize := roundTrip(
		http.MethodGet,
		"/api/auth"+AuthorizePath+"?client_id="+registration["client_id"].(string)+"&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&state=x",
		"", nil, nil,
	)
	if authorize.status != http.StatusFound || authorize.headers.Get("Location") == "" ||
		len(authorize.headers.Values("Set-Cookie")) == 0 {
		t.Fatalf("authorize status=%d headers=%#v body=%s", authorize.status, authorize.headers, authorize.body)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("transport-client:transport-secret"))
	refreshed := roundTrip(
		http.MethodPost, "/api/auth"+TokenPath, "application/x-www-form-urlencoded",
		[]byte("grant_type=refresh_token&refresh_token=transport-refresh"),
		http.Header{"Authorization": {"Basic " + basic}},
	)
	if refreshed.status != http.StatusOK || !bytes.Contains(refreshed.body, []byte(`"access_token"`)) ||
		!bytes.Contains(refreshed.body, []byte(`"token_type":"Bearer"`)) {
		t.Fatalf("refresh status=%d body=%s", refreshed.status, refreshed.body)
	}
	info := roundTrip(
		http.MethodGet, "/api/auth"+UserInfoPath, "", nil,
		http.Header{"Authorization": {"Bearer transport-access"}},
	)
	if info.status != http.StatusOK || !bytes.Contains(info.body, []byte(`"sub"`)) ||
		!bytes.Contains(info.body, []byte(`"email"`)) {
		t.Fatalf("userinfo status=%d body=%s", info.status, info.body)
	}
	consent := roundTrip(
		http.MethodPost, "/api/auth"+ConsentPath, "application/json", []byte(`{"accept":true}`), nil,
	)
	if consent.status != http.StatusUnauthorized {
		t.Fatalf("consent status=%d body=%s", consent.status, consent.body)
	}
	logout := roundTrip(
		http.MethodPost, "/api/auth"+EndSessionPath, "application/json", nil,
		http.Header{"Sec-Fetch-Site": {"same-origin"}},
	)
	if logout.status != http.StatusOK || !bytes.Contains(logout.body, []byte(`"success":true`)) {
		t.Fatalf("logout status=%d body=%s", logout.status, logout.body)
	}
}

func netHTTPRoundTrip(t *testing.T, harness *harness) transportRoundTrip {
	t.Helper()
	handler := nethttptransport.NewHandler(harness.auth.Dispatcher())
	return func(method, target, contentType string, body []byte, headers http.Header) transportResponse {
		request := httptest.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
		request.Header.Set("Origin", "http://localhost:3000")
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return transportResponse{status: recorder.Code, headers: recorder.Header().Clone(), body: recorder.Body.Bytes()}
	}
}

func fastHTTPRoundTrip(t *testing.T, harness *harness) transportRoundTrip {
	t.Helper()
	handler := fasthttptransport.NewHandler(harness.auth.Dispatcher())
	return func(method, target, contentType string, body []byte, headers http.Header) transportResponse {
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.Header.Set("Origin", "http://localhost:3000")
		if contentType != "" {
			request.Header.SetContentType(contentType)
		}
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
		ctx.Response.Header.VisitAll(func(key, value []byte) {
			responseHeaders.Add(string(key), string(value))
		})
		return transportResponse{
			status: ctx.Response.StatusCode(), headers: responseHeaders,
			body: append([]byte(nil), ctx.Response.Body()...),
		}
	}
}

func fiberRoundTrip(t *testing.T, harness *harness) transportRoundTrip {
	t.Helper()
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(harness.auth.Dispatcher()))
	return func(method, target, contentType string, body []byte, headers http.Header) transportResponse {
		request, err := http.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", "http://localhost:3000")
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
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
		return transportResponse{status: response.StatusCode, headers: response.Header.Clone(), body: responseBody}
	}
}
