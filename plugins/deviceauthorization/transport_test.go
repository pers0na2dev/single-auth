package deviceauthorization

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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

type transportRoundTrip func(method, target string, body []byte) transportResponse

func TestNetHTTPFastHTTPAndFiberDeviceAuthorizationRoutes(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T, *deviceHarness) transportRoundTrip
	}{
		{name: "net/http", build: netHTTPRoundTrip},
		{name: "fasthttp", build: fastHTTPRoundTrip},
		{name: "fiber", build: fiberRoundTrip},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newDeviceHarness(t, nil)
			roundTrip := test.build(t, harness)
			assertAllTransportRoutes(t, roundTrip)
		})
	}
}

func assertAllTransportRoutes(t *testing.T, roundTrip transportRoundTrip) {
	t.Helper()
	codeResponse := roundTrip(http.MethodPost, "/api/auth/device/code", []byte(`{"client_id":"transport-client"}`))
	if codeResponse.status != http.StatusOK {
		t.Fatalf("device code status=%d body=%s", codeResponse.status, codeResponse.body)
	}
	if codeResponse.headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("device code Cache-Control=%q", codeResponse.headers.Get("Cache-Control"))
	}
	var code DeviceCodeResponse
	if err := json.Unmarshal(codeResponse.body, &code); err != nil {
		t.Fatal(err)
	}

	verify := roundTrip(http.MethodGet, "/api/auth/device?user_code="+code.UserCode, nil)
	if verify.status != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verify.status, verify.body)
	}
	var verified VerifyResponse
	if err := json.Unmarshal(verify.body, &verified); err != nil || verified.Status != "pending" {
		t.Fatalf("verify=%#v err=%v", verified, err)
	}

	approve := roundTrip(http.MethodPost, "/api/auth/device/approve", []byte(`{"userCode":"`+code.UserCode+`"}`))
	assertTransportOAuthError(t, approve, http.StatusUnauthorized, "unauthorized", MessageAuthenticationRequired)
	deny := roundTrip(http.MethodPost, "/api/auth/device/deny", []byte(`{"userCode":"`+code.UserCode+`"}`))
	assertTransportOAuthError(t, deny, http.StatusUnauthorized, "unauthorized", MessageAuthenticationRequired)

	token := roundTrip(http.MethodPost, "/api/auth/device/token", []byte(`{"grant_type":"`+DeviceCodeGrantType+`","device_code":"`+code.DeviceCode+`","client_id":"transport-client"}`))
	assertTransportOAuthError(t, token, http.StatusBadRequest, "authorization_pending", MessageAuthorizationPending)
}

func assertTransportOAuthError(t *testing.T, response transportResponse, status int, code, description string) {
	t.Helper()
	if response.status != status {
		t.Fatalf("status=%d body=%s", response.status, response.body)
	}
	var body OAuthErrorBody
	if err := json.Unmarshal(response.body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != code || body.ErrorDescription != description {
		t.Fatalf("OAuth error = %#v", body)
	}
}

func netHTTPRoundTrip(t *testing.T, harness *deviceHarness) transportRoundTrip {
	t.Helper()
	handler := nethttptransport.NewHandler(harness.auth.Dispatcher())
	return func(method, target string, body []byte) transportResponse {
		request := httptest.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
		request.Header.Set("Origin", "http://localhost:3000")
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return transportResponse{status: recorder.Code, headers: recorder.Header().Clone(), body: recorder.Body.Bytes()}
	}
}

func fastHTTPRoundTrip(t *testing.T, harness *deviceHarness) transportRoundTrip {
	t.Helper()
	handler := fasthttptransport.NewHandler(harness.auth.Dispatcher())
	return func(method, target string, body []byte) transportResponse {
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.Header.Set("Origin", "http://localhost:3000")
		if len(body) > 0 {
			request.Header.SetContentType("application/json")
			request.SetBody(body)
		}
		request.SetRequestURI("http://localhost:3000" + target)
		var ctx fasthttpserver.RequestCtx
		ctx.Init(&request, nil, nil)
		handler(&ctx)
		headers := make(http.Header)
		ctx.Response.Header.VisitAll(func(key, value []byte) {
			headers.Add(string(key), string(value))
		})
		return transportResponse{
			status: ctx.Response.StatusCode(), headers: headers,
			body: append([]byte(nil), ctx.Response.Body()...),
		}
	}
}

func fiberRoundTrip(t *testing.T, harness *deviceHarness) transportRoundTrip {
	t.Helper()
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(harness.auth.Dispatcher()))
	return func(method, target string, body []byte) transportResponse {
		request, err := http.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", "http://localhost:3000")
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
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
