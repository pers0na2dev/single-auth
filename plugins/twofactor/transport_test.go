package twofactor

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/contract"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type transportExchange func(method, path, cookie string, body any) testResult

func TestDirectNetHTTPFastHTTPAndFiberTwoFactorFlow(t *testing.T) {
	tests := []struct {
		name     string
		exchange func(*testing.T, enrolledHarness) transportExchange
	}{
		{name: "direct", exchange: func(t *testing.T, h enrolledHarness) transportExchange {
			return func(method, path, cookie string, body any) testResult {
				name := map[string]string{
					"/sign-in/email":         "signInEmail",
					"/two-factor/send-otp":   "sendTwoFactorOTP",
					"/two-factor/verify-otp": "verifyTwoFactorOTP",
				}[path]
				return invoke(t, h.auth, name, method, path, cookie, body)
			}
		}},
		{name: "net/http", exchange: netHTTPExchange},
		{name: "fasthttp", exchange: fastHTTPExchange},
		{name: "fiber", exchange: fiberExchange},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := &otpCapture{}
			h := setupEnrolled(t, Options{OTP: OTPOptions{SendOTP: capture.send}}, nil)
			exchange := test.exchange(t, h)
			challenge := exchange(http.MethodPost, "/sign-in/email", "", map[string]any{
				"email": testEmail, "password": testPass,
			})
			if challenge.status != http.StatusOK || challenge.body["twoFactorRedirect"] != true {
				t.Fatalf("challenge=%d %#v raw=%s", challenge.status, challenge.body, challenge.raw)
			}
			assertOnlyExpiredSessionCookies(t, challenge.headers.Values("Set-Cookie"))
			sent := exchange(http.MethodPost, "/two-factor/send-otp", challenge.cookie, map[string]any{})
			if sent.status != http.StatusOK || capture.get() == "" {
				t.Fatalf("send=%d %#v code=%q", sent.status, sent.body, capture.get())
			}
			verified := exchange(http.MethodPost, "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": capture.get()})
			if verified.status != http.StatusOK || verified.body["token"] == "" ||
				responseCookie(verified.headers.Values("Set-Cookie"), "session_token") == nil {
				t.Fatalf("verify=%d %#v cookies=%#v", verified.status, verified.body, verified.headers.Values("Set-Cookie"))
			}
		})
	}
}

func netHTTPExchange(t *testing.T, h enrolledHarness) transportExchange {
	t.Helper()
	handler := nethttptransport.NewHandler(h.auth.Dispatcher())
	return func(method, path, cookie string, body any) testResult {
		raw, _ := json.Marshal(body)
		request := httptest.NewRequest(method, testBaseURL+"/api/auth"+path, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
			request.Header.Set("Origin", testBaseURL)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		headers := contract.Headers{}
		for name, values := range recorder.Header() {
			for _, value := range values {
				headers.Add(name, value)
			}
		}
		return decodeResult(t, contract.NewResponse(recorder.Code, headers, recorder.Body.Bytes()), cookie, nil)
	}
}

func fastHTTPExchange(t *testing.T, h enrolledHarness) transportExchange {
	t.Helper()
	handler := fasthttptransport.NewHandler(h.auth.Dispatcher())
	return func(method, path, cookie string, body any) testResult {
		raw, _ := json.Marshal(body)
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.Header.SetContentType("application/json")
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
			request.Header.Set("Origin", testBaseURL)
		}
		request.SetRequestURI(testBaseURL + "/api/auth" + path)
		request.SetBody(raw)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		headers := contract.Headers{}
		requestContext.Response.Header.VisitAll(func(name, value []byte) {
			if string(name) != "Set-Cookie" {
				headers.Add(string(name), string(value))
			}
		})
		requestContext.Response.Header.VisitAllCookie(func(_, value []byte) {
			headers.Add("Set-Cookie", string(value))
		})
		return decodeResult(t, contract.NewResponse(
			requestContext.Response.StatusCode(), headers, requestContext.Response.Body(),
		), cookie, nil)
	}
}

func fiberExchange(t *testing.T, h enrolledHarness) transportExchange {
	t.Helper()
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(h.auth.Dispatcher()))
	return func(method, path, cookie string, body any) testResult {
		raw, _ := json.Marshal(body)
		request, err := http.NewRequest(method, testBaseURL+"/api/auth"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
			request.Header.Set("Origin", testBaseURL)
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
		headers := contract.Headers{}
		for name, values := range response.Header {
			for _, value := range values {
				headers.Add(name, value)
			}
		}
		return decodeResult(t, contract.NewResponse(response.StatusCode, headers, responseBody), cookie, nil)
	}
}
