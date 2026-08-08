package captcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/engine"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

const missingResponseBody = `{"message":"Missing CAPTCHA response","code":"MISSING_RESPONSE"}`

func transportTestDispatcher(t *testing.T) *engine.Dispatcher {
	t.Helper()
	return testDispatcher(t, Options{
		Provider:  CloudflareTurnstile,
		SecretKey: "secret",
		Runtime: Runtime{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
			return jsonProviderResponse(http.StatusOK, `{"success":true}`), nil
		})},
	})
}

func TestNetHTTPFastHTTPAndFiberEnforceCaptcha(t *testing.T) {
	t.Run("net/http", func(t *testing.T) {
		handler := nethttptransport.NewHandler(transportTestDispatcher(t))
		request := httptest.NewRequest(http.MethodPost, "http://auth.test/api/auth/sign-in/email", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		assertTransportCaptchaResponse(t, recorder.Code, recorder.Body.Bytes())
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(transportTestDispatcher(t))
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodPost)
		request.SetRequestURI("http://auth.test/api/auth/sign-in/email")
		var ctx fasthttpserver.RequestCtx
		ctx.Init(&request, nil, nil)
		handler(&ctx)
		assertTransportCaptchaResponse(t, ctx.Response.StatusCode(), ctx.Response.Body())
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(transportTestDispatcher(t)))
		request, err := http.NewRequest(http.MethodPost, "http://auth.test/api/auth/sign-in/email", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertTransportCaptchaResponse(t, response.StatusCode, body)
	})
}

func TestAllTransportsAllowAValidCaptcha(t *testing.T) {
	t.Run("net/http", func(t *testing.T) {
		handler := nethttptransport.NewHandler(transportTestDispatcher(t))
		request := httptest.NewRequest(http.MethodPost, "http://auth.test/api/auth/sign-in/email", nil)
		request.Header.Set("x-captcha-response", "token")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(transportTestDispatcher(t))
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodPost)
		request.Header.Set("x-captcha-response", "token")
		request.SetRequestURI("http://auth.test/api/auth/sign-in/email")
		var ctx fasthttpserver.RequestCtx
		ctx.Init(&request, nil, nil)
		handler(&ctx)
		if ctx.Response.StatusCode() != http.StatusNoContent {
			t.Fatalf("status=%d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
		}
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(transportTestDispatcher(t)))
		request, err := http.NewRequest(http.MethodPost, "http://auth.test/api/auth/sign-in/email", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("x-captcha-response", "token")
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("status=%d body=%s", response.StatusCode, body)
		}
	})
}

func assertTransportCaptchaResponse(t *testing.T, status int, body []byte) {
	t.Helper()
	if status != http.StatusBadRequest || string(body) != missingResponseBody {
		t.Fatalf("status=%d body=%q", status, body)
	}
}
