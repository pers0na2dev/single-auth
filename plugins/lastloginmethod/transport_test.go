package lastloginmethod

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func TestLastLoginMethodAcrossDirectNetHTTPFastHTTPAndFiber(t *testing.T) {
	newAuth := func(t *testing.T) *singleauth.Auth {
		t.Helper()
		auth, err := singleauth.New(singleauth.Options{
			BaseURL: "http://auth.example.test", Secret: integrationSecret,
			EmailAndPassword: fastEmailPasswordOptions(),
			PluginFactories:  []singleauth.PluginFactory{NewFactory(Options{})},
		})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}
	assert := func(t *testing.T, status int, headers contract.Headers) {
		t.Helper()
		response := contract.NewResponse(status, headers, nil)
		cookie, exists := responseCookie(response, DefaultCookieName)
		if status != http.StatusOK || !exists || cookie.Attributes.Value != "email" {
			t.Fatalf("status=%d cookie=%#v headers=%#v", status, cookie, headers.Values("Set-Cookie"))
		}
	}

	t.Run("direct", func(t *testing.T) {
		result, err := newAuth(t).API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
			Name: "Transport User", Email: "transport@example.com", Password: "password123",
		})
		if err != nil {
			t.Fatal(err)
		}
		assert(t, http.StatusOK, result.Headers)
	})

	payload := []byte(`{"name":"Transport User","email":"transport@example.com","password":"password123"}`)
	t.Run("net/http", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "http://auth.example.test/api/auth/sign-up/email", bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://auth.example.test")
		recorder := httptest.NewRecorder()
		newAuth(t).ServeHTTP(recorder, request)
		assert(t, recorder.Code, headersFromHTTP(recorder.Header()))
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(newAuth(t).Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodPost)
		request.Header.SetHost("auth.example.test")
		request.Header.SetContentType("application/json")
		request.Header.Set("Origin", "http://auth.example.test")
		request.SetRequestURI("/api/auth/sign-up/email")
		request.SetBody(payload)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		headers := contract.Headers{}
		requestContext.Response.Header.VisitAll(func(name, value []byte) {
			headers.Add(string(name), string(value))
		})
		assert(t, requestContext.Response.StatusCode(), headers)
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(newAuth(t).Dispatcher()))
		request, err := http.NewRequest(http.MethodPost, "http://auth.example.test/api/auth/sign-up/email", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://auth.example.test")
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if _, err := io.ReadAll(response.Body); err != nil {
			t.Fatal(err)
		}
		assert(t, response.StatusCode, headersFromHTTP(response.Header))
	})
}
