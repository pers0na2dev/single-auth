package username

import (
	"bytes"
	"encoding/json"
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

func TestUsernameAvailabilityAcrossDirectNetHTTPFastHTTPAndFiber(t *testing.T) {
	newAuth := func(t *testing.T) *singleauth.Auth {
		t.Helper()
		return newTestAuth(t, Options{}, singleauth.EmailVerificationOptions{}, false)
	}
	assert := func(t *testing.T, status int, body []byte) {
		t.Helper()
		var response map[string]any
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("decode status=%d body=%q: %v", status, body, err)
		}
		if status != http.StatusOK || response["available"] != true {
			t.Fatalf("status=%d response=%#v", status, response)
		}
	}

	t.Run("direct", func(t *testing.T) {
		result, err := newAuth(t).API().Call(t.Context(), "isUsernameAvailable", singleauth.DirectCallInput{
			Method: http.MethodPost,
			Scheme: "http",
			Host:   "auth.example.test",
			Headers: contract.NewHeaders(
				contract.HeaderField{Name: "Origin", Value: "http://auth.example.test"},
			),
			Body: map[string]any{"username": "available_user"},
		})
		if err != nil {
			t.Fatal(err)
		}
		response, ok := result.Value.(map[string]any)
		if !ok || response["available"] != true {
			t.Fatalf("direct response=%#v", result.Value)
		}
	})

	payload := []byte(`{"username":"available_user"}`)
	t.Run("net/http", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "http://auth.example.test/api/auth/is-username-available", bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://auth.example.test")
		recorder := httptest.NewRecorder()
		newAuth(t).ServeHTTP(recorder, request)
		assert(t, recorder.Code, recorder.Body.Bytes())
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(newAuth(t).Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodPost)
		request.Header.SetHost("auth.example.test")
		request.Header.SetContentType("application/json")
		request.Header.Set("Origin", "http://auth.example.test")
		request.SetRequestURI("/api/auth/is-username-available")
		request.SetBody(payload)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		assert(t, requestContext.Response.StatusCode(), requestContext.Response.Body())
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(newAuth(t).Dispatcher()))
		request, err := http.NewRequest(http.MethodPost, "http://auth.example.test/api/auth/is-username-available", bytes.NewReader(payload))
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
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		assert(t, response.StatusCode, body)
	})
}
