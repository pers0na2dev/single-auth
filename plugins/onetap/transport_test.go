package onetap

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
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func TestDirectNetHTTPFastHTTPAndFiberCallback(t *testing.T) {
	claims := defaultClaims()
	auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
		VerifyIDToken: claimsVerifier(claims, nil),
	}, singleauth.AccountLinkingOptions{})
	body, err := json.Marshal(map[string]any{"idToken": "stub-id-token"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("direct", func(t *testing.T) {
		request := contract.NewRequest(
			http.MethodPost, "/api/auth/one-tap/callback",
			contract.RequestOptions{
				Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
				Body:    body,
			},
		)
		response, err := auth.Invoke("oneTapCallback", engine.DirectInput{Request: request})
		if err != nil {
			t.Fatal(err)
		}
		assertTransportResponse(t, response.Status(), response.Body())
	})

	t.Run("net/http", func(t *testing.T) {
		request := httptest.NewRequest(
			http.MethodPost, "http://localhost:3000/api/auth/one-tap/callback", bytes.NewReader(body),
		)
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		auth.Handler().ServeHTTP(recorder, request)
		assertTransportResponse(t, recorder.Code, recorder.Body.Bytes())
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodPost)
		request.Header.SetContentType("application/json")
		request.SetRequestURI("http://localhost:3000/api/auth/one-tap/callback")
		request.SetBody(body)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		assertTransportResponse(t, requestContext.Response.StatusCode(), requestContext.Response.Body())
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(
			http.MethodPost, "http://localhost:3000/api/auth/one-tap/callback", bytes.NewReader(body),
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		encoded, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertTransportResponse(t, response.StatusCode, encoded)
	})
}

func assertTransportResponse(t *testing.T, status int, body []byte) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if token(decoded) == "" || userID(decoded) == "" {
		t.Fatalf("callback response = %#v", decoded)
	}
}
