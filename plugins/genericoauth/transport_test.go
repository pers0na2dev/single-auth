package genericoauth

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

const transportValidationBody = `{"code":"VALIDATION_ERROR","message":"[body.providerId] Invalid input: expected string, received undefined"}`

func TestDirectNetHTTPFastHTTPAndFiberExposeGenericOAuthEndpoints(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "transport", "email": "transport@test.com", "name": "Transport",
	})
	auth := genericTestAuth(t, server.config("transport"), nil)
	body := []byte(`{"callbackURL":"http://auth.test/done"}`)

	t.Run("direct", func(t *testing.T) {
		request := contract.NewRequest(http.MethodPost, "/sign-in/oauth2", contract.RequestOptions{
			Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
			Body:    body,
		})
		response, _ := auth.Invoke("signInWithOAuth2", engine.DirectInput{Request: request})
		assertGenericTransportValidation(t, response.Status(), response.Body())
	})

	t.Run("net/http", func(t *testing.T) {
		handler := nethttptransport.NewHandler(auth.Dispatcher())
		request := httptest.NewRequest(http.MethodPost, genericBaseURL+"/api/auth/sign-in/oauth2", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		assertGenericTransportValidation(t, recorder.Code, recorder.Body.Bytes())
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodPost)
		request.Header.SetContentType("application/json")
		request.SetRequestURI(genericBaseURL + "/api/auth/sign-in/oauth2")
		request.SetBody(body)
		var ctx fasthttpserver.RequestCtx
		ctx.Init(&request, nil, nil)
		handler(&ctx)
		assertGenericTransportValidation(t, ctx.Response.StatusCode(), ctx.Response.Body())
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(http.MethodPost, genericBaseURL+"/api/auth/sign-in/oauth2", bytes.NewReader(body))
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
		assertGenericTransportValidation(t, response.StatusCode, encoded)
	})
}

func assertGenericTransportValidation(t *testing.T, status int, body []byte) {
	t.Helper()
	if status != 422 || string(body) != transportValidationBody {
		t.Fatalf("status=%d body=%s", status, body)
	}
}
