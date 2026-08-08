package admin

import (
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
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

func TestAdminAcrossDirectNetHTTPFastHTTPAndFiber(t *testing.T) {
	newAuthenticated := func(t *testing.T) (*singleauth.Auth, string) {
		t.Helper()
		auth := newRootAuth(t, Options{})
		identity := signUpIdentity(t, auth, "Admin", "transport-admin@example.com", "password123")
		return auth, identity.Cookie
	}
	assertWire := func(t *testing.T, status int, body []byte) {
		t.Helper()
		var value map[string]any
		if err := json.Unmarshal(body, &value); err != nil {
			t.Fatalf("decode status=%d body=%q: %v", status, body, err)
		}
		users, ok := value["users"].([]any)
		if status != http.StatusOK || !ok || len(users) != 1 {
			t.Fatalf("status=%d value=%#v", status, value)
		}
	}

	t.Run("direct", func(t *testing.T) {
		auth, cookie := newAuthenticated(t)
		result, err := auth.API().Call(t.Context(), "listUsers", singleauth.DirectCallInput{
			Method: http.MethodGet,
			Scheme: "http",
			Host:   "auth.example.test",
			Headers: contract.NewHeaders(
				contract.HeaderField{Name: "Origin", Value: "http://auth.example.test"},
				contract.HeaderField{Name: "Cookie", Value: cookie},
			),
			Query: map[string][]string{"limit": {"10"}},
		})
		if err != nil || result.Response.Status() != http.StatusOK {
			t.Fatalf("status=%d value=%#v err=%v", result.Response.Status(), result.Value, err)
		}
		value, ok := result.Value.(map[string]any)
		users, usersOK := value["users"].([]any)
		if !ok || !usersOK || len(users) != 1 {
			t.Fatalf("direct value=%#v", result.Value)
		}
	})

	t.Run("net/http", func(t *testing.T) {
		auth, cookie := newAuthenticated(t)
		handler := nethttptransport.NewHandler(auth.Dispatcher())
		request := httptest.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/admin/list-users?limit=10", nil)
		request.Header.Set("Origin", "http://auth.example.test")
		request.Header.Set("Cookie", cookie)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		assertWire(t, recorder.Code, recorder.Body.Bytes())
	})

	t.Run("fasthttp", func(t *testing.T) {
		auth, cookie := newAuthenticated(t)
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodGet)
		request.Header.SetHost("auth.example.test")
		request.Header.Set("Origin", "http://auth.example.test")
		request.Header.Set("Cookie", cookie)
		request.SetRequestURI("/api/auth/admin/list-users?limit=10")
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		assertWire(t, requestContext.Response.StatusCode(), requestContext.Response.Body())
	})

	t.Run("fiber", func(t *testing.T) {
		auth, cookie := newAuthenticated(t)
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/admin/list-users?limit=10", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", "http://auth.example.test")
		request.Header.Set("Cookie", cookie)
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertWire(t, response.StatusCode, body)
	})
}
