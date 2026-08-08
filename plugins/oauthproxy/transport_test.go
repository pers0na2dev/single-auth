package oauthproxy

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func TestProxyCallbackWireContractAcrossNetHTTPFastHTTPAndFiber(t *testing.T) {
	newAuth := func(t *testing.T) *singleauth.Auth {
		t.Helper()
		return testAuth(t, previewBase, previewSecret, Options{},
			singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	}
	target := "/api/auth/oauth-proxy-callback?callbackURL=" + url.QueryEscape("/dashboard")
	assert := func(t *testing.T, status int, location string) {
		t.Helper()
		if status != http.StatusFound || !strings.Contains(location, "error=missing_profile") {
			t.Fatalf("status=%d location=%q", status, location)
		}
	}

	t.Run("net/http", func(t *testing.T) {
		response := exchange(t, newAuth(t), http.MethodGet, previewBase+target, nil, nil)
		assert(t, response.Status, response.Header.Get("Location"))
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(newAuth(t).Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodGet)
		request.Header.SetHost("preview.example.com")
		request.SetRequestURI(target)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		assert(t, requestContext.Response.StatusCode(), string(requestContext.Response.Header.Peek("Location")))
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(newAuth(t).Dispatcher()))
		request, err := http.NewRequest(http.MethodGet, previewBase+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if _, err := io.ReadAll(response.Body); err != nil {
			t.Fatal(err)
		}
		assert(t, response.StatusCode, response.Header.Get("Location"))
	})
}
