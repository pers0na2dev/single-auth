package openapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/openapi"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func newOpenAPITransportAuth(t *testing.T, options openapi.Options) *singleauth.Auth {
	t.Helper()
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:         "http://auth.example.test",
		PluginFactories: []singleauth.PluginFactory{openapi.NewFactory(options)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func assertOpenAPIDocument(t *testing.T, status int, body []byte) {
	t.Helper()
	var document openapi.Document
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("status=%d body=%q err=%v", status, body, err)
	}
	if status != http.StatusOK || document.OpenAPI != "3.1.1" || document.Servers[0].URL != "http://auth.example.test/api/auth" || document.Paths["/get-session"].Get == nil {
		t.Fatalf("status=%d document=%#v", status, document)
	}
}

func TestSchemaEndpointAcrossDirectNetHTTPFastHTTPAndFiber(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		result, err := newOpenAPITransportAuth(t, openapi.Options{}).API().Call(t.Context(), "generateOpenAPISchema", singleauth.DirectCallInput{
			Method: http.MethodGet, Scheme: "http", Host: "auth.example.test",
		})
		if err != nil {
			t.Fatal(err)
		}
		assertOpenAPIDocument(t, result.Response.Status(), result.Response.Body())
	})

	t.Run("net/http", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/open-api/generate-schema", nil)
		recorder := httptest.NewRecorder()
		newOpenAPITransportAuth(t, openapi.Options{}).ServeHTTP(recorder, request)
		assertOpenAPIDocument(t, recorder.Code, recorder.Body.Bytes())
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(newOpenAPITransportAuth(t, openapi.Options{}).Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodGet)
		request.Header.SetHost("auth.example.test")
		request.SetRequestURI("/api/auth/open-api/generate-schema")
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		assertOpenAPIDocument(t, requestContext.Response.StatusCode(), requestContext.Response.Body())
	})

	t.Run("Fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(newOpenAPITransportAuth(t, openapi.Options{}).Dispatcher()))
		request, err := http.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/open-api/generate-schema", nil)
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
		assertOpenAPIDocument(t, response.StatusCode, body)
	})
}

func TestScalarReferenceCustomPathThemeNonceAndDisable(t *testing.T) {
	auth := newOpenAPITransportAuth(t, openapi.Options{Path: "/docs", Theme: "moon", Nonce: "nonce-value"})
	request := httptest.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/docs", nil)
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/html" ||
		!strings.Contains(body, `<script nonce="nonce-value">`) ||
		!strings.Contains(body, `src="https://cdn.jsdelivr.net/npm/@scalar/api-reference" nonce="nonce-value"`) ||
		!strings.Contains(body, `theme: "moon"`) || !strings.Contains(body, `"openapi":"3.1.1"`) {
		t.Fatalf("status=%d content-type=%q body=%s", recorder.Code, recorder.Header().Get("Content-Type"), body)
	}

	disabled := newOpenAPITransportAuth(t, openapi.Options{DisableDefaultReference: true})
	request = httptest.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/reference", nil)
	recorder = httptest.NewRecorder()
	disabled.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("disabled status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
