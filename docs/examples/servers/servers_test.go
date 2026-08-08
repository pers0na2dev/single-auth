package servers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"
)

const testSecret = "documentation-example-secret-that-is-long-enough"

func TestTransportExamplesConstruct(t *testing.T) {
	httpHandler, err := NetHTTP(testSecret)
	if err != nil || httpHandler == nil {
		t.Fatalf("NetHTTP() handler=%v err=%v", httpHandler, err)
	}
	httpRequest := httptest.NewRequest(http.MethodGet, "https://auth.example.com/api/auth/ok", nil)
	httpResponse := httptest.NewRecorder()
	httpHandler.ServeHTTP(httpResponse, httpRequest)
	if httpResponse.Code != http.StatusOK {
		t.Fatalf("net/http GET /ok status = %d, want %d", httpResponse.Code, http.StatusOK)
	}

	fastHandler, err := FastHTTP(testSecret)
	if err != nil || fastHandler == nil {
		t.Fatalf("FastHTTP() handler=%v err=%v", fastHandler, err)
	}
	var fastRequest fasthttpserver.Request
	fastRequest.Header.SetMethod(http.MethodGet)
	fastRequest.Header.SetHost("auth.example.com")
	fastRequest.SetRequestURI("/api/auth/ok")
	var fastContext fasthttpserver.RequestCtx
	fastContext.Init(&fastRequest, nil, nil)
	fastHandler(&fastContext)
	if fastContext.Response.StatusCode() != http.StatusOK {
		t.Fatalf("fasthttp GET /ok status = %d, want %d", fastContext.Response.StatusCode(), http.StatusOK)
	}

	fiberApp, err := Fiber(testSecret)
	if err != nil || fiberApp == nil {
		t.Fatalf("Fiber() app=%v err=%v", fiberApp, err)
	}
	fiberRequest := httptest.NewRequest(http.MethodGet, "https://auth.example.com/api/auth/ok", nil)
	fiberResponse, err := fiberApp.Test(fiberRequest, fiberframework.TestConfig{Timeout: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer fiberResponse.Body.Close()
	if fiberResponse.StatusCode != http.StatusOK {
		t.Fatalf("Fiber GET /ok status = %d, want %d", fiberResponse.StatusCode, http.StatusOK)
	}
}
