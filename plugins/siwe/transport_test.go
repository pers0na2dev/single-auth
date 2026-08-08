package siwe

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
	"github.com/pers0na2dev/single-auth/core/engine"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

func TestDirectNetHTTPFastHTTPAndFiberSIWEFlow(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		nonceBody := mustJSON(t, map[string]any{"walletAddress": testWalletAddress, "chainId": 1})
		nonceResponse, err := auth.Invoke("getSiweNonce", engine.DirectInput{Request: contract.NewRequest(
			http.MethodPost, "/api/auth/siwe/nonce", contract.RequestOptions{
				Scheme: "http", Host: "localhost:3000", Body: nonceBody,
			},
		)})
		if err != nil || nonceResponse.Status() != http.StatusOK {
			t.Fatalf("nonce status=%d err=%v body=%s", nonceResponse.Status(), err, nonceResponse.Body())
		}
		verifyBody := mustJSON(t, validVerifyBody())
		verifyResponse, err := auth.Invoke("verifySiweMessage", engine.DirectInput{Request: contract.NewRequest(
			http.MethodPost, "/api/auth/siwe/verify", contract.RequestOptions{
				Scheme: "http", Host: "localhost:3000", Body: verifyBody,
			},
		)})
		assertTransportSuccess(t, verifyResponse.Status(), verifyResponse.Body(), verifyResponse.Headers().Values("Set-Cookie"))
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("net/http", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		handler := nethttptransport.NewHandler(auth.Dispatcher())
		callNetHTTPTransport(t, handler, "/siwe/nonce", map[string]any{
			"walletAddress": testWalletAddress, "chainId": 1,
		}, http.StatusOK)
		response := callNetHTTPTransport(t, handler, "/siwe/verify", validVerifyBody(), http.StatusOK)
		assertTransportSuccess(t, response.Code, response.Body.Bytes(), response.Header().Values("Set-Cookie"))
	})

	t.Run("fasthttp", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		callFastHTTPTransport(t, handler, "/siwe/nonce", map[string]any{
			"walletAddress": testWalletAddress, "chainId": 1,
		}, http.StatusOK)
		status, body, cookies := callFastHTTPTransport(t, handler, "/siwe/verify", validVerifyBody(), http.StatusOK)
		assertTransportSuccess(t, status, body, cookies)
	})

	t.Run("fiber", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		callFiberTransport(t, app, "/siwe/nonce", map[string]any{
			"walletAddress": testWalletAddress, "chainId": 1,
		}, http.StatusOK)
		status, body, cookies := callFiberTransport(t, app, "/siwe/verify", validVerifyBody(), http.StatusOK)
		assertTransportSuccess(t, status, body, cookies)
	})
}

func validVerifyBody() map[string]any {
	return map[string]any{
		"message": testMessage(testMessageOptions{}), "signature": "valid_signature",
		"walletAddress": testWalletAddress, "chainId": 1,
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func callNetHTTPTransport(
	t *testing.T, handler http.Handler, path string, body map[string]any, expected int,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(
		http.MethodPost, "http://localhost:3000/api/auth"+path,
		bytes.NewReader(mustJSON(t, body)),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != expected {
		t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
	}
	return response
}

func callFastHTTPTransport(
	t *testing.T, handler fasthttpserver.RequestHandler, path string,
	body map[string]any, expected int,
) (int, []byte, []string) {
	t.Helper()
	var request fasthttpserver.Request
	request.Header.SetMethod(http.MethodPost)
	request.Header.SetContentType("application/json")
	request.SetRequestURI("http://localhost:3000/api/auth" + path)
	request.SetBody(mustJSON(t, body))
	var requestContext fasthttpserver.RequestCtx
	requestContext.Init(&request, nil, nil)
	handler(&requestContext)
	status := requestContext.Response.StatusCode()
	responseBody := append([]byte(nil), requestContext.Response.Body()...)
	cookies := make([]string, 0)
	requestContext.Response.Header.VisitAllCookie(func(_, value []byte) {
		cookies = append(cookies, string(value))
	})
	if status != expected {
		t.Fatalf("%s status=%d body=%s", path, status, responseBody)
	}
	return status, responseBody, cookies
}

func callFiberTransport(
	t *testing.T, app *fiberframework.App, path string, body map[string]any, expected int,
) (int, []byte, []string) {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost, "http://localhost:3000/api/auth"+path,
		bytes.NewReader(mustJSON(t, body)),
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
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != expected {
		t.Fatalf("%s status=%d body=%s", path, response.StatusCode, responseBody)
	}
	return response.StatusCode, responseBody, response.Header.Values("Set-Cookie")
}

func assertTransportSuccess(t *testing.T, status int, body []byte, cookies []string) {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || decoded["success"] != true || decoded["token"] == "" {
		t.Fatalf("status=%d body=%#v", status, decoded)
	}
	if len(cookies) == 0 {
		t.Fatal("successful transport response omitted Set-Cookie")
	}
}
