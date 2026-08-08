package phonenumber

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
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type transportCall func(method, path, endpoint string, body map[string]any) (int, map[string]any)

func TestDirectNetHTTPFastHTTPAndFiberFullPhoneFlow(t *testing.T) {
	tests := []struct {
		name string
		make func(*testing.T, *singleauth.Auth) transportCall
	}{
		{"direct", directTransport},
		{"net/http", netHTTPTransport},
		{"fasthttp", fastHTTPTransport},
		{"fiber", fiberTransport},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newCaptureStore()
			auth, _ := newRootHarness(t, standardOptions(store), nil)
			call := test.make(t, auth)
			phone := "+1555123000" + string(rune('0'+index))

			status, sent := call(http.MethodPost, "/phone-number/send-otp", "sendPhoneNumberOTP", map[string]any{
				"phoneNumber": phone,
			})
			if status != http.StatusOK || sent["message"] != "code sent" {
				t.Fatalf("send status=%d body=%#v", status, sent)
			}
			status, verified := call(http.MethodPost, "/phone-number/verify", "verifyPhoneNumber", map[string]any{
				"phoneNumber": phone, "code": store.code(phone), "disableSession": true,
			})
			if status != http.StatusOK || verified["status"] != true || verified["token"] != nil {
				t.Fatalf("verify status=%d body=%#v", status, verified)
			}
			status, requested := call(
				http.MethodPost, "/phone-number/request-password-reset", "requestPasswordResetPhoneNumber",
				map[string]any{"phoneNumber": phone},
			)
			if status != http.StatusOK || requested["status"] != true {
				t.Fatalf("request reset status=%d body=%#v", status, requested)
			}
			status, reset := call(
				http.MethodPost, "/phone-number/reset-password", "resetPasswordPhoneNumber",
				map[string]any{"phoneNumber": phone, "otp": store.resetCode(phone), "newPassword": "password123"},
			)
			if status != http.StatusOK || reset["status"] != true {
				t.Fatalf("reset status=%d body=%#v", status, reset)
			}
			status, signedIn := call(http.MethodPost, "/sign-in/phone-number", "signInPhoneNumber", map[string]any{
				"phoneNumber": phone, "password": "password123",
			})
			if status != http.StatusOK || bodyString(t, signedIn, "token") == "" {
				t.Fatalf("sign-in status=%d body=%#v", status, signedIn)
			}
		})
	}
}

func encodeTransportBody(t *testing.T, body map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodeTransportBody(t *testing.T, status int, body []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode status=%d body=%q: %v", status, body, err)
	}
	return value
}

func directTransport(t *testing.T, auth *singleauth.Auth) transportCall {
	t.Helper()
	return func(method, path, endpoint string, body map[string]any) (int, map[string]any) {
		encoded := encodeTransportBody(t, body)
		request := contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
			Scheme: "http", Host: "auth.example.test", Body: encoded,
			Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
		})
		response, _ := auth.Invoke(endpoint, engine.DirectInput{Request: request})
		return response.Status(), decodeTransportBody(t, response.Status(), response.Body())
	}
}

func netHTTPTransport(t *testing.T, auth *singleauth.Auth) transportCall {
	t.Helper()
	return func(method, path, _ string, body map[string]any) (int, map[string]any) {
		encoded := encodeTransportBody(t, body)
		request := httptest.NewRequest(method, testBaseURL+"/api/auth"+path, bytes.NewReader(encoded))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		auth.Handler().ServeHTTP(recorder, request)
		return recorder.Code, decodeTransportBody(t, recorder.Code, recorder.Body.Bytes())
	}
}

func fastHTTPTransport(t *testing.T, auth *singleauth.Auth) transportCall {
	t.Helper()
	handler := fasthttptransport.NewHandler(auth.Dispatcher())
	return func(method, path, _ string, body map[string]any) (int, map[string]any) {
		encoded := encodeTransportBody(t, body)
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.Header.SetContentType("application/json")
		request.SetRequestURI(testBaseURL + "/api/auth" + path)
		request.SetBody(encoded)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		status := requestContext.Response.StatusCode()
		return status, decodeTransportBody(t, status, requestContext.Response.Body())
	}
}

func fiberTransport(t *testing.T, auth *singleauth.Auth) transportCall {
	t.Helper()
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(auth.Dispatcher()))
	return func(method, path, _ string, body map[string]any) (int, map[string]any) {
		encoded := encodeTransportBody(t, body)
		request, err := http.NewRequest(method, testBaseURL+"/api/auth"+path, bytes.NewReader(encoded))
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
		return response.StatusCode, decodeTransportBody(t, response.StatusCode, responseBody)
	}
}
