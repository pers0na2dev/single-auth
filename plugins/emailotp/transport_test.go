package emailotp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/emailotp"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func newTransportEmailOTPAuth(t *testing.T, sent *emailotp.OTPMessage) *singleauth.Auth {
	t.Helper()
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
		PluginFactories: []singleauth.PluginFactory{emailotp.NewFactory(emailotp.Options{
			GenerateOTP: func(emailotp.OTPData, *engine.Context) (string, error) { return "123456", nil },
			SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
				*sent = message
				return nil
			},
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func encodeTransportBody(t *testing.T, body map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertTransportSignIn(t *testing.T, status int, body []byte, cookies []string) {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode sign-in status=%d body=%s: %v", status, body, err)
	}
	user, _ := result["user"].(map[string]any)
	if status != http.StatusOK || result["token"] == "" || user["email"] != "transport@example.com" ||
		!strings.Contains(strings.Join(cookies, ";"), "single-auth.session_token=") {
		t.Fatalf("sign-in status=%d body=%#v cookies=%q", status, result, cookies)
	}
}

func TestDirectNetHTTPFastHTTPAndFiberEmailOTPFlow(t *testing.T) {
	t.Run("direct API", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newTransportEmailOTPAuth(t, &sent)
		sendBody := encodeTransportBody(t, map[string]any{"email": "transport@example.com", "type": "sign-in"})
		request := contract.NewRequest(http.MethodPost, "/", contract.RequestOptions{
			Body: sendBody, Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
		})
		response, err := auth.Invoke("sendVerificationOTP", engine.DirectInput{Request: request})
		if err != nil || response.Status() != http.StatusOK || sent.OTP != "123456" {
			t.Fatalf("direct send status=%d err=%v body=%s sent=%#v", response.Status(), err, response.Body(), sent)
		}
		signInBody := encodeTransportBody(t, map[string]any{"email": "transport@example.com", "otp": sent.OTP})
		request = contract.NewRequest(http.MethodPost, "/", contract.RequestOptions{
			Body: signInBody, Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
		})
		response, err = auth.Invoke("signInEmailOTP", engine.DirectInput{Request: request})
		if err != nil {
			t.Fatalf("direct sign-in err=%v body=%s", err, response.Body())
		}
		assertTransportSignIn(t, response.Status(), response.Body(), response.Headers().Values("Set-Cookie"))
	})

	t.Run("net/http", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newTransportEmailOTPAuth(t, &sent)
		post := func(path string, body map[string]any) *httptest.ResponseRecorder {
			request := httptest.NewRequest(http.MethodPost, "http://localhost:3000/api/auth"+path, bytes.NewReader(encodeTransportBody(t, body)))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, request)
			return recorder
		}
		response := post("/email-otp/send-verification-otp", map[string]any{"email": "transport@example.com", "type": "sign-in"})
		if response.Code != http.StatusOK || sent.OTP != "123456" {
			t.Fatalf("net/http send status=%d body=%s sent=%#v", response.Code, response.Body.String(), sent)
		}
		response = post("/sign-in/email-otp", map[string]any{"email": "transport@example.com", "otp": sent.OTP})
		assertTransportSignIn(t, response.Code, response.Body.Bytes(), response.Header().Values("Set-Cookie"))
	})

	t.Run("fasthttp", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newTransportEmailOTPAuth(t, &sent)
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		call := func(path string, body map[string]any) (int, []byte, []string) {
			var request fasthttpserver.Request
			request.Header.SetMethod(http.MethodPost)
			request.SetRequestURI("http://localhost:3000/api/auth" + path)
			request.Header.SetContentType("application/json")
			request.SetBody(encodeTransportBody(t, body))
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(&request, nil, nil)
			handler(&requestContext)
			cookieValues := requestContext.Response.Header.PeekAll("Set-Cookie")
			cookies := make([]string, 0, len(cookieValues))
			for _, value := range cookieValues {
				cookies = append(cookies, string(value))
			}
			return requestContext.Response.StatusCode(), append([]byte(nil), requestContext.Response.Body()...), cookies
		}
		status, body, _ := call("/email-otp/send-verification-otp", map[string]any{"email": "transport@example.com", "type": "sign-in"})
		if status != http.StatusOK || sent.OTP != "123456" {
			t.Fatalf("fasthttp send status=%d body=%s sent=%#v", status, body, sent)
		}
		status, body, responseCookies := call("/sign-in/email-otp", map[string]any{"email": "transport@example.com", "otp": sent.OTP})
		assertTransportSignIn(t, status, body, responseCookies)
	})

	t.Run("Fiber", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newTransportEmailOTPAuth(t, &sent)
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		call := func(path string, body map[string]any) (int, []byte, []string) {
			request, err := http.NewRequest(http.MethodPost, "http://localhost:3000/api/auth"+path, bytes.NewReader(encodeTransportBody(t, body)))
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
			return response.StatusCode, encoded, response.Header.Values("Set-Cookie")
		}
		status, body, _ := call("/email-otp/send-verification-otp", map[string]any{"email": "transport@example.com", "type": "sign-in"})
		if status != http.StatusOK || sent.OTP != "123456" {
			t.Fatalf("Fiber send status=%d body=%s sent=%#v", status, body, sent)
		}
		status, body, responseCookies := call("/sign-in/email-otp", map[string]any{"email": "transport@example.com", "otp": sent.OTP})
		assertTransportSignIn(t, status, body, responseCookies)
	})
}
