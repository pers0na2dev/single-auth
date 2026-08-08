package passkey_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/passkey"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func TestPasskeyPreAuthRegistrationThroughRealNetHTTPServer(t *testing.T) {
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost",
		Secret:  "0123456789abcdef0123456789abcdef",
		TrustedOrigins: []string{
			"http://localhost:*",
		},
		PluginFactories: []singleauth.PluginFactory{passkey.NewFactory(passkey.Options{
			Registration: passkey.RegistrationOptions{
				RequireSession: passkey.Bool(false),
				ResolveUser: func(arguments passkey.ResolveRegistrationUserArgs) (passkey.RegistrationUser, error) {
					value := "unknown"
					if arguments.Context != nil {
						value = *arguments.Context
					}
					return passkey.RegistrationUser{
						ID: "user-" + value, Name: value, DisplayName: "Pre-auth " + value,
					}, nil
				},
			},
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(auth)
	defer server.Close()
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	contextValue := "preauth@example.com"
	origin := "http://localhost:" + address.Port()
	request, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet,
		origin+"/api/auth/passkey/generate-register-options?context="+url.QueryEscape(contextValue), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", origin)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode status=%d body=%q: %v", response.StatusCode, body, err)
	}
	user, _ := payload["user"].(map[string]any)
	challenge, _ := payload["challenge"].(string)
	if response.StatusCode != http.StatusOK || user["name"] != contextValue ||
		user["displayName"] != "Pre-auth "+contextValue || challenge == "" {
		t.Fatalf("status=%d payload=%#v", response.StatusCode, payload)
	}
	if !strings.Contains(response.Header.Get("Set-Cookie"), "single-auth-passkey") {
		t.Fatalf("Set-Cookie=%#v", response.Header.Values("Set-Cookie"))
	}
}

func TestPasskeyOptionsAcrossDirectNetHTTPFastHTTPAndFiber(t *testing.T) {
	newAuth := func(t *testing.T) *singleauth.Auth {
		t.Helper()
		auth, err := singleauth.New(singleauth.Options{
			AppName: "Transport App", BaseURL: "http://auth.example.test",
			Secret:          "0123456789abcdef0123456789abcdef",
			PluginFactories: []singleauth.PluginFactory{passkey.NewFactory(passkey.Options{})},
		})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}
	assert := func(t *testing.T, status int, body []byte, cookies []string) {
		t.Helper()
		var response map[string]any
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("decode status=%d body=%q: %v", status, body, err)
		}
		challenge, _ := response["challenge"].(string)
		if status != http.StatusOK || challenge == "" || response["rpId"] != "auth.example.test" {
			t.Fatalf("status=%d response=%#v", status, response)
		}
		if len(cookies) != 1 || !strings.HasPrefix(cookies[0], "single-auth.single-auth-passkey=") {
			t.Fatalf("Set-Cookie=%#v", cookies)
		}
	}

	t.Run("direct", func(t *testing.T) {
		result, err := newAuth(t).API().Call(t.Context(), "generatePasskeyAuthenticationOptions", singleauth.DirectCallInput{
			Method: http.MethodGet, Scheme: "http", Host: "auth.example.test",
		})
		if err != nil {
			t.Fatal(err)
		}
		assert(t, result.Response.Status(), result.Response.Body(), result.Response.Headers().Values("Set-Cookie"))
	})

	t.Run("net/http", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/passkey/generate-authenticate-options", nil)
		recorder := httptest.NewRecorder()
		newAuth(t).ServeHTTP(recorder, request)
		assert(t, recorder.Code, recorder.Body.Bytes(), recorder.Header().Values("Set-Cookie"))
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(newAuth(t).Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodGet)
		request.Header.SetHost("auth.example.test")
		request.SetRequestURI("/api/auth/passkey/generate-authenticate-options")
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		cookies := make([]string, 0, 1)
		requestContext.Response.Header.VisitAllCookie(func(_, value []byte) {
			cookies = append(cookies, string(value))
		})
		assert(t, requestContext.Response.StatusCode(), requestContext.Response.Body(), cookies)
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(newAuth(t).Dispatcher()))
		request, err := http.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/passkey/generate-authenticate-options", nil)
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
		assert(t, response.StatusCode, body, response.Header.Values("Set-Cookie"))
	})
}
