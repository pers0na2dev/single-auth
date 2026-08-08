package customsession

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

const (
	integrationBaseURL = "https://auth.example.test"
	integrationSecret  = "0123456789abcdef0123456789abcdef"
)

func TestRootFactoryReplacesCoreGetSessionAndPreservesRefresh(t *testing.T) {
	var callbackCalls atomic.Int64
	zero := time.Duration(0)
	partitioned := true
	secure := true
	httpOnly := true
	sameSite := "none"
	auth := mustCustomSessionAuth(t, singleauth.Options{
		BaseURL: integrationBaseURL,
		Secret:  integrationSecret,
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{
				"role": {Type: storage.FieldString, Required: storage.Bool(false)},
			}},
		}},
		EmailAndPassword: fastEmailPassword(),
		Session: singleauth.SessionOptions{
			ExpiresIn: 24 * time.Hour,
			UpdateAge: &zero,
			CookieCache: singleauth.CookieCacheOptions{
				Enabled: true, MaxAge: 5 * time.Minute,
			},
		},
		Advanced: singleauth.AdvancedOptions{DefaultCookieAttributes: singleauth.CookieOverride{
			Partitioned: &partitioned, Secure: &secure, HTTPOnly: &httpOnly, SameSite: &sameSite,
		}},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			Enrich: func(data SessionData, ctx *engine.Context) (any, error) {
				callbackCalls.Add(1)
				name, _ := data.User["name"].(string)
				parts := strings.Fields(name)
				return map[string]any{
					"user": map[string]any{
						"firstName": parts[0],
						"lastName":  parts[1],
						"role":      data.User["role"],
					},
					"newData": map[string]any{"message": "Hello, World!"},
					"session": data.Session,
					"path":    ctx.Path(),
				}, nil
			},
		})},
	})

	signUp := rootHTTPJSON(t, auth.Handler(), http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Ada Lovelace", "email": "ada@example.com", "password": "password123", "role": "admin",
	})
	if signUp.status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s", signUp.status, signUp.body)
	}
	cookieHeader := cookies.ApplySetCookies("", signUp.headers.Values("Set-Cookie"))
	if cookieHeader == "" {
		t.Fatal("sign-up did not issue a session cookie")
	}
	signedToken := responseCookieValue(signUp.headers.Values("Set-Cookie"), "session_token")

	cached := rootHTTPJSON(t, auth.Handler(), http.MethodGet, "/get-session", cookieHeader, nil)
	if cached.status != http.StatusOK {
		t.Fatalf("cached get-session status=%d body=%s", cached.status, cached.body)
	}
	assertRootProjection(t, cached.value)

	withoutRefresh := rootHTTPJSON(t, auth.Handler(), http.MethodGet, "/get-session?disableRefresh=true", cookieHeader, nil)
	if withoutRefresh.status != http.StatusOK {
		t.Fatalf("disableRefresh status=%d body=%s", withoutRefresh.status, withoutRefresh.body)
	}
	assertRootProjection(t, withoutRefresh.value)

	refreshed := rootHTTPJSON(t, auth.Handler(), http.MethodGet, "/get-session?disableCookieCache=true", cookieHeader, nil)
	if refreshed.status != http.StatusOK {
		t.Fatalf("get-session status=%d body=%s", refreshed.status, refreshed.body)
	}
	assertRootProjection(t, refreshed.value)
	if callbackCalls.Load() != 3 {
		t.Fatalf("callback calls = %d", callbackCalls.Load())
	}
	if refreshed.headers.Get("Cache-Control") != "no-store" || refreshed.headers.Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %#v", refreshed.headers)
	}
	assertRefreshedCookies(t, refreshed.headers.Values("Set-Cookie"), 86400, 300)
	if refreshedToken := responseCookieValue(refreshed.headers.Values("Set-Cookie"), "session_token"); refreshedToken == "" || refreshedToken != signedToken {
		t.Fatalf("refreshed token = %q, signed token = %q", refreshedToken, signedToken)
	}

	post := rootHTTPJSON(t, auth.Handler(), http.MethodPost, "/get-session", cookieHeader, map[string]any{})
	if post.status != http.StatusMethodNotAllowed || post.value.(map[string]any)["code"] != "METHOD_NOT_ALLOWED" {
		t.Fatalf("POST replacement status=%d body=%s", post.status, post.body)
	}

	directHeaders := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader})
	direct, err := auth.API().Call(t.Context(), "getSession", singleauth.DirectCallInput{
		Method: http.MethodGet, Headers: directHeaders,
		Query: url.Values{"disableCookieCache": []string{"true"}},
	})
	if err != nil || direct.Response.Status() != http.StatusOK {
		t.Fatalf("direct status=%d body=%s err=%v", direct.Response.Status(), direct.Response.Body(), err)
	}
	assertRootProjection(t, direct.Value)
	if len(direct.Response.Headers().Values("Set-Cookie")) < 2 {
		t.Fatalf("direct refresh cookies = %#v", direct.Response.Headers().Values("Set-Cookie"))
	}

	missing, err := auth.API().Call(t.Context(), "getSession", singleauth.DirectCallInput{Method: http.MethodGet})
	if err != nil || missing.Value != nil || string(missing.Response.Body()) != "null" {
		t.Fatalf("missing direct status=%d body=%s value=%#v err=%v", missing.Response.Status(), missing.Response.Body(), missing.Value, err)
	}
	if callbackCalls.Load() != 4 {
		t.Fatalf("null session invoked callback: calls=%d", callbackCalls.Load())
	}
}

func TestRootFactoryCustomSessionAcrossDispatchFastHTTPAndFiber(t *testing.T) {
	auth := mustCustomSessionAuth(t, singleauth.Options{
		BaseURL:          integrationBaseURL,
		Secret:           integrationSecret,
		EmailAndPassword: fastEmailPassword(),
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			Enrich: func(data SessionData, _ *engine.Context) (any, error) {
				return map[string]any{"subject": data.User["id"], "token": data.Session["token"]}, nil
			},
		})},
	})
	signUp := rootHTTPJSON(t, auth.Handler(), http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Transport User", "email": "transport@example.com", "password": "password123",
	})
	if signUp.status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s", signUp.status, signUp.body)
	}
	cookieHeader := cookies.ApplySetCookies("", signUp.headers.Values("Set-Cookie"))

	neutralRequest := contract.NewRequest(http.MethodGet, "/api/auth/get-session", contract.RequestOptions{
		Scheme: "https", Host: "auth.example.test",
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}),
	})
	neutral, err := auth.Dispatch(neutralRequest)
	if err != nil || neutral.Status() != http.StatusOK {
		t.Fatalf("neutral status=%d body=%s err=%v", neutral.Status(), neutral.Body(), err)
	}
	assertSubjectProjection(t, neutral.Body())

	fastHandler := fasthttptransport.NewHandler(auth.Dispatcher())
	var fastRequest fasthttpserver.Request
	fastRequest.Header.SetMethod(http.MethodGet)
	fastRequest.Header.Set("Cookie", cookieHeader)
	fastRequest.SetRequestURI(integrationBaseURL + "/api/auth/get-session")
	var fastContext fasthttpserver.RequestCtx
	fastContext.Init(&fastRequest, nil, nil)
	fastHandler(&fastContext)
	if fastContext.Response.StatusCode() != http.StatusOK {
		t.Fatalf("fasthttp status=%d body=%s", fastContext.Response.StatusCode(), fastContext.Response.Body())
	}
	assertSubjectProjection(t, fastContext.Response.Body())

	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(auth.Dispatcher()))
	fiberRequest, err := http.NewRequest(http.MethodGet, integrationBaseURL+"/api/auth/get-session", nil)
	if err != nil {
		t.Fatal(err)
	}
	fiberRequest.Header.Set("Cookie", cookieHeader)
	fiberResponse, err := app.Test(fiberRequest, fiberframework.TestConfig{Timeout: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer fiberResponse.Body.Close()
	fiberBody, err := io.ReadAll(fiberResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if fiberResponse.StatusCode != http.StatusOK {
		t.Fatalf("fiber status=%d body=%s", fiberResponse.StatusCode, fiberBody)
	}
	assertSubjectProjection(t, fiberBody)
}

type rootHTTPResult struct {
	status  int
	headers http.Header
	body    []byte
	value   any
}

func rootHTTPJSON(
	t *testing.T,
	handler http.Handler,
	method, path, cookieHeader string,
	body any,
) rootHTTPResult {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, integrationBaseURL+"/api/auth"+path, bytes.NewReader(payload))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookieHeader != "" {
		request.Header.Set("Cookie", cookieHeader)
		if method != http.MethodGet && method != http.MethodHead {
			request.Header.Set("Origin", integrationBaseURL)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	result := rootHTTPResult{
		status: recorder.Code, headers: recorder.Header().Clone(), body: recorder.Body.Bytes(),
	}
	if len(bytes.TrimSpace(result.body)) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(result.body))
		decoder.UseNumber()
		if err := decoder.Decode(&result.value); err != nil {
			t.Fatalf("decode %s: %v", result.body, err)
		}
	}
	return result
}

func mustCustomSessionAuth(t *testing.T, options singleauth.Options) *singleauth.Auth {
	t.Helper()
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func fastEmailPassword() singleauth.EmailAndPasswordOptions {
	return singleauth.EmailAndPasswordOptions{
		Enabled: true,
		Password: singleauth.PasswordOptions{
			Hash:   func(password string) (string, error) { return "test:" + password, nil },
			Verify: func(hash, password string) bool { return hash == "test:"+password },
		},
	}
}

func assertRootProjection(t *testing.T, value any) {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("projection = %#v", value)
	}
	user, _ := object["user"].(map[string]any)
	newData, _ := object["newData"].(map[string]any)
	session, _ := object["session"].(map[string]any)
	if user["firstName"] != "Ada" || user["lastName"] != "Lovelace" || user["role"] != "admin" ||
		newData["message"] != "Hello, World!" || session["token"] == "" || object["path"] != "/get-session" {
		t.Fatalf("projection = %#v", object)
	}
}

func assertSubjectProjection(t *testing.T, body []byte) {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if object["subject"] == "" || object["token"] == "" {
		t.Fatalf("projection = %#v", object)
	}
}

func assertRefreshedCookies(t *testing.T, lines []string, tokenAge, cacheAge int) {
	t.Helper()
	var tokenCookie, dataCookie *cookies.SetCookie
	for _, line := range lines {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			cookie := parsed
			switch {
			case strings.Contains(parsed.Name, "session_token"):
				tokenCookie = &cookie
			case strings.Contains(parsed.Name, "session_data"):
				dataCookie = &cookie
			}
		}
	}
	if tokenCookie == nil || dataCookie == nil ||
		tokenCookie.Attributes.MaxAge == nil || *tokenCookie.Attributes.MaxAge != tokenAge ||
		dataCookie.Attributes.MaxAge == nil || *dataCookie.Attributes.MaxAge != cacheAge ||
		!tokenCookie.Attributes.Partitioned || !dataCookie.Attributes.Partitioned ||
		!tokenCookie.Attributes.Secure || !dataCookie.Attributes.Secure ||
		tokenCookie.Attributes.SameSite != "none" || dataCookie.Attributes.SameSite != "none" {
		t.Fatalf("refreshed cookies = %#v %#v from %#v", tokenCookie, dataCookie, lines)
	}
}

func responseCookieValue(lines []string, nameFragment string) string {
	for _, line := range lines {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if strings.Contains(parsed.Name, nameFragment) {
				return parsed.Attributes.Value
			}
		}
	}
	return ""
}
