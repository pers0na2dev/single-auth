package singleauth_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type cookieCacheFallbackCase struct {
	Suite       string
	Title       string
	Observation cookieCacheFallbackObservation
}

type cookieCacheFallbackObservation struct {
	Strategy              string `json:"strategy"`
	CrossSubDomain        bool   `json:"crossSubDomain"`
	InitialSessionPresent *bool  `json:"initialSessionPresent"`
	SessionTokenPresent   bool   `json:"sessionTokenPresent"`
	SessionPresent        bool   `json:"sessionPresent"`
	EmailMatches          *bool  `json:"emailMatches"`
	ErrorPresent          bool   `json:"errorPresent"`
	InvalidCacheExpired   bool   `json:"invalidCacheExpired"`
	InvalidTokenExpired   bool   `json:"invalidTokenExpired"`
}

type cookieCacheFallbackExchange func(
	method, target string,
	headers http.Header,
	body []byte,
) (int, http.Header, []byte, error)

func TestCookieCacheFallbackHTTPBehavior(t *testing.T) {
	for _, vector := range cookieCacheFallbackCases() {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					t.Parallel()
					actual := runCookieCacheFallbackVector(t, transportName, vector.Title)
					if !reflect.DeepEqual(actual, vector.Observation) {
						t.Fatalf("observation = %#v, want %#v", actual, vector.Observation)
					}
				})
			}
		})
	}
}

func runCookieCacheFallbackVector(
	t *testing.T,
	transportName string,
	title string,
) cookieCacheFallbackObservation {
	t.Helper()
	now := time.Date(2026, 8, 9, 8, 30, 0, 0, time.UTC)
	strategy := "compact"
	crossSubDomain := false
	checkInitial := false
	maxAge := 5 * time.Minute
	switch title {
	case "should fall through to session_token DB validation when session_data HMAC fails":
		checkInitial = true
	case "should still return null when both session_data and session_token are invalid":
	case "should work with JWT strategy when HMAC verification fails":
		strategy = "jwt"
	case "should work with JWE strategy when decryption fails":
		strategy = "jwe"
	case "should handle cross-subdomain cookie migration without silent logout":
		crossSubDomain = true
		checkInitial = true
		maxAge = 10 * time.Second
	case "should work during cookieCache window even with stale session_data":
		checkInitial = true
		maxAge = time.Minute
	default:
		t.Fatalf("unsupported cookie-cache fallback vector %q", title)
	}

	baseURL := "http://localhost:3000"
	advanced := singleauth.AdvancedOptions{}
	if crossSubDomain {
		baseURL = "https://www.app.example.com"
		advanced.CrossSubDomainCookies = singleauth.CrossSubDomainCookieOptions{
			Enabled: true,
			Domain:  ".example.com",
		}
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: baseURL,
		Secret:  "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return password, nil },
				Verify: func(hash, password string) bool { return hash == password },
			},
		},
		Session: singleauth.SessionOptions{CookieCache: singleauth.CookieCacheOptions{
			Enabled:  true,
			Strategy: strategy,
			MaxAge:   maxAge,
		}},
		Advanced: advanced,
		Clock:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	exchange := newCookieCacheFallbackExchange(t, transportName, auth, baseURL)
	email := "cookie-cache-" + transportName + "@example.test"
	signUpBody, err := json.Marshal(map[string]any{
		"name": "Cookie Cache", "email": email, "password": "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{
		"Content-Type": {"application/json"},
		"Origin":       {baseURL},
	}
	status, responseHeaders, body, err := exchange(
		http.MethodPost, "/api/auth/sign-up/email", headers, signUpBody,
	)
	if err != nil || status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s err=%v", status, body, err)
	}
	cookieHeader := cookies.ApplySetCookies("", responseHeaders.Values("Set-Cookie"))
	securePrefix := ""
	if crossSubDomain {
		securePrefix = "__Secure-"
	}
	sessionToken, sessionTokenPresent := cookies.Parse(cookieHeader).Get(
		securePrefix + "single-auth.session_token",
	)

	var initialSessionPresent *bool
	if checkInitial {
		initialHeaders := http.Header{"Cookie": {cookieHeader}}
		initialStatus, _, initialBody, initialErr := exchange(
			http.MethodGet, "/api/auth/get-session", initialHeaders, nil,
		)
		if initialErr != nil || initialStatus != http.StatusOK {
			t.Fatalf("initial get-session status=%d body=%s err=%v", initialStatus, initialBody, initialErr)
		}
		present := !bytes.Equal(bytes.TrimSpace(initialBody), []byte("null"))
		initialSessionPresent = &present
	}

	invalidSessionData := cookieCacheFallbackInvalidData(t, title, email, now)
	if title == "should still return null when both session_data and session_token are invalid" {
		sessionToken = "invalid-token.invalid-signature"
	}
	tamperedHeader := securePrefix + "single-auth.session_data=" + invalidSessionData +
		"; " + securePrefix + "single-auth.session_token=" + sessionToken
	status, responseHeaders, body, err = exchange(
		http.MethodGet,
		"/api/auth/get-session",
		http.Header{"Cookie": {tamperedHeader}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	sessionPresent := status == http.StatusOK &&
		!bytes.Equal(bytes.TrimSpace(body), []byte("null"))
	var emailMatches *bool
	if sessionPresent {
		var result struct {
			User struct {
				Email string `json:"email"`
			} `json:"user"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("decode get-session response %s: %v", body, err)
		}
		matches := result.User.Email == email
		emailMatches = &matches
	}
	return cookieCacheFallbackObservation{
		Strategy:              strategy,
		CrossSubDomain:        crossSubDomain,
		InitialSessionPresent: initialSessionPresent,
		SessionTokenPresent:   sessionTokenPresent,
		SessionPresent:        sessionPresent,
		EmailMatches:          emailMatches,
		ErrorPresent:          status < 200 || status >= 300,
		InvalidCacheExpired: cookieCacheFallbackExpired(
			responseHeaders.Values("Set-Cookie"),
			securePrefix+"single-auth.session_data",
		),
		InvalidTokenExpired: cookieCacheFallbackExpired(
			responseHeaders.Values("Set-Cookie"),
			securePrefix+"single-auth.session_token",
		),
	}
}

func cookieCacheFallbackInvalidData(
	t *testing.T,
	title, email string,
	now time.Time,
) string {
	t.Helper()
	switch title {
	case "should work with JWT strategy when HMAC verification fails":
		return "invalid.jwt.token"
	case "should work with JWE strategy when decryption fails":
		return "invalid.jwe.token.here.test"
	}
	var value map[string]any
	if title == "should handle cross-subdomain cookie migration without silent logout" {
		value = map[string]any{
			"session": map[string]any{
				"session": map[string]any{
					"token": "old-session-token", "userId": "old-user-id",
					"expiresAt": now.Add(-time.Second).Format(time.RFC3339Nano),
					"createdAt": now.Format(time.RFC3339Nano),
					"updatedAt": now.Format(time.RFC3339Nano),
				},
				"user": map[string]any{
					"id": "old-user-id", "email": email, "name": "Cookie Cache",
					"emailVerified": false,
					"createdAt":     now.Format(time.RFC3339Nano),
					"updatedAt":     now.Format(time.RFC3339Nano),
				},
				"updatedAt": now.Add(-time.Minute).UnixMilli(),
			},
			"expiresAt": now.Add(-time.Second).UnixMilli(),
			"signature": "stale-signature-from-old-domain-cookie",
		}
	} else if title == "should work during cookieCache window even with stale session_data" {
		value = map[string]any{
			"session": map[string]any{
				"session":   map[string]any{"token": "stale", "userId": "stale"},
				"user":      map[string]any{"id": "stale", "email": "stale@example.com"},
				"updatedAt": now.Add(-time.Hour).UnixMilli(),
			},
			"expiresAt": now.Add(-time.Second).UnixMilli(),
			"signature": "stale-signature-from-old-deployment",
		}
	} else {
		signature := "invalid-signature-that-will-fail-hmac-verification"
		if title == "should still return null when both session_data and session_token are invalid" {
			signature = "invalid-signature"
		}
		value = map[string]any{
			"session": map[string]any{
				"session":   map[string]any{"token": "fake", "userId": "fake"},
				"user":      map[string]any{"id": "fake", "email": "fake@example.com"},
				"updatedAt": now.UnixMilli(),
			},
			"expiresAt": now.Add(5 * time.Minute).UnixMilli(),
			"signature": signature,
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func cookieCacheFallbackExpired(setCookieValues []string, name string) bool {
	for _, value := range setCookieValues {
		for _, parsed := range cookies.ParseSetCookieHeader(value) {
			if parsed.Name == name && parsed.Attributes.MaxAge != nil &&
				*parsed.Attributes.MaxAge == 0 {
				return true
			}
		}
	}
	return false
}

func newCookieCacheFallbackExchange(
	t *testing.T,
	transportName string,
	auth *singleauth.Auth,
	baseURL string,
) cookieCacheFallbackExchange {
	t.Helper()
	switch transportName {
	case "net-http":
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			request := httptest.NewRequest(method, baseURL+target, bytes.NewReader(body))
			request.Header = headers.Clone()
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, response.Header.Clone(), encoded, err
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			var request fasthttpserver.Request
			request.Header.SetMethod(method)
			request.SetRequestURI(baseURL + target)
			for name, values := range headers {
				for _, value := range values {
					request.Header.Add(name, value)
				}
			}
			request.SetBody(body)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(
				&request,
				&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123},
				nil,
			)
			handler(&requestContext)
			responseHeaders := make(http.Header)
			requestContext.Response.Header.VisitAll(func(name, value []byte) {
				responseHeaders.Add(string(name), string(value))
			})
			return requestContext.Response.StatusCode(), responseHeaders,
				append([]byte(nil), requestContext.Response.Body()...), nil
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			request, err := http.NewRequest(method, baseURL+target, bytes.NewReader(body))
			if err != nil {
				return 0, nil, nil, err
			}
			request.Header = headers.Clone()
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				return 0, nil, nil, err
			}
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, response.Header.Clone(), encoded, err
		}
	default:
		t.Fatalf("unknown cookie-cache fallback transport %q", transportName)
		return nil
	}
}

func TestCookieCacheFallbackScenarioDefinitions(t *testing.T) {
	cases := cookieCacheFallbackCases()
	if len(cases) != 6 {
		t.Fatalf("cookie-cache fallback scenarios=%d, want 6", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, vector := range cases {
		name := vector.Suite + "::" + vector.Title
		if vector.Suite == "" || vector.Title == "" {
			t.Fatalf("invalid cookie-cache fallback scenario: %#v", vector)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate cookie-cache fallback scenario %q", name)
		}
		seen[name] = struct{}{}
	}
}

func cookieCacheFallbackCases() []cookieCacheFallbackCase {
	const suite = "cookieCache HMAC verification failure fallback"
	boolValue := func(value bool) *bool { return &value }
	validFallback := func(strategy string, crossSubDomain bool, initial *bool) cookieCacheFallbackObservation {
		return cookieCacheFallbackObservation{
			Strategy:              strategy,
			CrossSubDomain:        crossSubDomain,
			InitialSessionPresent: initial,
			SessionTokenPresent:   true,
			SessionPresent:        true,
			EmailMatches:          boolValue(true),
			InvalidCacheExpired:   true,
		}
	}
	return []cookieCacheFallbackCase{
		{Suite: suite, Title: "should fall through to session_token DB validation when session_data HMAC fails", Observation: validFallback("compact", false, boolValue(true))},
		{Suite: suite, Title: "should handle cross-subdomain cookie migration without silent logout", Observation: validFallback("compact", true, boolValue(true))},
		{Suite: suite, Title: "should still return null when both session_data and session_token are invalid", Observation: cookieCacheFallbackObservation{Strategy: "compact", SessionTokenPresent: true}},
		{Suite: suite, Title: "should work during cookieCache window even with stale session_data", Observation: validFallback("compact", false, boolValue(true))},
		{Suite: suite, Title: "should work with JWE strategy when decryption fails", Observation: validFallback("jwe", false, nil)},
		{Suite: suite, Title: "should work with JWT strategy when HMAC verification fails", Observation: validFallback("jwt", false, nil)},
	}
}
