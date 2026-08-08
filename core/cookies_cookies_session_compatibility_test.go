package core

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

func cookieBehaviorSessionRunner(vector cookiesBehaviorVector) (func(*testing.T), bool) {
	switch vector.Suite {
	case "cookies", "cookies > production environment":
		return func(t *testing.T) { runCookieWriterBehavior(t, vector) }, true
	case "crossSubdomainCookies":
		return func(t *testing.T) { runCrossSubdomainCookieBehavior(t, vector.Title) }, true
	case "cookie configuration":
		return func(t *testing.T) { runCookieConfigurationBehavior(t) }, true
	case "getSessionCookie":
		return func(t *testing.T) { runGetSessionCookieBehavior(t, vector.Title) }, true
	default:
		if strings.HasPrefix(vector.Suite, "getSessionCookie > with ") {
			return func(t *testing.T) { runParameterizedGetSessionCookieBehavior(t, vector) }, true
		}
		return nil, false
	}
}

func newCookieBehaviorAuth(t *testing.T, options Options) *Auth {
	t.Helper()
	if options.Secret == "" {
		options.Secret = "0123456789abcdef0123456789abcdef"
	}
	options.EmailAndPassword.Enabled = true
	options.EmailAndPassword.Password.Hash = func(password string) (string, error) { return password, nil }
	options.EmailAndPassword.Password.Verify = func(hash, password string) bool { return hash == password }
	if options.Clock == nil {
		now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
		options.Clock = func() time.Time { return now }
	}
	auth, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func cookieBehaviorSignUp(
	t *testing.T,
	auth *Auth,
	email string,
	extra map[string]any,
) (http.Header, string, map[string]any) {
	t.Helper()
	body := map[string]any{
		"name": "Cookie User", "email": email, "password": "password123",
	}
	for key, value := range extra {
		body[key] = value
	}
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-up/email", "", body)
	if status != http.StatusOK {
		t.Fatalf("sign-up status=%d value=%#v", status, value)
	}
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("sign-up result=%#v", value)
	}
	return headers, cookies.ApplySetCookies("", headers.Values("Set-Cookie")), result
}

func runCookieWriterBehavior(t *testing.T, vector cookiesBehaviorVector) {
	options := Options{BaseURL: "http://auth.test"}
	switch vector.Title {
	case "should set cookies with default options", "should set multiple cookies":
	case "should use secure cookies":
		secure := true
		options.Advanced.UseSecureCookies = &secure
	case "should use secure cookies when the base url is https":
		options.BaseURL = "https://example.com"
	case "should use secure cookies when baseURL is not configured":
		for _, name := range []string{
			"SINGLE_AUTH_URL", "NEXT_PUBLIC_SINGLE_AUTH_URL", "PUBLIC_SINGLE_AUTH_URL",
			"NUXT_PUBLIC_SINGLE_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL",
		} {
			t.Setenv(name, "")
		}
		options.BaseURL = ""
		options.Environment = "production"
	default:
		t.Fatalf("unsupported cookies title %q", vector.Title)
	}
	if vector.Title == "should set multiple cookies" {
		options.Session.CookieCache.Enabled = true
	}
	auth := newCookieBehaviorAuth(t, options)
	headers, _, _ := cookieBehaviorSignUp(t, auth, "writer@example.test", nil)
	setCookies := headers.Values("Set-Cookie")
	joined := strings.Join(setCookies, "\n")
	switch vector.Title {
	case "should set cookies with default options":
		for _, want := range []string{"Path=/", "HttpOnly", "SameSite=Lax", "single-auth"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("Set-Cookie=%q missing %q", joined, want)
			}
		}
	case "should set multiple cookies":
		names := make(map[string]bool)
		for _, line := range setCookies {
			for _, parsed := range cookies.ParseSetCookieHeader(line) {
				names[parsed.Name] = true
			}
		}
		if !names[auth.options.cookie.sessionName] || !names[auth.options.cookie.sessionDataName] || len(names) < 2 {
			t.Fatalf("cookie names=%#v", names)
		}
	default:
		if !strings.Contains(joined, "; Secure") {
			t.Fatalf("secure Set-Cookie missing: %q", joined)
		}
	}
}

func runCrossSubdomainCookieBehavior(t *testing.T, title string) {
	options := Options{
		BaseURL: "http://auth.test",
		Advanced: AdvancedOptions{CrossSubDomainCookies: CrossSubDomainCookieOptions{
			Enabled: true, Domain: "example.com",
		}},
	}
	if title == "should use default domain from baseURL if not provided" {
		options.BaseURL = "https://example.com"
		options.Advanced.CrossSubDomainCookies.Domain = ""
	} else if title != "should update cookies with custom domain" {
		t.Fatalf("unsupported crossSubdomainCookies title %q", title)
	}
	auth := newCookieBehaviorAuth(t, options)
	headers, _, _ := cookieBehaviorSignUp(t, auth, "cross-domain@example.test", nil)
	joined := strings.Join(headers.Values("Set-Cookie"), "\n")
	if !strings.Contains(joined, "Domain=example.com") {
		t.Fatalf("Set-Cookie=%q", joined)
	}
	if title == "should update cookies with custom domain" && !strings.Contains(joined, "SameSite=Lax") {
		t.Fatalf("Set-Cookie=%q", joined)
	}
}

func runCookieConfigurationBehavior(t *testing.T) {
	secure := true
	builder, err := newCookieBuilder(Options{
		BaseURL: "https://example.com",
		Advanced: AdvancedOptions{
			UseSecureCookies: &secure,
			CrossSubDomainCookies: CrossSubDomainCookieOptions{
				Enabled: true, Domain: "example.com",
			},
			CookiePrefix: "test-prefix",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	maxAge := 300
	sessionName, session := builder.cookie("session_token", "session_token", &maxAge)
	_, sessionData := builder.cookie("session_data", "session_data", &maxAge)
	if !session.Secure || !strings.Contains(sessionName, "test-prefix.session_token") ||
		sessionData.SameSite != "lax" || sessionData.Domain != "example.com" {
		t.Fatalf("session=%q %#v data=%#v", sessionName, session, sessionData)
	}
}

type inheritedCookieHeaders struct{ http.Header }

type crossRuntimeCookieHeaders struct{ value string }

func (headers crossRuntimeCookieHeaders) Get(name string) string {
	if strings.EqualFold(name, "cookie") {
		return headers.value
	}
	return ""
}

func runGetSessionCookieBehavior(t *testing.T, title string) {
	switch title {
	case "prefers the __Secure- cookie when a non-secure leftover is also present":
		value, ok := GetSessionCookie("single-auth.session_token=stale; __Secure-single-auth.session_token=current")
		if !ok || value != "current" {
			t.Fatalf("session=%q ok=%v", value, ok)
		}
		return
	case "does not fall back to a non-secure cookie when the __Secure- value is empty":
		if value, ok := GetSessionCookie("single-auth.session_token=stale; __Secure-single-auth.session_token="); ok || value != "" {
			t.Fatalf("session=%q ok=%v", value, ok)
		}
		return
	case "should return null if the cookie is invalid":
		secure := false
		cache, err := GetCookieCache("", CookieCacheLookupOptions{
			Secret: "wrong-secret", IsSecure: &secure,
		})
		if err != nil || cache != nil {
			t.Fatalf("cache=%#v err=%v", cache, err)
		}
		return
	case "should throw an error if the secret is not provided":
		t.Setenv("SINGLE_AUTH_SECRET", "")
		auth := newCookieBehaviorAuth(t, Options{
			BaseURL: "http://auth.test",
			Session: SessionOptions{CookieCache: CookieCacheOptions{Enabled: true}},
		})
		_, cookieHeader, _ := cookieBehaviorSignUp(t, auth, "missing-secret@example.test", nil)
		secure := false
		_, err := GetCookieCache(cookieHeader, CookieCacheLookupOptions{IsSecure: &secure, Clock: auth.options.Clock})
		var upstreamError *UpstreamError
		if !errors.As(err, &upstreamError) || !strings.Contains(err.Error(), "requires a secret") {
			t.Fatalf("error=%#v", err)
		}
		return
	case "should return cookie cache":
		runGetSessionCookieCacheBehavior(t)
		return
	case "should respect dontRememberMe when storing session in cookie cache":
		runDontRememberCookieCacheBehavior(t)
		return
	case "should chunk large cookies instead of logging error":
		runGetSessionCookieChunkBehavior(t)
		return
	}

	options := Options{BaseURL: "http://auth.test"}
	lookup := SessionCookieLookupOptions{}
	if title == "should return the correct session cookie on production" {
		options.BaseURL = "https://example.com"
	}
	if title == "should allow override cookie prefix with secure cookies" {
		secure := true
		options.Advanced.UseSecureCookies = &secure
		options.Advanced.CookiePrefix = "test-prefix"
		lookup.CookiePrefix = "test-prefix"
	}
	if title == "should allow override cookie name" {
		secure := true
		options.Advanced.UseSecureCookies = &secure
		options.Advanced.CookiePrefix = "test"
		options.Advanced.Cookies = map[string]CookieOverride{
			"session_token": {Name: "test-session-token"},
		}
		lookup.CookiePrefix = "test"
		lookup.CookieName = "session-token"
	}
	auth := newCookieBehaviorAuth(t, options)
	_, cookieHeader, _ := cookieBehaviorSignUp(t, auth, "session-cookie@example.test", nil)
	var value string
	var ok bool
	switch title {
	case "should return the correct session cookie", "should return the correct session cookie on production":
		request := httptest.NewRequest(http.MethodGet, "https://example.com/api/auth/session", nil)
		request.Header.Set("Cookie", cookieHeader)
		value, ok = GetSessionCookieFromHTTPRequest(request, lookup)
	case "should work with Headers object directly":
		value, ok = GetSessionCookieFromHeaderGetter(http.Header{"Cookie": {cookieHeader}}, lookup)
	case "should work with Headers-like object that has inherited 'headers' property":
		value, ok = GetSessionCookieFromHeaderGetter(inheritedCookieHeaders{Header: http.Header{"Cookie": {cookieHeader}}}, lookup)
	case "should work with cross-realm Headers-like object (instanceof fails)":
		value, ok = GetSessionCookieFromHeaderGetter(crossRuntimeCookieHeaders{value: cookieHeader}, lookup)
	case "should allow override cookie prefix with secure cookies", "should allow override cookie name":
		value, ok = GetSessionCookie(cookieHeader, lookup)
	default:
		t.Fatalf("unsupported getSessionCookie title %q", title)
	}
	if !ok || value == "" {
		t.Fatalf("session=%q ok=%v cookie=%q", value, ok, cookieHeader)
	}
}

func runParameterizedGetSessionCookieBehavior(t *testing.T, vector cookiesBehaviorVector) {
	separator := "."
	if strings.Contains(vector.Suite, "with '-' separator") {
		separator = "-"
	}
	securePrefix := ""
	if strings.Contains(vector.Suite, "__Secure- prefix") {
		securePrefix = cookies.SecurePrefix
	}
	const titlePrefix = "finds cookie with config "
	if !strings.HasPrefix(vector.Title, titlePrefix) {
		t.Fatalf("unexpected parameter title %q", vector.Title)
	}
	var raw map[string]string
	if err := json.Unmarshal([]byte(strings.TrimPrefix(vector.Title, titlePrefix)), &raw); err != nil {
		t.Fatal(err)
	}
	config := SessionCookieLookupOptions{
		CookiePrefix: raw["cookiePrefix"], CookieName: raw["cookieName"],
	}
	prefix := config.CookiePrefix
	if prefix == "" {
		prefix = "single-auth"
	}
	name := config.CookieName
	if name == "" {
		name = "session_token"
	}
	header := securePrefix + prefix + separator + name + "=token-123"
	value, ok := GetSessionCookie(header, config)
	if !ok || value != "token-123" {
		t.Fatalf("session=%q ok=%v header=%q config=%#v", value, ok, header, config)
	}
}

func runGetSessionCookieCacheBehavior(t *testing.T) {
	auth := newCookieBehaviorAuth(t, Options{
		BaseURL: "http://auth.test", Secret: "single-auth.secret",
		Session: SessionOptions{CookieCache: CookieCacheOptions{Enabled: true}},
	})
	_, cookieHeader, result := cookieBehaviorSignUp(t, auth, "cache-return@example.test", nil)
	secure := false
	cache, err := GetCookieCache(cookieHeader, CookieCacheLookupOptions{
		Secret: "single-auth.secret", IsSecure: &secure, Clock: auth.options.Clock,
	})
	if err != nil || cache == nil {
		t.Fatalf("cache=%#v err=%v", cache, err)
	}
	user, _ := cache["user"].(map[string]any)
	session, _ := cache["session"].(map[string]any)
	if user["email"] != "cache-return@example.test" || session["token"] == "" || result["token"] == "" {
		t.Fatalf("cache=%#v", cache)
	}
}

func runDontRememberCookieCacheBehavior(t *testing.T) {
	auth := newCookieBehaviorAuth(t, Options{
		BaseURL: "http://auth.test", Secret: "single-auth.secret",
		Session: SessionOptions{CookieCache: CookieCacheOptions{Enabled: true}},
	})
	cookieBehaviorSignUp(t, auth, "dont-remember@example.test", nil)
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": "dont-remember@example.test", "password": "password123", "rememberMe": false,
	})
	if status != http.StatusOK {
		t.Fatalf("sign-in status=%d value=%#v", status, value)
	}
	found := map[string]bool{"session_token": false, "session_data": false}
	for _, line := range headers.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			for suffix := range found {
				if strings.HasSuffix(parsed.Name, suffix) {
					found[suffix] = true
					if parsed.Attributes.MaxAge != nil {
						t.Fatalf("%s Max-Age=%d", parsed.Name, *parsed.Attributes.MaxAge)
					}
				}
			}
		}
	}
	if !found["session_token"] || !found["session_data"] {
		t.Fatalf("missing cookies: %#v", found)
	}
}

func runGetSessionCookieChunkBehavior(t *testing.T) {
	fields := map[string]storage.FieldAttribute{}
	extra := map[string]any{}
	for index := 1; index <= 3; index++ {
		name := "customField" + string(rune('0'+index))
		fields[name] = storage.FieldAttribute{
			Type: storage.FieldString, Required: storage.Bool(false),
		}
		extra[name] = strings.Repeat("x", 2000)
	}
	auth := newCookieBehaviorAuth(t, Options{
		BaseURL: "http://auth.test", Secret: "single-auth.secret",
		Session: SessionOptions{CookieCache: CookieCacheOptions{Enabled: true}},
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: fields},
		}},
	})
	headers, _, _ := cookieBehaviorSignUp(t, auth, "large-data@example.test", extra)
	hasChunks := false
	for _, line := range headers.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if strings.Contains(parsed.Name, "session_data.0") || strings.Contains(parsed.Name, "session_data.1") {
				hasChunks = true
			}
		}
	}
	if !hasChunks {
		t.Fatalf("session_data was not chunked: %#v", headers.Values("Set-Cookie"))
	}
}
