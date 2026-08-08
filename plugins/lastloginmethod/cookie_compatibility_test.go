package lastloginmethod

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestReferenceBeforeStoreCookie(t *testing.T) {
	path := "/sign-in/email"
	session := []string{"single-auth.session_token=token; Path=/; HttpOnly"}
	for _, test := range []struct {
		name string
		hook BeforeStoreCookieFunc
		want bool
	}{
		{name: "undefined defaults true", want: true},
		{name: "true", hook: func(HookContext, string) (bool, error) { return true, nil }, want: true},
		{name: "false", hook: func(HookContext, string) (bool, error) { return false, nil }},
		{name: "error is swallowed", hook: func(HookContext, string) (bool, error) { return false, errors.New("GDPR check failed") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := invokeProbe(t, Options{BeforeStoreCookie: test.hook}, &path, nil, session)
			cookie, exists := responseCookie(response, DefaultCookieName)
			if exists != test.want {
				t.Fatalf("cookie exists=%v cookies=%#v, want %v", exists, response.Headers().Values("Set-Cookie"), test.want)
			}
			if exists && cookie.Attributes.Value != "email" {
				t.Fatalf("cookie=%#v", cookie)
			}
		})
	}

	t.Run("dynamic consent is evaluated on every login", func(t *testing.T) {
		consent := false
		options := Options{BeforeStoreCookie: func(HookContext, string) (bool, error) { return consent, nil }}
		first := invokeProbe(t, options, &path, nil, session)
		if _, exists := responseCookie(first, DefaultCookieName); exists {
			t.Fatalf("cookie present before consent: %#v", first.Headers().Values("Set-Cookie"))
		}
		consent = true
		second := invokeProbe(t, options, &path, nil, session)
		if cookie, exists := responseCookie(second, DefaultCookieName); !exists || cookie.Attributes.Value != "email" {
			t.Fatalf("cookie after consent: %#v", second.Headers().Values("Set-Cookie"))
		}
	})

	t.Run("receives isolated context and resolved method", func(t *testing.T) {
		var receivedPath, receivedMethod string
		options := Options{BeforeStoreCookie: func(ctx HookContext, method string) (bool, error) {
			receivedPath = ctx.Path
			receivedMethod = method
			ctx.Params["mutated"] = "yes"
			return true, nil
		}}
		response := invokeProbe(t, options, &path, nil, session)
		if receivedPath != path || receivedMethod != "email" {
			t.Fatalf("path=%q method=%q", receivedPath, receivedMethod)
		}
		if _, exists := responseCookie(response, DefaultCookieName); !exists {
			t.Fatalf("cookie absent: %#v", response.Headers().Values("Set-Cookie"))
		}
	})

	t.Run("different methods can use different consent", func(t *testing.T) {
		options := Options{BeforeStoreCookie: func(_ HookContext, method string) (bool, error) {
			return method == "email", nil
		}}
		email := invokeProbe(t, options, &path, nil, session)
		if _, exists := responseCookie(email, DefaultCookieName); !exists {
			t.Fatal("email cookie missing")
		}
		siwePath := "/siwe/verify"
		siwe := invokeProbe(t, options, &siwePath, nil, session)
		if _, exists := responseCookie(siwe, DefaultCookieName); exists {
			t.Fatalf("SIWE cookie unexpectedly present: %#v", siwe.Headers().Values("Set-Cookie"))
		}
	})

	t.Run("sign-up flow resolves email", func(t *testing.T) {
		signUpPath := "/sign-up/email"
		response := invokeProbe(t, Options{BeforeStoreCookie: func(_ HookContext, method string) (bool, error) {
			return method == "email", nil
		}}, &signUpPath, nil, session)
		if cookie, exists := responseCookie(response, DefaultCookieName); !exists || cookie.Attributes.Value != "email" {
			t.Fatalf("sign-up cookie=%#v headers=%#v", cookie, response.Headers().Values("Set-Cookie"))
		}
	})
}

func TestReferenceLastLoginCookieNameAndAttributeMatrix(t *testing.T) {
	secure := true
	insecure := false
	none := "none"
	tests := []struct {
		name       string
		baseURL    string
		advanced   singleauth.AdvancedOptions
		plugin     Options
		cookieName string
		secure     bool
		domain     string
		sameSite   string
	}{
		{
			name: "default name ignores custom root prefix", baseURL: "http://auth.example.test",
			advanced:   singleauth.AdvancedOptions{CookiePrefix: "custom-auth"},
			cookieName: DefaultCookieName, sameSite: "lax",
		},
		{
			name: "custom name with matching prefix", baseURL: "http://auth.example.test",
			advanced: singleauth.AdvancedOptions{CookiePrefix: "my-app"},
			plugin:   Options{CookieName: "my-app.last_method"}, cookieName: "my-app.last_method", sameSite: "lax",
		},
		{
			name: "custom name remains verbatim", baseURL: "http://auth.example.test",
			advanced: singleauth.AdvancedOptions{CookiePrefix: "my-app"},
			plugin:   Options{CookieName: "last_login_method"}, cookieName: "last_login_method", sameSite: "lax",
		},
		{
			name: "cross subdomain inherits domain with custom prefix", baseURL: "https://auth.example.com",
			advanced: singleauth.AdvancedOptions{
				UseSecureCookies: &secure, CookiePrefix: "custom-auth",
				CrossSubDomainCookies: singleauth.CrossSubDomainCookieOptions{Enabled: true, Domain: "example.com"},
			},
			cookieName: DefaultCookieName, secure: true, domain: "example.com", sameSite: "lax",
		},
		{
			name: "cross origin inherits SameSite None and Secure", baseURL: "https://api.example.com",
			advanced: singleauth.AdvancedOptions{DefaultCookieAttributes: singleauth.CookieOverride{
				SameSite: &none, Secure: &secure,
			}},
			cookieName: DefaultCookieName, secure: true, sameSite: "none",
		},
		{
			name: "localhost cross origin permits insecure SameSite None", baseURL: "http://localhost:3000",
			advanced: singleauth.AdvancedOptions{DefaultCookieAttributes: singleauth.CookieOverride{
				SameSite: &none, Secure: &insecure,
			}},
			cookieName: DefaultCookieName, sameSite: "none",
		},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth, err := singleauth.New(singleauth.Options{
				BaseURL: test.baseURL, Secret: integrationSecret,
				Advanced: test.advanced, EmailAndPassword: fastEmailPasswordOptions(),
				PluginFactories: []singleauth.PluginFactory{NewFactory(test.plugin)},
			})
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(fmt.Sprintf(
				`{"name":"Cookie User","email":"cookie-%d@example.com","password":"password123"}`,
				index,
			))
			request := httptest.NewRequest(http.MethodPost, test.baseURL+"/api/auth/sign-up/email", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", test.baseURL)
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			response := contract.NewResponse(recorder.Code, headersFromHTTP(recorder.Header()), nil)
			cookie, exists := responseCookie(response, test.cookieName)
			if !exists {
				t.Fatalf("cookie %q missing from %#v", test.cookieName, recorder.Header().Values("Set-Cookie"))
			}
			attributes := cookie.Attributes
			if attributes.Value != "email" || attributes.Secure != test.secure || attributes.Domain != test.domain || attributes.SameSite != test.sameSite || attributes.HTTPOnly {
				t.Fatalf("cookie=%#v", cookie)
			}
		})
	}
}

func TestReferenceLastLoginScansAndPreservesMultipleSetCookieHeaders(t *testing.T) {
	path := "/sign-in/email"
	response := invokeProbe(t, Options{}, &path, nil, []string{
		"unrelated=first; Path=/",
		"single-auth.session_token=token; Path=/; HttpOnly",
		"additional-test-cookie=test-value; Path=/",
	})
	values := response.Headers().Values("Set-Cookie")
	if len(values) != 4 {
		t.Fatalf("set-cookie headers=%#v", values)
	}
	if _, exists := responseCookie(response, DefaultCookieName); !exists {
		t.Fatalf("last-login cookie missing from %#v", values)
	}
}
