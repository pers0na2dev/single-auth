package lastloginmethod

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

const integrationSecret = "0123456789abcdef0123456789abcdef"

func TestDirectEmailFlowStoresDatabaseFieldBeforeUserHooks(t *testing.T) {
	var observedMethod any
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:          "http://auth.example.test",
		Secret:           integrationSecret,
		EmailAndPassword: fastEmailPasswordOptions(),
		PluginFactories: []singleauth.PluginFactory{
			NewFactory(Options{StoreInDatabase: true}),
		},
		DatabaseHooks: singleauth.DatabaseHooks{
			"user": {
				Create: singleauth.DatabaseOperationHooks{Before: func(
					user storage.Record,
					_ singleauth.DatabaseHookContext,
				) (singleauth.DatabaseHookResult, error) {
					observedMethod = user["lastLoginMethod"]
					return singleauth.DatabaseHookResult{}, nil
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Direct User", Email: "direct@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if observedMethod != "email" {
		t.Fatalf("user hook observed lastLoginMethod = %#v, want email", observedMethod)
	}
	response := contract.NewResponse(contract.StatusOK, result.Headers, nil)
	methodCookie, exists := responseCookie(response, DefaultCookieName)
	if !exists || methodCookie.Attributes.Value != "email" {
		t.Fatalf("direct cookies = %#v", result.Headers.Values("Set-Cookie"))
	}

	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "direct@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || user["lastLoginMethod"] != "email" {
		t.Fatalf("stored user = %#v", user)
	}

	plugin := auth.Options().Plugins[0]
	if plugin.ID != "last-login-method" || plugin.Version != Version ||
		len(plugin.RateLimit) != 0 || len(plugin.ErrorCodes) != 0 {
		t.Fatalf("plugin descriptor = %#v", plugin)
	}
}

func TestNetHTTPInheritsSessionCookiePolicyAndIgnoresCookiePrefix(t *testing.T) {
	secure := true
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:          "https://auth.example.com",
		Secret:           integrationSecret,
		EmailAndPassword: fastEmailPasswordOptions(),
		Advanced: singleauth.AdvancedOptions{
			UseSecureCookies: &secure,
			CookiePrefix:     "custom-auth",
			CrossSubDomainCookies: singleauth.CrossSubDomainCookieOptions{
				Enabled: true, Domain: "example.com",
			},
		},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{})},
	})
	if err != nil {
		t.Fatal(err)
	}

	recorder := serveJSON(t, auth, http.MethodPost, "/api/auth/sign-up/email", map[string]any{
		"name": "HTTP User", "email": "http@example.com", "password": "password123",
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := contract.NewResponse(recorder.Code, headersFromHTTP(recorder.Header()), nil)
	methodCookie, exists := responseCookie(response, DefaultCookieName)
	if !exists {
		t.Fatalf("method cookie missing from %#v", recorder.Header().Values("Set-Cookie"))
	}
	attributes := methodCookie.Attributes
	if attributes.Value != "email" || attributes.MaxAge == nil ||
		*attributes.MaxAge != DefaultMaxAge || attributes.Domain != "example.com" ||
		attributes.Path != "/" || !attributes.Secure || attributes.HTTPOnly ||
		attributes.SameSite != "lax" {
		t.Fatalf("method cookie = %#v", methodCookie)
	}
	if _, exists := responseCookie(response, "__Secure-custom-auth.session_token"); !exists {
		t.Fatalf("secure prefixed session cookie missing from %#v", recorder.Header().Values("Set-Cookie"))
	}
	if _, exists := responseCookie(response, "__Secure-custom-auth.last_used_login_method"); exists {
		t.Fatal("last-login cookie was incorrectly rewritten by the root prefix")
	}

	failed := serveJSON(t, auth, http.MethodPost, "/api/auth/sign-in/email", map[string]any{
		"email": "http@example.com", "password": "wrong-password",
	})
	failedResponse := contract.NewResponse(failed.Code, headersFromHTTP(failed.Header()), nil)
	if _, exists := responseCookie(failedResponse, DefaultCookieName); exists {
		t.Fatalf("failed authentication set method cookie: %#v", failed.Header().Values("Set-Cookie"))
	}
}

func TestCustomCookieNameAndConsentDoNotAffectDatabaseStorage(t *testing.T) {
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:          "http://auth.example.test",
		Secret:           integrationSecret,
		EmailAndPassword: fastEmailPasswordOptions(),
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			CookieName:      "app.last_method",
			StoreInDatabase: true,
			BeforeStoreCookie: func(HookContext, string) (bool, error) {
				return false, nil
			},
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Consent User", Email: "consent@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	response := contract.NewResponse(contract.StatusOK, result.Headers, nil)
	if _, exists := responseCookie(response, "app.last_method"); exists {
		t.Fatalf("blocked cookie present in %#v", result.Headers.Values("Set-Cookie"))
	}
	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "consent@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user["lastLoginMethod"] != "email" {
		t.Fatalf("database method = %#v", user["lastLoginMethod"])
	}
}

func TestDatabaseFieldRejectsClientSuppliedValue(t *testing.T) {
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:          "http://auth.example.test",
		Secret:           integrationSecret,
		EmailAndPassword: fastEmailPasswordOptions(),
		PluginFactories: []singleauth.PluginFactory{
			NewFactory(Options{StoreInDatabase: true}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := serveJSON(t, auth, http.MethodPost, "/api/auth/sign-up/email", map[string]any{
		"name": "Attacker", "email": "attacker@example.com", "password": "password123",
		"lastLoginMethod": "attacker-controlled",
	})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"FIELD_NOT_ALLOWED"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "attacker@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Fatalf("rejected user was stored: %#v", user)
	}
}

func fastEmailPasswordOptions() singleauth.EmailAndPasswordOptions {
	return singleauth.EmailAndPasswordOptions{
		Enabled: true,
		Password: singleauth.PasswordOptions{
			Hash: func(password string) (string, error) { return "test:" + password, nil },
			Verify: func(hash, password string) bool {
				return hash == "test:"+password
			},
		},
	}
}

func serveJSON(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body map[string]any,
) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, "https://auth.example.com"+path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func headersFromHTTP(source http.Header) contract.Headers {
	result := contract.Headers{}
	for name, values := range source {
		for _, value := range values {
			result.Add(name, value)
		}
	}
	return result
}
