package passkey_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/passkey"
)

func TestRootFactoryBindsSchemaSessionsAndCookiePolicy(t *testing.T) {
	secure := true
	auth, err := singleauth.New(singleauth.Options{
		AppName: "Passkey App",
		BaseURL: "https://auth.example.test",
		Secret:  "0123456789abcdef0123456789abcdef",
		Advanced: singleauth.AdvancedOptions{
			UseSecureCookies: &secure,
			CookiePrefix:     "factory-auth",
		},
		PluginFactories: []singleauth.PluginFactory{passkey.NewFactory(passkey.Options{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := auth.Options().Schema.Models["passkey"]; !exists {
		t.Fatal("passkey factory schema was not installed")
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"https://auth.example.test/api/auth/passkey/generate-authenticate-options",
		nil,
	)
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	setCookie := recorder.Header().Get("Set-Cookie")
	if !strings.HasPrefix(setCookie, "__Secure-factory-auth.single-auth-passkey=") ||
		!strings.Contains(setCookie, "Max-Age=300") || !strings.Contains(setCookie, "Secure") {
		t.Fatalf("challenge Set-Cookie = %q", setCookie)
	}
}
