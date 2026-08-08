package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestCookieSecurityAndCrossSubDomainDefaults(t *testing.T) {
	production, err := New(Options{Environment: "production", Secret: "0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	config := production.options.cookie
	if !strings.HasPrefix(config.sessionName, "__Secure-") || !config.sessionToken.Secure {
		t.Fatalf("production cookie = %q %#v", config.sessionName, config.sessionToken)
	}

	insecure := false
	overridden := MustNew(Options{
		Environment: "production", Secret: "0123456789abcdef0123456789abcdef",
		Advanced: AdvancedOptions{UseSecureCookies: &insecure},
	})
	if strings.HasPrefix(overridden.options.cookie.sessionName, "__Secure-") || overridden.options.cookie.sessionToken.Secure {
		t.Fatalf("explicit insecure cookie = %q %#v", overridden.options.cookie.sessionName, overridden.options.cookie.sessionToken)
	}

	static := MustNew(Options{
		BaseURL:  "https://auth.example.com",
		Advanced: AdvancedOptions{CrossSubDomainCookies: CrossSubDomainCookieOptions{Enabled: true}},
	})
	if static.options.cookie.sessionToken.Domain != "auth.example.com" {
		t.Fatalf("static cross-domain cookie = %#v", static.options.cookie.sessionToken)
	}
	if _, err := New(Options{
		Advanced: AdvancedOptions{CrossSubDomainCookies: CrossSubDomainCookieOptions{Enabled: true}},
	}); err == nil || !strings.Contains(err.Error(), "base URL is required") {
		t.Fatalf("missing cross-domain base URL error = %v", err)
	}
}

func TestDynamicCrossSubDomainCookiesRehydratePerRequest(t *testing.T) {
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{
			AllowedHosts: []string{"auth.one.example", "auth.two.example"}, Protocol: "https",
		},
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Advanced: AdvancedOptions{
			CrossSubDomainCookies: CrossSubDomainCookieOptions{Enabled: true},
		},
	})
	for index, host := range []string{"auth.one.example", "auth.two.example"} {
		body, err := json.Marshal(map[string]any{
			"name": "Dynamic", "email": "dynamic" + strconv.Itoa(index+1) + "@example.com", "password": "password123",
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "http://internal/api/auth/sign-up/email", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Forwarded-Host", host)
		request.Header.Set("X-Forwarded-Proto", "https")
		request.Header.Set("Origin", "https://"+host)
		response := httptest.NewRecorder()
		auth.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", host, response.Code, response.Body.String())
		}
		setCookie := strings.Join(response.Header().Values("Set-Cookie"), "\n")
		if !strings.Contains(setCookie, "__Secure-single-auth.session_token=") ||
			!strings.Contains(setCookie, "Domain="+host) || !strings.Contains(setCookie, "; Secure") {
			t.Fatalf("%s set-cookie = %q", host, setCookie)
		}
		other := "auth.one.example"
		if host == other {
			other = "auth.two.example"
		}
		if strings.Contains(setCookie, "Domain="+other) {
			t.Fatalf("%s leaked prior domain in %q", host, setCookie)
		}
	}
}
