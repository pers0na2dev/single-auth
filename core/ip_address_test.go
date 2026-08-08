package core

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestRootIPAddressResolutionMatchesAdvancedOptions(t *testing.T) {
	request := func(headers contract.Headers) contract.Request {
		return contract.NewRequest(http.MethodGet, "/", contract.RequestOptions{Headers: headers})
	}
	headers := func(fields ...contract.HeaderField) contract.Headers {
		return contract.NewHeaders(fields...)
	}
	secureSecret := "0123456789abcdef0123456789abcdef"

	tests := []struct {
		name        string
		environment string
		options     ratelimit.IPOptions
		headers     contract.Headers
		want        string
	}{
		{
			name: "default x-forwarded-for", headers: headers(
				contract.HeaderField{Name: "X-Forwarded-For", Value: "192.0.2.10"},
			), want: "192.0.2.10",
		},
		{
			name: "default rejects untrusted chain", headers: headers(
				contract.HeaderField{Name: "X-Forwarded-For", Value: "192.0.2.10, 10.0.0.2"},
			), want: "",
		},
		{
			name: "default ignores unrelated and peer-derived headers", headers: headers(
				contract.HeaderField{Name: "X-Client-IP", Value: "192.0.2.11"},
				contract.HeaderField{Name: "CF-Connecting-IP", Value: "192.0.2.12"},
			), want: "",
		},
		{
			name: "configured header order", options: ratelimit.IPOptions{Headers: []string{"x-client-ip", "cf-connecting-ip"}},
			headers: headers(
				contract.HeaderField{Name: "X-Client-IP", Value: "invalid"},
				contract.HeaderField{Name: "CF-Connecting-IP", Value: "198.51.100.7"},
			), want: "198.51.100.7",
		},
		{
			name: "explicit empty headers", options: ratelimit.IPOptions{Headers: []string{}},
			headers: headers(contract.HeaderField{Name: "X-Forwarded-For", Value: "192.0.2.10"}), want: "",
		},
		{
			name: "tracking disabled", options: ratelimit.IPOptions{DisableTracking: true},
			headers: headers(contract.HeaderField{Name: "X-Forwarded-For", Value: "192.0.2.10"}), want: "",
		},
		{
			name: "trusted proxy chain", options: ratelimit.IPOptions{TrustedProxies: []string{"10.0.0.0/8"}},
			headers: headers(contract.HeaderField{Name: "X-Forwarded-For", Value: "203.0.113.9, 10.0.0.2"}),
			want:    "203.0.113.9",
		},
		{name: "development fallback", environment: "development", want: "127.0.0.1"},
		{name: "test fallback", environment: "test", want: "127.0.0.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := MustNew(Options{
				Secret: secureSecret, Environment: test.environment,
				Advanced: AdvancedOptions{IPAddress: test.options},
			})
			if got := auth.resolveIPAddress(request(test.headers)); got != test.want {
				t.Fatalf("IP=%q want=%q", got, test.want)
			}
		})
	}
}

func TestRootIPAddressIPv6SnapshotWarningAndSessionPersistence(t *testing.T) {
	prefix := 48
	headerNames := []string{"x-real-ip"}
	trusted := []string{"bad-cidr", "fc00::/7"}
	var warnings []string
	auth := MustNew(Options{
		Environment:      "production",
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Advanced: AdvancedOptions{IPAddress: ratelimit.IPOptions{
			Headers: headerNames, TrustedProxies: trusted, IPv6Subnet: &prefix,
		}},
		Logger: logger.Options{Log: func(level logger.Level, message string, _ ...any) {
			if level == logger.Warn {
				warnings = append(warnings, message)
			}
		}},
	})
	if len(warnings) != 1 || !strings.Contains(warnings[0], "bad-cidr") || !strings.Contains(warnings[0], "advanced.ipAddress.trustedProxies") {
		t.Fatalf("warnings=%#v", warnings)
	}

	// Mutating caller-owned slices and pointers after New must not affect the
	// runtime resolver.
	headerNames[0] = "x-mutated"
	trusted[1] = "0.0.0.0/0"
	prefix = 128
	requestHeaders := contract.NewHeaders(contract.HeaderField{
		Name: "X-Real-IP", Value: "2001:db8:abcd:1234::1, fc00::1",
	})
	request := contract.NewRequest(http.MethodGet, "/", contract.RequestOptions{Headers: requestHeaders})
	if got := auth.resolveIPAddress(request); got != "2001:0db8:abcd:0000:0000:0000:0000:0000" {
		t.Fatalf("snapshotted IPv6=%q", got)
	}

	body := bytes.NewBufferString(`{"name":"IP User","email":"ip-session@example.com","password":"password123"}`)
	httpRequest := httptest.NewRequest(http.MethodPost, "http://auth.test/api/auth/sign-up/email", body)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("X-Real-IP", "2001:db8:abcd:beef::1, fc00::2")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, httpRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	sessions, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "session"})
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions=%#v err=%v", sessions, err)
	}
	if got := sessions[0]["ipAddress"]; got != "2001:0db8:abcd:0000:0000:0000:0000:0000" {
		t.Fatalf("stored IP=%#v", got)
	}
}
