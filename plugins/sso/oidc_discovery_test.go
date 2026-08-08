package sso

import (
	"encoding/json"
	"net"
	"reflect"
	"testing"
)

func TestOIDCDiscoveryNormalizationAndAuthenticationSelection(t *testing.T) {
	for _, test := range []struct {
		issuer string
		want   string
	}{
		{"https://idp.example", "https://idp.example/.well-known/openid-configuration"},
		{"https://idp.example/", "https://idp.example/.well-known/openid-configuration"},
		{"https://idp.example/tenant", "https://idp.example/tenant/.well-known/openid-configuration"},
	} {
		if got := ComputeDiscoveryURL(test.issuer); got != test.want {
			t.Fatalf("ComputeDiscoveryURL(%q)=%q want %q", test.issuer, got, test.want)
		}
	}
	for _, test := range []struct {
		name, endpoint, issuer, want string
	}{
		{"absolute", "https://idp.example/token", "https://idp.example/tenant", "https://idp.example/token"},
		{"relative", "/token", "https://idp.example/tenant", "https://idp.example/tenant/token"},
		{"nested", "oauth/token", "https://idp.example/tenant/", "https://idp.example/tenant/oauth/token"},
	} {
		got, err := normalizeOIDCEndpoint(test.name, test.endpoint, test.issuer)
		if err != nil || got != test.want {
			t.Fatalf("normalize %s=%q err=%v want %q", test.name, got, err, test.want)
		}
	}
	if got := selectOIDCTokenAuth([]string{"client_secret_post", "client_secret_basic"}); got != "client_secret_basic" {
		t.Fatalf("preferred auth=%q", got)
	}
	if got := selectOIDCTokenAuth([]string{"private_key_jwt", "client_secret_post"}); got != "client_secret_post" {
		t.Fatalf("post auth=%q", got)
	}
	if got := selectOIDCTokenAuth([]string{"private_key_jwt"}); got != "client_secret_basic" {
		t.Fatalf("fallback auth=%q", got)
	}
}

func TestOIDCSSRFHostClassification(t *testing.T) {
	for _, host := range []string{
		"localhost", "127.0.0.1", "10.1.2.3", "100.64.0.1", "169.254.169.254",
		"192.168.1.2", "::1", "fc00::1", "metadata.google.internal",
	} {
		if publicOIDCHost(host) {
			t.Errorf("host %q classified public", host)
		}
	}
	for _, host := range []string{"idp.example.com", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicOIDCHost(host) {
			t.Errorf("host %q classified private", host)
		}
	}
	if publicOIDCIP(net.ParseIP("198.51.100.7")) || !publicOIDCIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("reserved/public IP classification mismatch")
	}
}

func TestOIDCProfileMappingAndStrictEmailVerification(t *testing.T) {
	profile := map[string]any{
		"subject": json.Number("42"), "mail": "User@Example.com", "display": "Mapped User",
		"avatar": "https://images.example/mapped.png", "verified": "true", "team": "security",
	}
	mapping := OIDCMapping{
		ID: "subject", Email: "mail", EmailVerified: "verified", Name: "display", Image: "avatar",
		ExtraFields: map[string]string{"department": "team"},
	}
	user := mapOIDCProfile(profile, mapping, true)
	if user.ID != "42" || user.Email == nil || *user.Email != "User@Example.com" || !user.EmailVerified ||
		user.Name != "Mapped User" || user.Image != "https://images.example/mapped.png" || user.Extra["department"] != "security" {
		t.Fatalf("mapped user=%#v", user)
	}
	for _, value := range []any{false, "false", "0", 1, []any{"true"}, map[string]any{"value": true}} {
		if parseOIDCEmailVerified(value) {
			t.Errorf("email verification accepted %#v", value)
		}
	}
	if !parseOIDCEmailVerified(true) || !parseOIDCEmailVerified("true") {
		t.Fatal("strict true values were rejected")
	}
	untrusted := mapOIDCProfile(profile, mapping, false)
	if untrusted.EmailVerified {
		t.Fatal("provider verification was trusted while option was disabled")
	}
}

func TestOIDCConfigCloneDoesNotAliasMutableFields(t *testing.T) {
	enabled := false
	original := &OIDCConfig{
		Scopes: []string{"openid"}, ScopesSupported: []string{"openid", "email"}, PKCE: &enabled,
		Mapping: OIDCMapping{ExtraFields: map[string]string{"team": "group"}},
	}
	clone := cloneOIDCConfig(original)
	clone.Scopes[0] = "profile"
	clone.ScopesSupported[0] = "offline_access"
	clone.Mapping.ExtraFields["team"] = "department"
	*clone.PKCE = true
	if !reflect.DeepEqual(original.Scopes, []string{"openid"}) ||
		!reflect.DeepEqual(original.ScopesSupported, []string{"openid", "email"}) ||
		original.Mapping.ExtraFields["team"] != "group" || *original.PKCE {
		t.Fatalf("clone mutated original=%#v", original)
	}
}
