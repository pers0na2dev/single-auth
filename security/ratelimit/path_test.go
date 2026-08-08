package ratelimit

import "testing"

func TestNormalizePathname(t *testing.T) {
	t.Parallel()
	tests := []struct {
		url, base, want string
	}{
		{"http://localhost:3000/api/auth/sso/saml2/callback/provider1", "/api/auth", "/sso/saml2/callback/provider1"},
		{"http://localhost:3000/api/auth/", "/api/auth/", "/"},
		{"http://localhost:3000/api/auth/sign-in/email///?a=1", "/api/auth", "/sign-in/email"},
		{"http://localhost:3000/api/authevil/sign-in", "/api/auth", "/api/authevil/sign-in"},
		{"http://localhost:3000/sign-in/", "/", "/sign-in"},
		{"relative/path", "/api/auth", "/"},
		{"%", "/api/auth", "/"},
	}
	for _, test := range tests {
		if got := NormalizePathname(test.url, test.base); got != test.want {
			t.Errorf("NormalizePathname(%q, %q) = %q, want %q", test.url, test.base, got, test.want)
		}
	}
}

func TestWildcardMatchMatchesPathSemantics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern, sample string
		want            bool
	}{
		{"/sign-in/*", "/sign-in/email", true},
		{"/sign-in/*", "/sign-in/email/extra", false},
		{"/**/callback/*", "/oauth/deep/callback/google", true},
		{"/foo/?ar", "/foo/bar", true},
		{"/foo/?ar", "/foo/x/bar", false},
		{"/foo/bar", "/foo//bar///", true},
	}
	for _, test := range tests {
		if got := WildcardMatch(test.pattern, test.sample); got != test.want {
			t.Errorf("WildcardMatch(%q, %q) = %v, want %v", test.pattern, test.sample, got, test.want)
		}
	}
}

func FuzzNormalizePathnameNeverPanics(f *testing.F) {
	f.Add("https://example.com/api/auth/sign-in", "/api/auth")
	f.Add("%", "/")
	f.Fuzz(func(t *testing.T, value, base string) {
		_ = NormalizePathname(value, base)
		_ = WildcardMatch(value, base)
	})
}
