package multisession

import "testing"

func TestMultiSessionCookieSemantics(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{name: "single-auth.session_token_multi-token", want: true},
		{name: "prefix_multi-suffix", want: true},
		{name: "single-auth.session_token", want: false},
		{name: "_MULTI-token", want: false},
	} {
		if got := isMultiSessionCookie(test.name); got != test.want {
			t.Errorf("isMultiSessionCookie(%q) = %v, want %v", test.name, got, test.want)
		}
	}

	for _, test := range []struct {
		base  string
		token string
		want  string
	}{
		{
			base:  "single-auth.session_token",
			token: "TokenABC",
			want:  "single-auth.session_token_multi-tokenabc",
		},
		{
			base:  "__Secure-custom.session_token",
			token: "MiXeD-123",
			want:  "__Secure-custom.session_token_multi-mixed-123",
		},
	} {
		if got := multiCookieName(test.base, test.token); got != test.want {
			t.Errorf("multiCookieName(%q, %q) = %q, want %q", test.base, test.token, got, test.want)
		}
	}

	for _, test := range []struct {
		keys, deleted int
		active        bool
		maximum       int
		count         int
		canWrite      bool
	}{
		{active: true, maximum: 5, count: 1, canWrite: true},
		{keys: 2, active: true, maximum: 2, count: 3, canWrite: false},
		{keys: 2, deleted: 1, active: true, maximum: 2, count: 2, canWrite: true},
		{active: true, count: 1, canWrite: false},
	} {
		count := multiCookieCount(test.keys, test.deleted, test.active)
		if count != test.count || (count <= test.maximum) != test.canWrite {
			t.Errorf("count=%d canWrite=%v, want count=%d canWrite=%v", count, count <= test.maximum, test.count, test.canWrite)
		}
	}

	for _, test := range []struct {
		name string
		want string
	}{
		{name: "__Secure-Custom.Session_Token_multi-AbC", want: "__Secure-custom.session_token_multi-abc"},
		{name: "single-auth.session_token_multi-AbC", want: "single-auth.session_token_multi-abc"},
	} {
		if got := secureCookieDeleteName(test.name); got != test.want {
			t.Errorf("secureCookieDeleteName(%q) = %q, want %q", test.name, got, test.want)
		}
	}

	const secret = "0123456789abcdef0123456789abcdef"
	const expected = "TokenABC.5MTr0YjuI2MwRSKX/c331OkTEPjKhvIPdloaJ4SX9As="
	if got := signedCookieValue("TokenABC", secret); got != expected {
		t.Fatalf("signedCookieValue() = %q, want %q", got, expected)
	}
}

func TestFactorySnapshotsMaximumSessions(t *testing.T) {
	maximum := 2
	factory := NewFactory(Options{MaximumSessions: &maximum}).(*rootFactory)
	maximum = 99
	if factory.options.MaximumSessions == nil || *factory.options.MaximumSessions != 2 {
		t.Fatalf("factory maximum = %#v", factory.options.MaximumSessions)
	}
}
