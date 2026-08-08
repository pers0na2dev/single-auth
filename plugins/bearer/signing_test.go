package bearer

import "testing"

func TestSigningAndDecoderExpectedValues(t *testing.T) {
	values := loadBearerTestValues(t)
	if got := signCookieValue(values.UnsignedToken, values.Secret); got != values.SignedToken {
		t.Fatalf("signed token = %q, want %q", got, values.SignedToken)
	}
	for _, valid := range []string{
		values.SignedToken,
		values.UnsignedToken + "." + values.URLSafeSignature,
		values.SignedToken + "ignored-after-padding",
		values.SignedToken + ".ignored-segment",
	} {
		if !verifySignedCookie(valid, values.Secret) {
			t.Fatalf("valid upstream representation rejected: %q", valid)
		}
	}
	for _, invalid := range []string{
		"", "no-dot", values.UnsignedToken + ".", values.UnsignedToken + ".not-base64!",
		values.UnsignedToken + "." + values.URLSafeSignature[:len(values.URLSafeSignature)-1] + "A",
	} {
		if verifySignedCookie(invalid, values.Secret) {
			t.Fatalf("invalid signature accepted: %q", invalid)
		}
	}
}

func TestDecodeURIComponentMatchesJavaScriptFailureSemantics(t *testing.T) {
	for input, want := range map[string]string{
		"plain":       "plain",
		"a%2Fb%3Dc":   "a/b=c",
		"bad%ZZvalue": "bad%ZZvalue",
		"%FF":         "%FF",
		"%E0%A4%A":    "%E0%A4%A",
	} {
		if got := tryDecodeURIComponent(input); got != want {
			t.Fatalf("tryDecodeURIComponent(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSchemeAndJavaScriptTrimBoundaries(t *testing.T) {
	for _, valid := range []string{"bearer ", "Bearer token", "BEARER  token", "BeArEr \uFEFFtoken"} {
		if !hasBearerScheme(valid) {
			t.Fatalf("valid scheme rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", "bearer", " bearer token", "Bearer\ttoken", "Basic token", "Xearer token"} {
		if hasBearerScheme(invalid) {
			t.Fatalf("invalid scheme accepted: %q", invalid)
		}
	}
	if got := trimJavaScriptSpace("\uFEFF \tvalue\u2029"); got != "value" {
		t.Fatalf("JavaScript trim = %q", got)
	}
	if got := trimJavaScriptSpace("\u0085value\u0085"); got != "\u0085value\u0085" {
		t.Fatalf("non-ECMAScript NEL was trimmed: %q", got)
	}
}

func TestMustNew(t *testing.T) {
	values := loadBearerTestValues(t)
	plugin := MustNew(Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}})
	if plugin.ID != "bearer" {
		t.Fatalf("plugin ID = %q", plugin.ID)
	}
	t.Run("panics on invalid runtime", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("MustNew did not panic")
			}
		}()
		_ = MustNew(Options{})
	})
}
