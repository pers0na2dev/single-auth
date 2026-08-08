package twofactor

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestTrustedDeviceLifecycleAndMaxAge(t *testing.T) {
	t.Run("default and custom max age", func(t *testing.T) {
		for _, test := range []struct {
			name string
			age  time.Duration
			want int
		}{
			{name: "default", want: int(DefaultTrustDeviceMaxAge / time.Second)},
			{name: "custom", age: 7 * 24 * time.Hour, want: 7 * 24 * 60 * 60},
		} {
			t.Run(test.name, func(t *testing.T) {
				h := setupEnrolled(t, Options{TrustDeviceMaxAge: test.age}, nil)
				trusted := verifyChallengeWithTrust(t, h)
				cookie := responseCookie(trusted.headers.Values("Set-Cookie"), "trust_device")
				if cookie == nil || cookie.Attributes.MaxAge == nil || *cookie.Attributes.MaxAge != test.want {
					t.Fatalf("trust cookie=%#v lines=%#v", cookie, trusted.headers.Values("Set-Cookie"))
				}
			})
		}
	})

	t.Run("valid trust bypasses and rotates", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		trusted := verifyChallengeWithTrust(t, h)
		oldIdentifier := trustIdentifier(t, trusted.headers.Values("Set-Cookie"))
		trustHeader := onlyCookie(t, trusted.headers.Values("Set-Cookie"), "trust_device")
		result := invoke(t, h.auth, "signInEmail", http.MethodPost, "/sign-in/email", trustHeader, map[string]any{
			"email": testEmail, "password": testPass,
		})
		if result.status != http.StatusOK || result.body["twoFactorRedirect"] != nil || result.body["token"] == "" {
			t.Fatalf("trusted sign-in=%d %#v", result.status, result.body)
		}
		newIdentifier := trustIdentifier(t, result.headers.Values("Set-Cookie"))
		if newIdentifier == oldIdentifier {
			t.Fatalf("trust identifier was not rotated: %q", oldIdentifier)
		}
		oldRecord, err := h.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: oldIdentifier}},
		})
		if err != nil || oldRecord != nil {
			t.Fatalf("old trust record=%#v err=%v", oldRecord, err)
		}
		newRecord, err := h.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: newIdentifier}},
		})
		if err != nil || newRecord == nil {
			t.Fatalf("new trust record=%#v err=%v", newRecord, err)
		}
		oldCookieResult := invoke(t, h.auth, "signInEmail", http.MethodPost, "/sign-in/email", trustHeader, map[string]any{
			"email": testEmail, "password": testPass,
		})
		if oldCookieResult.status != http.StatusOK || oldCookieResult.body["twoFactorRedirect"] != true {
			t.Fatalf("old rotated trust remained valid=%d %#v", oldCookieResult.status, oldCookieResult.body)
		}
		newTrustHeader := onlyCookie(t, result.headers.Values("Set-Cookie"), "trust_device")
		newCookieResult := invoke(t, h.auth, "signInEmail", http.MethodPost, "/sign-in/email", newTrustHeader, map[string]any{
			"email": testEmail, "password": testPass,
		})
		if newCookieResult.status != http.StatusOK || newCookieResult.body["twoFactorRedirect"] != nil || newCookieResult.body["token"] == "" {
			t.Fatalf("rotated trust rejected=%d %#v", newCookieResult.status, newCookieResult.body)
		}
	})

	t.Run("expired server record forces challenge", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		trusted := verifyChallengeWithTrust(t, h)
		identifier := trustIdentifier(t, trusted.headers.Values("Set-Cookie"))
		record, err := h.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
		})
		if err != nil || record == nil {
			t.Fatalf("trust record=%#v err=%v", record, err)
		}
		id, _ := recordString(record, "id")
		if _, err := h.auth.Adapter().Update(t.Context(), storage.UpdateParams{
			Model: "verification", Where: []storage.Where{{Field: "id", Value: id}},
			Update: storage.Record{"expiresAt": h.clock.Now().Add(-time.Second)},
		}); err != nil {
			t.Fatal(err)
		}
		result := invoke(t, h.auth, "signInEmail", http.MethodPost, "/sign-in/email", onlyCookie(t, trusted.headers.Values("Set-Cookie"), "trust_device"), map[string]any{
			"email": testEmail, "password": testPass,
		})
		if result.status != http.StatusOK || result.body["twoFactorRedirect"] != true {
			t.Fatalf("expired trust=%d %#v", result.status, result.body)
		}
		expired := responseCookie(result.headers.Values("Set-Cookie"), "trust_device")
		if expired == nil || expired.Attributes.Value != "" || expired.Attributes.MaxAge == nil || *expired.Attributes.MaxAge != 0 {
			t.Fatalf("expired trust cookie=%#v", expired)
		}
	})

	t.Run("sign-out preserves trust", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		trusted := verifyChallengeWithTrust(t, h)
		logout := invoke(t, h.auth, "signOut", http.MethodPost, "/sign-out", trusted.cookie, map[string]any{})
		if logout.status != http.StatusOK {
			t.Fatalf("sign-out=%d %#v", logout.status, logout.body)
		}
		result := invoke(t, h.auth, "signInEmail", http.MethodPost, "/sign-in/email", logout.cookie, map[string]any{
			"email": testEmail, "password": testPass,
		})
		if result.status != http.StatusOK || result.body["twoFactorRedirect"] != nil || result.body["token"] == "" {
			t.Fatalf("post-signout trust=%d %#v", result.status, result.body)
		}
	})

	t.Run("disable revokes trust", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		trusted := verifyChallengeWithTrust(t, h)
		identifier := trustIdentifier(t, trusted.headers.Values("Set-Cookie"))
		disabled := invoke(t, h.auth, "disableTwoFactor", http.MethodPost, "/two-factor/disable", trusted.cookie, map[string]any{"password": testPass})
		if disabled.status != http.StatusOK {
			t.Fatalf("disable=%d %#v", disabled.status, disabled.body)
		}
		record, err := h.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
		})
		if err != nil || record != nil {
			t.Fatalf("trust record after disable=%#v err=%v", record, err)
		}
		expired := responseCookie(disabled.headers.Values("Set-Cookie"), "trust_device")
		if expired == nil || expired.Attributes.Value != "" {
			t.Fatalf("disable trust cookie=%#v", expired)
		}
	})
}

func TestTwoFactorChallengeCookieMaxAge(t *testing.T) {
	for _, test := range []struct {
		name string
		age  time.Duration
		want int
	}{
		{name: "default", want: int(DefaultTwoFactorCookieMaxAge / time.Second)},
		{name: "custom", age: 90 * time.Second, want: 90},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := setupEnrolled(t, Options{TwoFactorCookieMaxAge: test.age}, nil)
			challenge := h.challenge(t)
			cookie := responseCookie(challenge.headers.Values("Set-Cookie"), "two_factor")
			if cookie == nil || cookie.Attributes.MaxAge == nil || *cookie.Attributes.MaxAge != test.want {
				t.Fatalf("challenge cookie=%#v lines=%#v", cookie, challenge.headers.Values("Set-Cookie"))
			}
		})
	}
}

func verifyChallengeWithTrust(t *testing.T, h enrolledHarness) testResult {
	t.Helper()
	challenge := h.challenge(t)
	result := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", challenge.cookie, map[string]any{
		"code": h.currentTOTP(t), "trustDevice": true,
	})
	if result.status != http.StatusOK {
		t.Fatalf("trusted verification=%d %#v", result.status, result.body)
	}
	if responseCookie(result.headers.Values("Set-Cookie"), "trust_device") == nil {
		t.Fatalf("trust cookie missing: %#v", result.headers.Values("Set-Cookie"))
	}
	return result
}

func onlyCookie(t *testing.T, lines []string, suffix string) string {
	t.Helper()
	parsed := cookies.Parse("")
	for _, line := range lines {
		for _, cookie := range cookies.ParseSetCookieHeader(line) {
			if strings.HasSuffix(cookie.Name, "."+suffix) || cookie.Name == suffix {
				parsed.Set(cookie.Name, cookie.Attributes.Value)
			}
		}
	}
	if parsed.Header() == "" {
		t.Fatalf("cookie %q missing from %#v", suffix, lines)
	}
	return parsed.Header()
}

func trustIdentifier(t *testing.T, lines []string) string {
	t.Helper()
	cookie := responseCookie(lines, "trust_device")
	if cookie == nil || cookie.Attributes.Value == "" {
		t.Fatalf("trust cookie missing: %#v", lines)
	}
	signed := cookie.Attributes.Value
	dot := strings.LastIndexByte(signed, '.')
	if dot < 1 {
		t.Fatalf("trust cookie is not signed: %q", signed)
	}
	value := signed[:dot]
	_, identifier, found := strings.Cut(value, "!")
	if !found || identifier == "" {
		t.Fatalf("trust identifier missing: %q", value)
	}
	return identifier
}
