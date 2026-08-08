package multisession_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/customsession"
	"github.com/pers0na2dev/single-auth/plugins/multisession"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestRootLifecycleMaximumDedupeFallbackAndSignOut(t *testing.T) {
	auth := newAuth(t, multisession.Int(2), nil)

	first, cookie, firstToken := signUp(t, auth, "", "first@example.test")
	firstMultiName := "single-auth.session_token_multi-" + strings.ToLower(firstToken)
	firstMulti := responseCookie(first.headers.Values("Set-Cookie"), firstMultiName)
	if firstMulti == nil || unsignedCookieToken(firstMulti.Attributes.Value) != firstToken {
		t.Fatalf("first multi cookie = %#v", firstMulti)
	}

	_, cookie, secondToken := signUp(t, auth, cookie, "second@example.test")
	listed := exchange(t, auth.Handler(), http.MethodGet, "/multi-session/list-device-sessions", cookie, nil)
	if listed.status != http.StatusOK || len(valueArray(t, listed.value)) != 2 {
		t.Fatalf("initial list status=%d body=%#v", listed.status, listed.value)
	}
	multiOnly := withoutRequestCookie(cookie, "single-auth.session_token")
	activatedWithoutPrimary := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", multiOnly, map[string]any{
		"sessionToken": firstToken,
	})
	if activatedWithoutPrimary.status != http.StatusOK ||
		nestedEmail(t, activatedWithoutPrimary.value) != "first@example.test" {
		t.Fatalf("multi-only activate status=%d body=%#v", activatedWithoutPrimary.status, activatedWithoutPrimary.value)
	}

	activated := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", cookie, map[string]any{
		"sessionToken": firstToken,
	})
	if activated.status != http.StatusOK || nestedEmail(t, activated.value) != "first@example.test" {
		t.Fatalf("activate status=%d body=%#v", activated.status, activated.value)
	}
	cookie = cookies.ApplySetCookies(cookie, activated.headers.Values("Set-Cookie"))

	signedIn, cookie, replacementToken := signIn(t, auth, cookie, "first@example.test")
	if replacementToken == firstToken {
		t.Fatal("same-user sign-in reused its session token")
	}
	expiredOld := responseCookie(signedIn.headers.Values("Set-Cookie"), firstMultiName)
	if expiredOld == nil || expiredOld.Attributes.MaxAge == nil || *expiredOld.Attributes.MaxAge != 0 {
		t.Fatalf("old same-user cookie was not expired: %#v", expiredOld)
	}
	oldSession, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: firstToken}},
	})
	if err != nil || oldSession != nil {
		t.Fatalf("old same-user session = %#v, err=%v", oldSession, err)
	}
	listed = exchange(t, auth.Handler(), http.MethodGet, "/multi-session/list-device-sessions", cookie, nil)
	if sessions := valueArray(t, listed.value); len(sessions) != 2 ||
		!hasSessionToken(t, sessions, replacementToken) || !hasSessionToken(t, sessions, secondToken) {
		t.Fatalf("same-user replacement list = %#v", sessions)
	}

	third, cookie, thirdToken := signUp(t, auth, cookie, "third@example.test")
	thirdMultiName := "single-auth.session_token_multi-" + strings.ToLower(thirdToken)
	if responseCookie(third.headers.Values("Set-Cookie"), thirdMultiName) != nil {
		t.Fatalf("maximumSessions=2 admitted third cookie: %#v", third.headers.Values("Set-Cookie"))
	}
	listed = exchange(t, auth.Handler(), http.MethodGet, "/multi-session/list-device-sessions", cookie, nil)
	if sessions := valueArray(t, listed.value); len(sessions) != 2 || hasSessionToken(t, sessions, thirdToken) {
		t.Fatalf("maximum list = %#v", sessions)
	}

	activated = exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", cookie, map[string]any{
		"sessionToken": replacementToken,
	})
	if activated.status != http.StatusOK {
		t.Fatalf("activate replacement status=%d body=%#v", activated.status, activated.value)
	}
	cookie = cookies.ApplySetCookies(cookie, activated.headers.Values("Set-Cookie"))
	revoked := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/revoke", cookie, map[string]any{
		"sessionToken": replacementToken,
	})
	if revoked.status != http.StatusOK || valueObject(t, revoked.value)["status"] != true {
		t.Fatalf("revoke status=%d body=%#v", revoked.status, revoked.value)
	}
	cookie = cookies.ApplySetCookies(cookie, revoked.headers.Values("Set-Cookie"))
	current := exchange(t, auth.Handler(), http.MethodGet, "/get-session", cookie, nil)
	if current.status != http.StatusOK || nestedEmail(t, current.value) != "second@example.test" {
		t.Fatalf("fallback active status=%d body=%#v", current.status, current.value)
	}

	signedOut := exchange(t, auth.Handler(), http.MethodPost, "/sign-out", cookie, map[string]any{})
	if signedOut.status != http.StatusOK {
		t.Fatalf("sign-out status=%d body=%#v", signedOut.status, signedOut.value)
	}
	for _, name := range []string{
		"single-auth.session_token_multi-" + strings.ToLower(secondToken),
	} {
		deleted := responseCookie(signedOut.headers.Values("Set-Cookie"), name)
		if deleted == nil || deleted.Attributes.MaxAge == nil || *deleted.Attributes.MaxAge != 0 {
			t.Fatalf("sign-out cookie %q = %#v", name, deleted)
		}
	}
	cookie = cookies.ApplySetCookies(cookie, signedOut.headers.Values("Set-Cookie"))
	listed = exchange(t, auth.Handler(), http.MethodGet, "/multi-session/list-device-sessions", cookie, nil)
	if listed.status != http.StatusOK || len(valueArray(t, listed.value)) != 0 {
		t.Fatalf("post-sign-out list status=%d body=%#v", listed.status, listed.value)
	}
}

func TestRevokeNonActiveSessionPreservesCurrentSession(t *testing.T) {
	auth := newAuth(t, nil, nil)
	_, cookie, firstToken := signUp(t, auth, "", "revoke-first@example.test")
	_, cookie, secondToken := signUp(t, auth, cookie, "revoke-second@example.test")
	revoked := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/revoke", cookie, map[string]any{
		"sessionToken": firstToken,
	})
	if revoked.status != http.StatusOK {
		t.Fatalf("non-active revoke status=%d body=%#v", revoked.status, revoked.value)
	}
	cookie = cookies.ApplySetCookies(cookie, revoked.headers.Values("Set-Cookie"))
	current := exchange(t, auth.Handler(), http.MethodGet, "/get-session", cookie, nil)
	if current.status != http.StatusOK || sessionToken(t, current.value) != secondToken {
		t.Fatalf("current after non-active revoke status=%d body=%#v", current.status, current.value)
	}
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: firstToken}},
	})
	if err != nil || stored != nil {
		t.Fatalf("non-active revoked session = %#v, err=%v", stored, err)
	}
}

func TestSetActiveAndRevokeUseSignedCookieValueNotBodyToken(t *testing.T) {
	auth := newAuth(t, nil, nil)
	callerResult, callerCookie, callerToken := signUp(t, auth, "", "caller@example.test")
	_, otherCookie, otherToken := signUp(t, auth, "", "other@example.test")
	callerMultiName := "single-auth.session_token_multi-" + strings.ToLower(callerToken)
	callerMulti := responseCookie(callerResult.headers.Values("Set-Cookie"), callerMultiName)
	if callerMulti == nil {
		t.Fatal("caller multi cookie missing")
	}
	craftedName := "single-auth.session_token_multi-" + strings.ToLower(otherToken)
	crafted := cookies.SetRequestCookie(callerCookie, craftedName, callerMulti.Attributes.Value)

	activated := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", crafted, map[string]any{
		"sessionToken": otherToken,
	})
	if activated.status != http.StatusOK || nestedEmail(t, activated.value) != "caller@example.test" {
		t.Fatalf("bound activate status=%d body=%#v", activated.status, activated.value)
	}

	revoked := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/revoke", crafted, map[string]any{
		"sessionToken": otherToken,
	})
	if revoked.status != http.StatusOK {
		t.Fatalf("bound revoke status=%d body=%#v", revoked.status, revoked.value)
	}
	other := exchange(t, auth.Handler(), http.MethodGet, "/get-session", otherCookie, nil)
	if other.status != http.StatusOK || sessionToken(t, other.value) != otherToken {
		t.Fatalf("other session was affected: status=%d body=%#v", other.status, other.value)
	}
	callerStored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: callerToken}},
	})
	if err != nil || callerStored != nil {
		t.Fatalf("authoritative caller session = %#v, err=%v", callerStored, err)
	}
}

func TestForgedCookiesAreIgnoredAndNotDeletedOnSignOut(t *testing.T) {
	auth := newAuth(t, nil, nil)
	_, attackerCookie, _ := signUp(t, auth, "", "attacker@example.test")
	_, victimCookie, victimToken := signUp(t, auth, "", "victim@example.test")
	forgedName := "single-auth.session_token_multi-" + strings.ToLower(victimToken)
	forged := cookies.SetRequestCookie(attackerCookie, forgedName, victimToken+".fake-signature")

	listed := exchange(t, auth.Handler(), http.MethodGet, "/multi-session/list-device-sessions", forged, nil)
	if listed.status != http.StatusOK || len(valueArray(t, listed.value)) != 1 {
		t.Fatalf("forged list status=%d body=%#v", listed.status, listed.value)
	}
	signedOut := exchange(t, auth.Handler(), http.MethodPost, "/sign-out", forged, map[string]any{})
	if signedOut.status != http.StatusOK {
		t.Fatalf("forged sign-out status=%d body=%#v", signedOut.status, signedOut.value)
	}
	if responseCookie(signedOut.headers.Values("Set-Cookie"), forgedName) != nil {
		t.Fatalf("forged cookie was expired: %#v", signedOut.headers.Values("Set-Cookie"))
	}
	victim := exchange(t, auth.Handler(), http.MethodGet, "/get-session", victimCookie, nil)
	if victim.status != http.StatusOK || sessionToken(t, victim.value) != victimToken {
		t.Fatalf("victim after forged sign-out status=%d body=%#v", victim.status, victim.value)
	}
}

func TestExpiredSetActiveCookieAndActiveRevokeWithoutFallback(t *testing.T) {
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	auth := newAuth(t, nil, func(options *singleauth.Options) {
		options.Clock = func() time.Time { return now }
	})
	_, cookie, token := signUp(t, auth, "", "expires@example.test")
	if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
		Update: storage.Record{"expiresAt": now.Add(-time.Second)},
	}); err != nil {
		t.Fatal(err)
	}
	invalid := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", cookie, map[string]any{
		"sessionToken": token,
	})
	if invalid.status != http.StatusUnauthorized ||
		valueObject(t, invalid.value)["code"] != multisession.ErrorInvalidSessionToken {
		t.Fatalf("expired activate status=%d body=%#v", invalid.status, invalid.value)
	}
	name := "single-auth.session_token_multi-" + strings.ToLower(token)
	expired := responseCookie(invalid.headers.Values("Set-Cookie"), name)
	if expired == nil || expired.Attributes.MaxAge == nil || *expired.Attributes.MaxAge != 0 {
		t.Fatalf("expired activation cookie = %#v", expired)
	}
	if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
		Update: storage.Record{"expiresAt": now},
	}); err != nil {
		t.Fatal(err)
	}
	equalExpiry := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", cookie, map[string]any{
		"sessionToken": token,
	})
	if equalExpiry.status != http.StatusOK {
		t.Fatalf("equal expiry must follow upstream < check: status=%d body=%#v", equalExpiry.status, equalExpiry.value)
	}
	equalList := exchange(t, auth.Handler(), http.MethodGet, "/multi-session/list-device-sessions", cookie, nil)
	if equalList.status != http.StatusOK || len(valueArray(t, equalList.value)) != 0 {
		t.Fatalf("equal expiry list status=%d body=%#v", equalList.status, equalList.value)
	}

	// Restore the record to exercise the no-fallback deletion branch.
	if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
		Update: storage.Record{"expiresAt": now.Add(time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	revoked := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/revoke", cookie, map[string]any{
		"sessionToken": token,
	})
	if revoked.status != http.StatusOK {
		t.Fatalf("sole revoke status=%d body=%#v", revoked.status, revoked.value)
	}
	for _, suffix := range []string{".session_token", ".session_data", ".dont_remember"} {
		deleted := responseCookieBySuffix(revoked.headers.Values("Set-Cookie"), suffix)
		if deleted == nil || deleted.Attributes.MaxAge == nil || *deleted.Attributes.MaxAge != 0 {
			t.Fatalf("deleted %s cookie = %#v", suffix, deleted)
		}
	}
}

func TestDynamicCookieConfigurationIsResolvedPerRequest(t *testing.T) {
	auth := newAuth(t, nil, func(options *singleauth.Options) {
		options.BaseURL = ""
		options.DynamicBaseURL = &singleauth.DynamicBaseURLOptions{
			AllowedHosts: []string{"auth.one.example", "auth.two.example"}, Protocol: "https",
		}
		options.Advanced = singleauth.AdvancedOptions{
			CookiePrefix:          "custom-auth",
			CrossSubDomainCookies: singleauth.CrossSubDomainCookieOptions{Enabled: true},
		}
	})
	for index, host := range []string{"auth.one.example", "auth.two.example"} {
		body, _ := json.Marshal(map[string]any{
			"name": "Dynamic", "email": "dynamic" + string(rune('1'+index)) + "@example.test", "password": "password123",
		})
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
		var multi *cookies.SetCookie
		for _, line := range response.Header().Values("Set-Cookie") {
			for _, parsed := range cookies.ParseSetCookieHeader(line) {
				if strings.Contains(parsed.Name, ".session_token_multi-") {
					value := parsed
					multi = &value
				}
			}
		}
		if multi == nil || !strings.HasPrefix(multi.Name, "__Secure-custom-auth.session_token_multi-") ||
			multi.Attributes.Domain != host || !multi.Attributes.Secure ||
			multi.Attributes.Path != "/" || !multi.Attributes.HTTPOnly ||
			multi.Attributes.SameSite != "lax" || multi.Attributes.MaxAge == nil {
			t.Fatalf("%s multi cookie = %#v", host, multi)
		}
		other := "auth.one.example"
		if host == other {
			other = "auth.two.example"
		}
		if multi.Attributes.Domain == other {
			t.Fatalf("%s leaked domain %s", host, other)
		}
	}
}

func TestDontRememberCookieControlsActivatedSessionLifetime(t *testing.T) {
	auth := newAuth(t, nil, nil)
	_, cookie, token := signUp(t, auth, "", "remember@example.test")
	value := "true"
	signed := value + "." + baCrypto.MakeSignature(value, testSecret)
	cookie = cookies.SetRequestCookie(cookie, "single-auth.dont_remember", signed)
	activated := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", cookie, map[string]any{
		"sessionToken": token,
	})
	if activated.status != http.StatusOK {
		t.Fatalf("activate status=%d body=%#v", activated.status, activated.value)
	}
	active := responseCookie(activated.headers.Values("Set-Cookie"), "single-auth.session_token")
	if active == nil || active.Attributes.MaxAge != nil {
		t.Fatalf("dont-remember active cookie = %#v", active)
	}
}

func TestFactoryUsesSecondaryStorageForListAndRevocation(t *testing.T) {
	secondary := newSecondaryStore()
	disabled := false
	auth := newAuth(t, nil, func(options *singleauth.Options) {
		options.SecondaryStorage = secondary
		options.RateLimit.Enabled = &disabled
	})
	_, cookie, firstToken := signUp(t, auth, "", "secondary-first@example.test")
	_, cookie, secondToken := signUp(t, auth, cookie, "secondary-second@example.test")
	if !secondary.has(firstToken) || !secondary.has(secondToken) {
		t.Fatalf("secondary sessions first=%v second=%v", secondary.has(firstToken), secondary.has(secondToken))
	}
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "session"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("secondary-only database rows = %#v, err=%v", rows, err)
	}
	listed := exchange(t, auth.Handler(), http.MethodGet, "/multi-session/list-device-sessions", cookie, nil)
	if listed.status != http.StatusOK || len(valueArray(t, listed.value)) != 2 {
		t.Fatalf("secondary list status=%d body=%#v", listed.status, listed.value)
	}
	activated := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", cookie, map[string]any{
		"sessionToken": firstToken,
	})
	if activated.status != http.StatusOK {
		t.Fatalf("secondary activate status=%d body=%#v", activated.status, activated.value)
	}
	cookie = cookies.ApplySetCookies(cookie, activated.headers.Values("Set-Cookie"))
	revoked := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/revoke", cookie, map[string]any{
		"sessionToken": firstToken,
	})
	if revoked.status != http.StatusOK || secondary.has(firstToken) || !secondary.has(secondToken) {
		t.Fatalf("secondary revoke status=%d first=%v second=%v body=%#v",
			revoked.status, secondary.has(firstToken), secondary.has(secondToken), revoked.value)
	}
}

func TestListOutputComposesWithCustomSessionSerializer(t *testing.T) {
	auth := newAuth(t, nil, func(options *singleauth.Options) {
		options.PluginFactories = append(options.PluginFactories, customsession.NewFactory(customsession.Options{
			ShouldMutateListDeviceSessionsEndpoint: true,
			Enrich: func(data customsession.SessionData, _ *engine.Context) (any, error) {
				return map[string]any{
					"email": data.User["email"], "token": data.Session["token"],
				}, nil
			},
		}))
	})
	_, cookie, token := signUp(t, auth, "", "custom-list@example.test")
	listed := exchange(t, auth.Handler(), http.MethodGet, "/multi-session/list-device-sessions", cookie, nil)
	items := valueArray(t, listed.value)
	if listed.status != http.StatusOK || len(items) != 1 {
		t.Fatalf("custom list status=%d body=%#v", listed.status, listed.value)
	}
	item := valueObject(t, items[0])
	if item["email"] != "custom-list@example.test" || item["token"] != token {
		t.Fatalf("custom list item = %#v", item)
	}
}

func TestValidationAndInvalidTokenErrors(t *testing.T) {
	auth := newAuth(t, nil, nil)
	_, cookie, _ := signUp(t, auth, "", "validation@example.test")
	missing := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", cookie, map[string]any{})
	if missing.status != http.StatusBadRequest || valueObject(t, missing.value)["code"] != "VALIDATION_ERROR" {
		t.Fatalf("missing token status=%d body=%#v", missing.status, missing.value)
	}
	invalid := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/set-active", cookie, map[string]any{
		"sessionToken": "not-held",
	})
	if invalid.status != http.StatusUnauthorized ||
		valueObject(t, invalid.value)["code"] != multisession.ErrorInvalidSessionToken ||
		valueObject(t, invalid.value)["message"] != "Invalid session token" {
		t.Fatalf("invalid token status=%d body=%#v", invalid.status, invalid.value)
	}
	unauthenticated := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/revoke", "", map[string]any{
		"sessionToken": "not-held",
	})
	if unauthenticated.status != http.StatusUnauthorized || valueObject(t, unauthenticated.value)["code"] != "UNAUTHORIZED" {
		t.Fatalf("unauth revoke status=%d body=%#v", unauthenticated.status, unauthenticated.value)
	}
	invalidBeforeSession := exchange(t, auth.Handler(), http.MethodPost, "/multi-session/revoke", "", map[string]any{})
	if invalidBeforeSession.status != http.StatusBadRequest ||
		valueObject(t, invalidBeforeSession.value)["code"] != "VALIDATION_ERROR" {
		t.Fatalf("validation-before-session status=%d body=%#v", invalidBeforeSession.status, invalidBeforeSession.value)
	}
}

func nestedEmail(t *testing.T, value any) string {
	t.Helper()
	user := valueObject(t, valueObject(t, value)["user"])
	result, _ := user["email"].(string)
	return result
}

func sessionToken(t *testing.T, value any) string {
	t.Helper()
	session := valueObject(t, valueObject(t, value)["session"])
	result, _ := session["token"].(string)
	return result
}

func hasSessionToken(t *testing.T, sessions []any, token string) bool {
	t.Helper()
	for _, value := range sessions {
		if sessionToken(t, value) == token {
			return true
		}
	}
	return false
}

func withoutRequestCookie(header, name string) string {
	parsed := cookies.Parse(header)
	result := cookies.Parsed{}
	for _, pair := range parsed.Pairs() {
		if pair.Name != name {
			result.Set(pair.Name, pair.Value)
		}
	}
	return result.Header()
}
