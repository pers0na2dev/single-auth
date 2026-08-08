package core

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func cookieBehaviorAuthRunner(vector cookiesBehaviorVector) (func(*testing.T), bool) {
	switch vector.Suite {
	case "Cookie Cache Field Filtering":
		return func(t *testing.T) { runCookieCacheFieldFilteringBehavior(t, vector.Title) }, true
	case "Cookie Chunking":
		return func(t *testing.T) { runCookieChunkingBehavior(t, vector.Title) }, true
	case "sensitive session middleware cookie cache":
		return func(t *testing.T) { runSensitiveCookieCacheBehavior(t, vector.Title) }, true
	case "account cookie sync on user switch":
		return func(t *testing.T) { runAccountCookieSyncBehavior(t, vector.Title) }, true
	case "getCookieCache expiry (compact strategy)":
		return func(t *testing.T) { runCookieCacheExpiryBehavior(t, vector.Title) }, true
	default:
		return nil, false
	}
}

func cookieBehaviorField(
	value string,
	returned bool,
) storage.FieldAttribute {
	return storage.FieldAttribute{
		Type: storage.FieldString, Required: storage.Bool(false),
		Returned: storage.Bool(returned), DefaultValue: storage.StaticValue(value),
	}
}

func cookieBehaviorCacheAuth(
	t *testing.T,
	strategy string,
	userFields map[string]storage.FieldAttribute,
	sessionFields map[string]storage.FieldAttribute,
) *Auth {
	t.Helper()
	models := map[string]storage.ModelSchema{}
	if len(userFields) != 0 {
		models["user"] = storage.ModelSchema{Fields: userFields}
	}
	if len(sessionFields) != 0 {
		models["session"] = storage.ModelSchema{Fields: sessionFields}
	}
	return newCookieBehaviorAuth(t, Options{
		BaseURL: "http://auth.test", Secret: "single-auth.secret",
		Session: SessionOptions{CookieCache: CookieCacheOptions{
			Enabled: true, Strategy: strategy,
		}},
		Schema: storage.Schema{Models: models},
	})
}

func readCookieBehaviorCache(t *testing.T, auth *Auth, cookieHeader, strategy string) map[string]any {
	t.Helper()
	secure := false
	cache, err := GetCookieCache(cookieHeader, CookieCacheLookupOptions{
		Secret: "single-auth.secret", Strategy: strategy,
		IsSecure: &secure, Clock: auth.options.Clock,
	})
	if err != nil || cache == nil {
		t.Fatalf("cookie cache=%#v err=%v", cache, err)
	}
	return cache
}

func runCookieCacheFieldFilteringBehavior(t *testing.T, title string) {
	strategy := ""
	userFields := map[string]storage.FieldAttribute{}
	sessionFields := map[string]storage.FieldAttribute{}
	switch title {
	case "should exclude user fields with returned: false from cookie cache":
		userFields["internalNote"] = cookieBehaviorField("", false)
	case "should correctly filter multiple user fields based on returned config":
		userFields["publicBio"] = cookieBehaviorField("default-bio", true)
		userFields["internalNotes"] = cookieBehaviorField("internal-notes", false)
		userFields["preferences"] = cookieBehaviorField("default-prefs", true)
		userFields["adminFlags"] = cookieBehaviorField("admin-flags", false)
	case "should reduce cookie size when large fields are excluded":
		userFields["largeBio"] = cookieBehaviorField(strings.Repeat("x", 2000), false)
		userFields["smallField"] = cookieBehaviorField("small-value", true)
	case "should maintain session field filtering (regression check)":
		sessionFields["internalSessionData"] = cookieBehaviorField("internal-data", false)
		sessionFields["publicSessionData"] = cookieBehaviorField("public-data", true)
	case "should include unknown user fields for backward compatibility":
		userFields["knownField"] = cookieBehaviorField("known-value", false)
	case "should work with JWT strategy":
		strategy = "jwt"
	case "should work with compact strategy":
		strategy = "compact"
	case "should return null for invalid JWT token":
		secure := false
		cache, err := GetCookieCache(
			"single-auth.session_data=invalid.jwt.token",
			CookieCacheLookupOptions{
				Secret: "single-auth.secret", Strategy: "jwt", IsSecure: &secure,
			},
		)
		if err != nil || cache != nil {
			t.Fatalf("invalid JWT cache=%#v err=%v", cache, err)
		}
		return
	case "should default to JWT strategy when not specified":
	default:
		t.Fatalf("unsupported Cookie Cache Field Filtering title %q", title)
	}
	auth := cookieBehaviorCacheAuth(t, strategy, userFields, sessionFields)
	_, cookieHeader, _ := cookieBehaviorSignUp(t, auth, "filter@example.test", nil)
	cache := readCookieBehaviorCache(t, auth, cookieHeader, strategy)
	user, userOK := cache["user"].(map[string]any)
	session, sessionOK := cache["session"].(map[string]any)
	if !userOK || !sessionOK || user["email"] != "filter@example.test" || session["token"] == "" {
		t.Fatalf("cache=%#v", cache)
	}
	switch title {
	case "should exclude user fields with returned: false from cookie cache":
		if _, exists := user["internalNote"]; exists {
			t.Fatalf("internalNote leaked: %#v", user)
		}
	case "should correctly filter multiple user fields based on returned config":
		if user["publicBio"] == nil || user["preferences"] == nil {
			t.Fatalf("returned fields missing: %#v", user)
		}
		if _, exists := user["internalNotes"]; exists {
			t.Fatalf("internalNotes leaked: %#v", user)
		}
		if _, exists := user["adminFlags"]; exists {
			t.Fatalf("adminFlags leaked: %#v", user)
		}
	case "should reduce cookie size when large fields are excluded":
		if _, exists := user["largeBio"]; exists || user["smallField"] == nil {
			t.Fatalf("user filter=%#v", user)
		}
		parsed := cookies.Parse(cookieHeader)
		if _, chunked := parsed.Get(auth.options.cookie.sessionDataName + ".0"); chunked {
			t.Fatalf("excluded field still forced chunking: %q", cookieHeader)
		}
	case "should maintain session field filtering (regression check)":
		if _, exists := session["internalSessionData"]; exists {
			t.Fatalf("internal session field leaked: %#v", session)
		}
	case "should include unknown user fields for backward compatibility":
		if _, exists := user["knownField"]; exists || user["name"] == nil {
			t.Fatalf("user fields=%#v", user)
		}
	}
}

func cookieBehaviorLargeFields(count, size int, prefix string) (map[string]storage.FieldAttribute, map[string]any) {
	fields := make(map[string]storage.FieldAttribute, count)
	values := make(map[string]any, count)
	for index := 0; index < count; index++ {
		name := prefix + string(rune('1'+index))
		fields[name] = storage.FieldAttribute{Type: storage.FieldString, Required: storage.Bool(false)}
		values[name] = strings.Repeat(string(rune('x'+index%3)), size)
	}
	return fields, values
}

func runCookieChunkingBehavior(t *testing.T, title string) {
	switch title {
	case "should chunk cookies when they exceed 4KB":
		fields, values := cookieBehaviorLargeFields(2, 2000, "field")
		auth := cookieBehaviorCacheAuth(t, "", fields, nil)
		headers, cookieHeader, _ := cookieBehaviorSignUp(t, auth, "chunk@example.test", values)
		assertCookieBehaviorChunks(t, headers.Values("Set-Cookie"), true)
		cache := readCookieBehaviorCache(t, auth, cookieHeader, "")
		if cache["user"].(map[string]any)["email"] != "chunk@example.test" {
			t.Fatalf("cache=%#v", cache)
		}
	case "should reconstruct chunked cookies correctly":
		fields := map[string]storage.FieldAttribute{
			"largeField": {Type: storage.FieldString, Required: storage.Bool(false)},
		}
		values := map[string]any{"largeField": strings.Repeat("y", 2500)}
		auth := cookieBehaviorCacheAuth(t, "", fields, nil)
		_, cookieHeader, _ := cookieBehaviorSignUp(t, auth, "reconstruct@example.test", values)
		cache := readCookieBehaviorCache(t, auth, cookieHeader, "")
		user := cache["user"].(map[string]any)
		if user["email"] != "reconstruct@example.test" || user["largeField"] != values["largeField"] {
			t.Fatalf("reconstructed cache=%#v", cache)
		}
	case "should clean up all chunks when deleting session":
		fields, values := cookieBehaviorLargeFields(2, 2000, "field")
		auth := cookieBehaviorCacheAuth(t, "", fields, nil)
		_, cookieHeader, _ := cookieBehaviorSignUp(t, auth, "cleanup@example.test", values)
		status, headers, response := sessionTestRequest(t, auth, http.MethodPost, "/sign-out", cookieHeader, map[string]any{})
		if status != http.StatusOK {
			t.Fatalf("sign-out status=%d response=%#v", status, response)
		}
		found := false
		for _, line := range headers.Values("Set-Cookie") {
			for _, parsed := range cookies.ParseSetCookieHeader(line) {
				if strings.Contains(parsed.Name, "session_data") {
					found = true
					if parsed.Attributes.MaxAge == nil || *parsed.Attributes.MaxAge != 0 {
						t.Fatalf("cleanup cookie=%#v", parsed)
					}
				}
			}
		}
		if !found {
			t.Fatal("no session_data cleanup cookies")
		}
	case "should NOT chunk cookies when they are under 4KB":
		auth := cookieBehaviorCacheAuth(t, "", nil, nil)
		headers, cookieHeader, _ := cookieBehaviorSignUp(t, auth, "small@example.test", nil)
		assertCookieBehaviorChunks(t, headers.Values("Set-Cookie"), false)
		cache := readCookieBehaviorCache(t, auth, cookieHeader, "")
		if cache["user"].(map[string]any)["email"] != "small@example.test" {
			t.Fatalf("cache=%#v", cache)
		}
	case "should chunk session cache when attributes push the line over the limit":
		runAttributeLimitedChunkBehavior(t)
	case "skips the session cache and warns when it is too large to chunk":
		runOversizedCacheBehavior(t, false)
	case "skips the session cache and warns when the prefix alone overflows":
		runOversizedCacheBehavior(t, true)
	default:
		t.Fatalf("unsupported Cookie Chunking title %q", title)
	}
}

func assertCookieBehaviorChunks(t *testing.T, values []string, wantChunked bool) {
	t.Helper()
	chunked := false
	bare := false
	for _, line := range values {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if strings.Contains(parsed.Name, "session_data.") {
				chunked = true
			}
			if strings.HasSuffix(parsed.Name, "session_data") {
				bare = true
			}
		}
	}
	if chunked != wantChunked || (!wantChunked && !bare) {
		t.Fatalf("chunked=%v bare=%v Set-Cookie=%#v", chunked, bare, values)
	}
}

func runAttributeLimitedChunkBehavior(t *testing.T) {
	longPrefix := "single-auth-" + strings.Repeat("x", 80)
	fields := map[string]storage.FieldAttribute{
		"entraProfile": {Type: storage.FieldString, Required: storage.Bool(false)},
	}
	auth := newCookieBehaviorAuth(t, Options{
		BaseURL: "http://auth.test", Secret: "single-auth.secret",
		Advanced: AdvancedOptions{CookiePrefix: longPrefix},
		Session:  SessionOptions{CookieCache: CookieCacheOptions{Enabled: true}},
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: fields},
		}},
	})
	headers, cookieHeader, _ := cookieBehaviorSignUp(t, auth, "entra@example.test", map[string]any{
		"entraProfile": strings.Repeat("x", 2400),
	})
	chunked := false
	for _, line := range headers.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if !strings.Contains(parsed.Name, "session_data") {
				continue
			}
			serialized := cookies.Serialize(parsed.Name, parsed.Attributes.Value, cookies.OptionsFromAttributes(parsed.Attributes))
			if len(serialized) > 4093 {
				t.Fatalf("cookie %q serialized to %d bytes", parsed.Name, len(serialized))
			}
			if strings.Contains(parsed.Name, "session_data.") {
				chunked = true
			}
		}
	}
	if !chunked {
		t.Fatalf("session cache not chunked: %#v", headers.Values("Set-Cookie"))
	}
	secure := false
	cache, err := GetCookieCache(cookieHeader, CookieCacheLookupOptions{
		CookiePrefix: longPrefix, Secret: "single-auth.secret",
		IsSecure: &secure, Clock: auth.options.Clock,
	})
	if err != nil || cache == nil || cache["user"].(map[string]any)["email"] != "entra@example.test" {
		t.Fatalf("cache=%#v err=%v", cache, err)
	}
}

func runOversizedCacheBehavior(t *testing.T, prefixOverflow bool) {
	warnings := make([]string, 0, 1)
	options := Options{
		BaseURL: "http://auth.test", Secret: "single-auth.secret",
		Session: SessionOptions{CookieCache: CookieCacheOptions{Enabled: true}},
		Logger: logger.Options{Log: func(level logger.Level, message string, _ ...any) {
			if level == logger.Warn {
				warnings = append(warnings, message)
			}
		}},
	}
	extra := map[string]any{}
	email := "too-big@example.test"
	if prefixOverflow {
		options.Advanced.CookiePrefix = "single-auth-" + strings.Repeat("x", 4100)
		email = "no-room@example.test"
	} else {
		options.Schema = storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{
				"blob": {Type: storage.FieldString, Required: storage.Bool(false)},
			}},
		}}
		extra["blob"] = strings.Repeat("x", 420_000)
	}
	auth := newCookieBehaviorAuth(t, options)
	headers, cookieHeader, result := cookieBehaviorSignUp(t, auth, email, extra)
	if result == nil {
		t.Fatal("sign-up returned nil")
	}
	hasData, hasToken := false, false
	for _, line := range headers.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			hasData = hasData || strings.Contains(parsed.Name, "session_data")
			hasToken = hasToken || strings.Contains(parsed.Name, "session_token")
		}
	}
	if hasData || !hasToken {
		t.Fatalf("hasData=%v hasToken=%v cookies=%#v", hasData, hasToken, headers.Values("Set-Cookie"))
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "too large to store even after chunking") {
		t.Fatalf("warnings=%#v", warnings)
	}
	status, _, session := sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK || session == nil || session.(map[string]any)["user"].(map[string]any)["email"] != email {
		t.Fatalf("session status=%d value=%#v", status, session)
	}
}

func runSensitiveCookieCacheBehavior(t *testing.T, title string) {
	if title != "should not let request query re-enable cookie cache on sensitive endpoints" {
		t.Fatalf("unsupported sensitive cache title %q", title)
	}
	auth := cookieBehaviorCacheAuth(t, "", nil, nil)
	_, cookieHeader, result := cookieBehaviorSignUp(t, auth, "sensitive@example.test", nil)
	user := result["user"].(map[string]any)
	if _, err := auth.Adapter().DeleteMany(t.Context(), storage.DeleteManyParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: user["id"]}},
	}); err != nil {
		t.Fatal(err)
	}
	status, _, response := sessionTestRequest(
		t, auth, http.MethodPost, "/change-password?disableCookieCache=", cookieHeader,
		map[string]any{"newPassword": "new-password", "currentPassword": "password123"},
	)
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d response=%#v", status, response)
	}
}

func runAccountCookieSyncBehavior(t *testing.T, title string) {
	database, err := memory.New()
	if err != nil {
		t.Fatal(err)
	}
	currentEmail := "switch-first@example.test"
	currentID := "switch-first-sub"
	provider, err := providers.Google(providers.Options{
		ClientID: "test", ClientSecret: "test",
		VerifyIDToken: func(context.Context, string, string) (bool, error) { return true, nil },
		GetUserInfo: func(context.Context, oauth2.Tokens) (*providers.UserInfoResult, error) {
			email := currentEmail
			return &providers.UserInfoResult{User: oauth2.UserInfo{
				ID: currentID, Name: "Cookie Switch", Email: &email, EmailVerified: true,
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	storeAccountCookie := true
	auth := newCookieBehaviorAuth(t, Options{
		BaseURL: "http://auth.test", Database: database,
		Account:         AccountOptions{StoreAccountCookie: &storeAccountCookie},
		Session:         SessionOptions{CookieCache: CookieCacheOptions{Enabled: true}},
		SocialProviders: map[string]*providers.Provider{"google": provider},
	})
	firstCookie := cookieBehaviorSocialSignIn(t, auth, "")
	switch title {
	case "keeps the fresh account cookie issued for the new user when the request carries another user's stale account cookie":
		currentEmail = "switch-second@example.test"
		currentID = "switch-second-sub"
		status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-in/social", firstCookie, map[string]any{
			"provider": "google", "idToken": map[string]any{"token": "valid", "accessToken": "access-second"},
		})
		if status != http.StatusOK {
			t.Fatalf("second social sign-in status=%d value=%#v", status, value)
		}
		account := lastSetCookieByName(t, headers.Values("Set-Cookie"), auth.options.cookie.accountDataName)
		if account.Value == "" || (account.MaxAge != nil && *account.MaxAge == 0) {
			t.Fatalf("fresh account cookie=%#v", account)
		}
		currentCookie := cookies.ApplySetCookies(firstCookie, headers.Values("Set-Cookie"))
		request := contract.NewRequest(http.MethodGet, "/get-session", contract.RequestOptions{
			Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: currentCookie}),
		})
		accountRecord := auth.getAccountCookie(request)
		status, _, sessionValue := sessionTestRequest(t, auth, http.MethodGet, "/get-session", currentCookie, nil)
		if status != http.StatusOK || sessionValue == nil {
			t.Fatalf("session status=%d value=%#v", status, sessionValue)
		}
		sessionUser := sessionValue.(map[string]any)["user"].(map[string]any)
		if accountRecord == nil || accountRecord["userId"] != sessionUser["id"] || sessionUser["email"] != currentEmail {
			t.Fatalf("account=%#v session=%#v", accountRecord, sessionValue)
		}
	case "still expires another user's stale account cookie when the response issues no fresh one":
		status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-up/email", firstCookie, map[string]any{
			"email": "expire-second@example.test", "password": "password123", "name": "Second User",
		})
		if status != http.StatusOK {
			t.Fatalf("email sign-up status=%d value=%#v", status, value)
		}
		account := lastSetCookieByName(t, headers.Values("Set-Cookie"), auth.options.cookie.accountDataName)
		if account.Value != "" || account.MaxAge == nil || *account.MaxAge != 0 {
			t.Fatalf("expired account cookie=%#v", account)
		}
	default:
		t.Fatalf("unsupported account sync title %q", title)
	}
}

func cookieBehaviorSocialSignIn(t *testing.T, auth *Auth, cookieHeader string) string {
	t.Helper()
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-in/social", cookieHeader, map[string]any{
		"provider": "google", "idToken": map[string]any{"token": "valid", "accessToken": "access-first"},
	})
	if status != http.StatusOK {
		t.Fatalf("social sign-in status=%d value=%#v", status, value)
	}
	return cookies.ApplySetCookies(cookieHeader, headers.Values("Set-Cookie"))
}

func lastSetCookieByName(t *testing.T, values []string, name string) cookies.Attributes {
	t.Helper()
	var result *cookies.Attributes
	for _, line := range values {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Name == name {
				attributes := parsed.Attributes
				result = &attributes
			}
		}
	}
	if result == nil {
		t.Fatalf("Set-Cookie %q missing from %#v", name, values)
	}
	return *result
}

func runCookieCacheExpiryBehavior(t *testing.T, title string) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	embeddedExpiry := now.Add(time.Hour)
	outerExpiry := now.Add(5 * time.Minute).UnixMilli()
	switch title {
	case "returns the session for a fresh snapshot":
	case "returns null when the embedded session has expired":
		embeddedExpiry = now.Add(-time.Minute)
	case "returns null when the cache window has elapsed":
		outerExpiry = now.Add(-time.Minute).UnixMilli()
	default:
		t.Fatalf("unsupported compact expiry title %q", title)
	}
	cookie := buildCookieBehaviorCompactCache(t, embeddedExpiry, outerExpiry)
	secure := false
	cache, err := GetCookieCache(
		"single-auth.session_data="+cookie,
		CookieCacheLookupOptions{
			Secret: "single-auth.secret", IsSecure: &secure,
			Clock: func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if title == "returns the session for a fresh snapshot" {
		if cache == nil || cache["user"].(map[string]any)["email"] != "cache@test.com" {
			t.Fatalf("cache=%#v", cache)
		}
	} else if cache != nil {
		t.Fatalf("expired cache=%#v", cache)
	}
}

func buildCookieBehaviorCompactCache(t *testing.T, embeddedExpiry time.Time, outerExpiry int64) string {
	t.Helper()
	payload := map[string]any{
		"session": map[string]any{
			"id": "s1", "token": "session-token", "userId": "u1",
			"createdAt": embeddedExpiry.Add(-time.Hour).UTC().Format(time.RFC3339Nano),
			"updatedAt": embeddedExpiry.Add(-time.Hour).UTC().Format(time.RFC3339Nano),
			"expiresAt": embeddedExpiry.UTC().Format(time.RFC3339Nano),
		},
		"user": map[string]any{
			"id": "u1", "email": "cache@test.com", "emailVerified": true,
			"name": "Cache User",
		},
		"updatedAt": embeddedExpiry.Add(-time.Hour).UnixMilli(), "version": "1",
	}
	payloadJSON, err := marshalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	signable := appendJSONObjectField(payloadJSON, "expiresAt", strconv.FormatInt(outerExpiry, 10))
	envelopeJSON, err := marshalJSON(compactCacheEnvelope{
		Session: payloadJSON, ExpiresAt: outerExpiry,
		Signature: baCrypto.MakeURLSignature(string(signable), "single-auth.secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(envelopeJSON)
}
