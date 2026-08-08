package singleauth_test

import (
	"reflect"
	"regexp"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
)

type oauthTokenUtilityCase struct {
	Suite    string
	Title    string
	Expected map[string]any
}

func TestOAuthTokenUtilitiesBehavior(t *testing.T) {
	for _, scenario := range oauthTokenUtilityCases() {
		scenario := scenario
		t.Run(scenario.Suite+"/"+scenario.Title, func(t *testing.T) {
			actual := runOAuthTokenUtilityCase(t, scenario.Suite, scenario.Title)
			if !reflect.DeepEqual(actual, scenario.Expected) {
				t.Fatalf("OAuth token utility observation = %#v, want %#v", actual, scenario.Expected)
			}
		})
	}
}

func runOAuthTokenUtilityCase(t *testing.T, suite, title string) map[string]any {
	t.Helper()
	const secret = "test-secret-key-for-encryption"
	enabled, err := singleauth.New(singleauth.Options{
		Secret: secret,
		Account: singleauth.AccountOptions{
			EncryptOAuthTokens: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := singleauth.New(singleauth.Options{Secret: secret})
	if err != nil {
		t.Fatal(err)
	}

	decode := func(auth *singleauth.Auth, token string) map[string]any {
		value, err := auth.DecodeOAuthToken(token)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"value": value}
	}
	encode := func(auth *singleauth.Auth, token string) string {
		value, err := auth.EncodeOAuthToken(&token)
		if err != nil {
			t.Fatal(err)
		}
		if value == nil {
			t.Fatal("non-nil OAuth token encoded as nil")
		}
		return *value
	}

	switch title {
	case "should return empty token as-is":
		return decode(enabled, "")
	case "should return token as-is when encryption is disabled":
		if suite == "setTokenUtil" {
			return map[string]any{"value": encode(disabled, "test-token")}
		}
		return decode(disabled, "ya29.a0ARW5m7hQ_some_oauth_token")
	case "should decrypt encrypted token when encryption is enabled":
		encrypted, err := baCrypto.Encrypt(secret, []byte("test-access-token"))
		if err != nil {
			t.Fatal(err)
		}
		return decode(enabled, encrypted)
	case "should handle migration: return unencrypted token as-is when encryption is enabled":
		return decode(enabled, "ya29.a0ARW5m7hQ_some_oauth_token_with-dashes")
	case "should handle migration: JWT-style tokens should be returned as-is":
		return decode(enabled, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
	case "should handle migration: token with odd length should be returned as-is":
		return decode(enabled, "abc")
	case "should handle Google OAuth token stored before encryption was enabled":
		return decode(enabled, "ya29.a0ARW5m7hQ_test-token_with.dots-and_underscores")
	case "should handle refresh token that was stored unencrypted":
		return decode(enabled, "1//0gxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	case "should still decrypt properly encrypted tokens":
		return decode(enabled, encode(enabled, "ya29.newToken_after_encryption_enabled"))
	case "should return null/undefined as-is":
		nullToken, err := enabled.EncodeOAuthToken(nil)
		if err != nil {
			t.Fatal(err)
		}
		undefinedToken, err := enabled.EncodeOAuthToken(nil)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"nullPreserved":      nullToken == nil,
			"undefinedPreserved": undefinedToken == nil,
		}
	case "should encrypt token when encryption is enabled":
		const token = "test-token"
		result := encode(enabled, token)
		return map[string]any{
			"different":  result != token,
			"hex":        regexp.MustCompile(`^[0-9a-f]+$`).MatchString(result),
			"evenLength": len(result)%2 == 0,
		}
	case "should produce tokens that can be decrypted":
		return decode(enabled, encode(enabled, "my-secret-access-token"))
	default:
		t.Fatalf("unsupported OAuth token utility test %q / %q", suite, title)
		return nil
	}
}

func oauthTokenUtilityCases() []oauthTokenUtilityCase {
	return []oauthTokenUtilityCase{
		{Suite: "decryptOAuthToken", Title: "should decrypt encrypted token when encryption is enabled", Expected: map[string]any{"value": "test-access-token"}},
		{Suite: "decryptOAuthToken", Title: "should handle migration: JWT-style tokens should be returned as-is", Expected: map[string]any{"value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"}},
		{Suite: "decryptOAuthToken", Title: "should handle migration: return unencrypted token as-is when encryption is enabled", Expected: map[string]any{"value": "ya29.a0ARW5m7hQ_some_oauth_token_with-dashes"}},
		{Suite: "decryptOAuthToken", Title: "should handle migration: token with odd length should be returned as-is", Expected: map[string]any{"value": "abc"}},
		{Suite: "decryptOAuthToken", Title: "should return empty token as-is", Expected: map[string]any{"value": ""}},
		{Suite: "decryptOAuthToken", Title: "should return token as-is when encryption is disabled", Expected: map[string]any{"value": "ya29.a0ARW5m7hQ_some_oauth_token"}},
		{Suite: "migration scenario - issue #6018", Title: "should handle Google OAuth token stored before encryption was enabled", Expected: map[string]any{"value": "ya29.a0ARW5m7hQ_test-token_with.dots-and_underscores"}},
		{Suite: "migration scenario - issue #6018", Title: "should handle refresh token that was stored unencrypted", Expected: map[string]any{"value": "1//0gxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}},
		{Suite: "migration scenario - issue #6018", Title: "should still decrypt properly encrypted tokens", Expected: map[string]any{"value": "ya29.newToken_after_encryption_enabled"}},
		{Suite: "setTokenUtil", Title: "should encrypt token when encryption is enabled", Expected: map[string]any{"different": true, "hex": true, "evenLength": true}},
		{Suite: "setTokenUtil", Title: "should produce tokens that can be decrypted", Expected: map[string]any{"value": "my-secret-access-token"}},
		{Suite: "setTokenUtil", Title: "should return null/undefined as-is", Expected: map[string]any{"nullPreserved": true, "undefinedPreserved": true}},
		{Suite: "setTokenUtil", Title: "should return token as-is when encryption is disabled", Expected: map[string]any{"value": "test-token"}},
	}
}
