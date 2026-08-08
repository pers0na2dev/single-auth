package multisession

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func decodeSessionTokenBody(ctx *engine.Context) (string, error) {
	raw := ctx.Request().Body()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var body map[string]any
	if err := decoder.Decode(&body); err != nil || body == nil {
		return "", validationError("Invalid request body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return "", validationError("Invalid request body")
	}
	value, exists := body["sessionToken"]
	if !exists {
		return "", validationError("sessionToken is required")
	}
	token, ok := value.(string)
	if !ok {
		return "", validationError("sessionToken must be a string")
	}
	return token, nil
}

func requestCookies(request contract.Request) cookies.Parsed {
	return cookies.Parse(strings.Join(request.Headers().Values("Cookie"), "; "))
}

func signedCookie(request contract.Request, name, secret string) (string, bool) {
	encoded, exists := requestCookies(request).Get(name)
	if !exists {
		return "", false
	}
	separator := strings.LastIndexByte(encoded, '.')
	if separator < 1 {
		return "", false
	}
	value, signature := encoded[:separator], encoded[separator+1:]
	if !baCrypto.VerifySignature(value, signature, secret) {
		return "", false
	}
	return value, true
}

func signedCookieValue(value, secret string) string {
	return value + "." + baCrypto.MakeSignature(value, secret)
}

func multiCookieName(sessionCookieName, token string) string {
	return sessionCookieName + "_multi-" + strings.ToLower(token)
}

func isMultiSessionCookie(name string) bool {
	return strings.Contains(name, "_multi-")
}

func multiCookieCount(keyCount, deletedCount int, hasSessionCookie bool) int {
	count := keyCount - deletedCount
	if hasSessionCookie {
		count++
	}
	return count
}

func responseHasCookie(response contract.Response, name string) bool {
	for _, line := range response.Headers().Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Name == name {
				return true
			}
		}
	}
	return false
}

func responseCookieString(response contract.Response) string {
	return strings.Join(response.Headers().Values("Set-Cookie"), ", ")
}

func recordString(record storage.Record, field string) (string, bool) {
	if record == nil {
		return "", false
	}
	value, exists := record[field]
	if !exists || value == nil {
		return "", false
	}
	result, ok := value.(string)
	return result, ok
}

func recordTime(record storage.Record, field string) (time.Time, bool) {
	if record == nil {
		return time.Time{}, false
	}
	switch value := record[field].(type) {
	case time.Time:
		return value, !value.IsZero()
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed, true
			}
		}
	}
	return time.Time{}, false
}

func cloneRecord(source storage.Record) storage.Record {
	if source == nil {
		return nil
	}
	result := make(storage.Record, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneState(source SessionState) SessionState {
	return SessionState{Session: cloneRecord(source.Session), User: cloneRecord(source.User)}
}

func cloneStates(source []SessionState) []SessionState {
	result := make([]SessionState, len(source))
	for index := range source {
		result[index] = cloneState(source[index])
	}
	return result
}

func expireCookie(ctx *engine.Context, cookie Cookie) {
	if cookie.Name == "" {
		return
	}
	attributes := cookie.Attributes
	zero := 0
	attributes.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(cookie.Name, "", attributes))
}

func expireCookieName(ctx *engine.Context, name string, attributes cookies.Options) {
	expireCookie(ctx, Cookie{Name: name, Attributes: attributes})
}

func secureCookieDeleteName(name string) string {
	lower := strings.ToLower(name)
	return strings.Replace(lower, strings.ToLower(cookies.SecurePrefix), cookies.SecurePrefix, 1)
}
