package customsession

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func decodeJSON(raw []byte) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return value, true
}

func sessionData(value any) (SessionData, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return SessionData{}, false
	}
	user, userOK := object["user"].(map[string]any)
	session, sessionOK := object["session"].(map[string]any)
	if !userOK || !sessionOK {
		return SessionData{}, false
	}
	return SessionData{
		User:    cloneRecord(user),
		Session: cloneRecord(session),
	}, true
}

func cloneSessionData(value SessionData) SessionData {
	return SessionData{
		User:    cloneRecord(value.User),
		Session: cloneRecord(value.Session),
	}
}

func cloneRecord(source map[string]any) storage.Record {
	if source == nil {
		return nil
	}
	result := make(storage.Record, len(source))
	for key, value := range source {
		result[key] = cloneValue(value)
	}
	return result
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneRecord(typed)
	case storage.Record:
		return cloneRecord(typed)
	case []any:
		result := make([]any, len(typed))
		for index := range typed {
			result[index] = cloneValue(typed[index])
		}
		return result
	case []byte:
		return append([]byte(nil), typed...)
	default:
		return value
	}
}

func truthyJSON(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != ""
	case json.Number:
		number, err := typed.Float64()
		return err != nil || number != 0
	case float64:
		return typed != 0
	default:
		return true
	}
}

// transferSessionHeaders mirrors parseSetCookieHeader + toCookieOptions from
// upstream. Set-Cookie stays as separate lines and decoded semantic values are
// serialized exactly once, preventing percent double-encoding on refresh.
func transferSessionHeaders(ctx *engine.Context, response contract.Response) {
	headers := response.Headers()
	for _, line := range headers.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			serialized := cookies.Serialize(
				parsed.Name,
				parsed.Attributes.Value,
				cookieOptions(parsed.Attributes),
			)
			if serialized != "" {
				ctx.AddSetCookie(serialized)
			}
		}
	}

	seen := make(map[string]struct{})
	for _, field := range headers.Fields() {
		key := strings.ToLower(field.Name)
		if key == "set-cookie" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		ctx.SetResponseHeader(field.Name, strings.Join(headers.Values(field.Name), ", "))
	}
}

func cookieOptions(attributes cookies.Attributes) cookies.Options {
	return cookies.Options{
		MaxAge:      cloneInt(attributes.MaxAge),
		Expires:     cloneTime(attributes.Expires),
		Domain:      attributes.Domain,
		Path:        attributes.Path,
		Secure:      attributes.Secure,
		HTTPOnly:    attributes.HTTPOnly,
		Partitioned: attributes.Partitioned,
		SameSite:    attributes.SameSite,
	}
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
