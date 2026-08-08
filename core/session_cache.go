package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type sessionCachePayload struct {
	Session   map[string]any `json:"session"`
	User      map[string]any `json:"user"`
	UpdatedAt int64          `json:"updatedAt"`
	Version   string         `json:"version"`
}

type compactCacheEnvelope struct {
	Session   json.RawMessage `json:"session"`
	ExpiresAt int64           `json:"expiresAt"`
	Signature string          `json:"signature"`
}

type cachedSessionSnapshot struct {
	payload   map[string]any
	expiresAt time.Time
}

func (a *Auth) setCompactSessionCookie(
	ctx *engine.Context,
	session storage.Record,
	user storage.Record,
	dontRemember bool,
) {
	config := a.cookiesForRequest(ctx.Request())
	payload := sessionCachePayload{
		Session:   a.publicSession(session),
		User:      a.publicUser(user),
		UpdatedAt: a.options.Clock().UnixMilli(),
		Version:   a.options.Session.CookieCache.Version,
	}
	options := config.sessionData
	if dontRemember {
		options.MaxAge = nil
	}
	maxAge := 60 * time.Second
	if options.MaxAge != nil {
		maxAge = time.Duration(*options.MaxAge) * time.Second
	}

	var encoded string
	switch strings.ToLower(a.options.Session.CookieCache.Strategy) {
	case "jwt":
		claims := map[string]any{
			"session": payload.Session, "user": payload.User,
			"updatedAt": payload.UpdatedAt, "version": payload.Version,
		}
		token, err := baCrypto.SignJWTAt(claims, a.options.Secret, maxAge, a.options.Clock())
		if err != nil {
			return
		}
		encoded = token
	case "jwe":
		claims := map[string]any{
			"session": payload.Session, "user": payload.User,
			"updatedAt": payload.UpdatedAt, "version": payload.Version,
		}
		token, err := baCrypto.EncodeJWEAt(
			claims,
			a.options.Secret,
			"single-auth-session",
			maxAge,
			a.options.Clock(),
			a.options.Random,
		)
		if err != nil {
			return
		}
		encoded = token
	default:
		payloadJSON, err := marshalJSON(payload)
		if err != nil {
			return
		}
		expiresAt := a.options.Clock().Add(maxAge).UnixMilli()
		signable := appendJSONObjectField(payloadJSON, "expiresAt", strconv.FormatInt(expiresAt, 10))
		envelopeJSON, err := marshalJSON(compactCacheEnvelope{
			Session: payloadJSON, ExpiresAt: expiresAt,
			Signature: baCrypto.MakeURLSignature(string(signable), a.options.Secret),
		})
		if err != nil {
			return
		}
		encoded = base64.RawURLEncoding.EncodeToString(envelopeJSON)
	}

	incoming := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
	store := cookies.NewStore("session_data", config.sessionDataName, options, incoming, a.warn)
	for _, chunk := range store.ChunkValue(encoded, nil) {
		ctx.AddSetCookie(cookies.Serialize(chunk.Name, chunk.Value, chunk.Options))
	}
	a.syncAccountCookieForSession(ctx, user)
}

func (a *Auth) refreshCachedSessionCookies(
	ctx *engine.Context,
	session storage.Record,
	user storage.Record,
	dontRemember bool,
) {
	// upstream implementation deliberately gives the refreshed cache its configured
	// lifetime even for a don't-remember session, while the session token stays
	// a browser-session cookie.
	a.setCompactSessionCookie(ctx, session, user, false)
	token, ok := recordString(session, "token")
	if !ok {
		return
	}
	config := a.cookiesForRequest(ctx.Request())
	options := config.sessionToken
	if dontRemember {
		options.MaxAge = nil
	}
	signed := token + "." + baCrypto.MakeSignature(token, a.options.Secret)
	ctx.AddSetCookie(cookies.Serialize(config.sessionName, signed, options))
}

func (a *Auth) cachedSession(request contract.Request) (cachedSessionSnapshot, bool) {
	if !a.options.Session.CookieCache.Enabled {
		return cachedSessionSnapshot{}, false
	}
	header := strings.Join(request.Headers().Values("Cookie"), "; ")
	encoded, ok := cookies.GetChunked(header, a.cookiesForRequest(request).sessionDataName)
	if !ok {
		return cachedSessionSnapshot{}, false
	}
	var payload map[string]any
	var expiresAt time.Time
	switch strings.ToLower(a.options.Session.CookieCache.Strategy) {
	case "jwt":
		var err error
		payload, err = baCrypto.VerifyJWTAt(encoded, a.options.Secret, a.options.Clock(), 15*time.Second)
		if err != nil {
			return cachedSessionSnapshot{}, false
		}
		expiresAt = joseExpiry(payload)
	case "jwe":
		var err error
		payload, err = baCrypto.DecodeJWEAt(
			encoded,
			a.options.Secret,
			"single-auth-session",
			a.options.Clock(),
		)
		if err != nil {
			return cachedSessionSnapshot{}, false
		}
		expiresAt = joseExpiry(payload)
	default:
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return cachedSessionSnapshot{}, false
		}
		var envelope compactCacheEnvelope
		if err := json.Unmarshal(decoded, &envelope); err != nil || len(envelope.Session) == 0 {
			return cachedSessionSnapshot{}, false
		}
		signable := appendJSONObjectField(
			envelope.Session,
			"expiresAt",
			strconv.FormatInt(envelope.ExpiresAt, 10),
		)
		if !baCrypto.VerifyURLSignature(string(signable), envelope.Signature, a.options.Secret) {
			return cachedSessionSnapshot{}, false
		}
		if envelope.ExpiresAt < a.options.Clock().UnixMilli() {
			return cachedSessionSnapshot{}, false
		}
		if err := json.Unmarshal(envelope.Session, &payload); err != nil {
			return cachedSessionSnapshot{}, false
		}
		expiresAt = time.UnixMilli(envelope.ExpiresAt)
	}
	if payload == nil {
		return cachedSessionSnapshot{}, false
	}
	version, _ := payload["version"].(string)
	if version == "" {
		version = "1"
	}
	if version != a.options.Session.CookieCache.Version {
		return cachedSessionSnapshot{}, false
	}
	session, ok := payload["session"].(map[string]any)
	if !ok || embeddedSessionExpired(session, a.options.Clock()) {
		return cachedSessionSnapshot{}, false
	}
	if _, ok := payload["user"].(map[string]any); !ok {
		return cachedSessionSnapshot{}, false
	}
	if expiresAt.IsZero() || expiresAt.Before(a.options.Clock()) {
		return cachedSessionSnapshot{}, false
	}
	return cachedSessionSnapshot{payload: payload, expiresAt: expiresAt}, true
}

func joseExpiry(payload map[string]any) time.Time {
	switch value := payload["exp"].(type) {
	case float64:
		return time.Unix(int64(value), 0)
	case int64:
		return time.Unix(value, 0)
	case int:
		return time.Unix(int64(value), 0)
	case json.Number:
		seconds, err := value.Int64()
		if err == nil {
			return time.Unix(seconds, 0)
		}
	}
	return time.Time{}
}

func (a *Auth) cookieCacheRefreshAge() (time.Duration, bool) {
	cache := a.options.Session.CookieCache
	if (!cache.RefreshCache && cache.RefreshCacheUpdateAge == nil) || a.options.stateful {
		return 0, false
	}
	if cache.RefreshCacheUpdateAge != nil {
		return *cache.RefreshCacheUpdateAge, true
	}
	// Upstream calculates Math.floor(maxAge * 0.2) in whole seconds.
	return time.Duration(int64(cache.MaxAge/time.Second)/5) * time.Second, true
}

func (a *Auth) hasSessionDataCookie(request contract.Request) bool {
	header := strings.Join(request.Headers().Values("Cookie"), "; ")
	_, ok := cookies.GetChunked(header, a.cookiesForRequest(request).sessionDataName)
	return ok
}

func (a *Auth) expireSessionDataCookies(ctx *engine.Context) {
	config := a.cookiesForRequest(ctx.Request())
	incoming := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
	store := cookies.NewStore(
		"session_data",
		config.sessionDataName,
		config.sessionData,
		incoming,
		a.warn,
	)
	for _, chunk := range store.Clean() {
		ctx.AddSetCookie(cookies.Serialize(chunk.Name, chunk.Value, chunk.Options))
	}
}

func embeddedSessionExpired(session map[string]any, now time.Time) bool {
	value, exists := session["expiresAt"]
	if !exists || value == nil {
		return false
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, text)
	return err == nil && expiresAt.Before(now)
}

func appendJSONObjectField(object []byte, name, rawValue string) []byte {
	trimmed := bytes.TrimSpace(object)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil
	}
	result := make([]byte, 0, len(trimmed)+len(name)+len(rawValue)+4)
	result = append(result, trimmed[:len(trimmed)-1]...)
	if len(trimmed) > 2 {
		result = append(result, ',')
	}
	encodedName, _ := json.Marshal(name)
	result = append(result, encodedName...)
	result = append(result, ':')
	result = append(result, rawValue...)
	result = append(result, '}')
	return result
}

func marshalJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}
