package core

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
)

// SessionCookieLookupOptions controls the public session-cookie reader.
type SessionCookieLookupOptions = cookies.SessionLookupOptions

// GetSessionCookie reads a upstream implementation session token from a Cookie header.
func GetSessionCookie(cookieHeader string, options ...SessionCookieLookupOptions) (string, bool) {
	config := SessionCookieLookupOptions{}
	if len(options) != 0 {
		config = options[0]
	}
	return cookies.GetSessionCookie(cookieHeader, config)
}

// GetSessionCookieFromHTTPRequest is the net/http form of GetSessionCookie.
func GetSessionCookieFromHTTPRequest(request *http.Request, options ...SessionCookieLookupOptions) (string, bool) {
	if request == nil {
		return "", false
	}
	return GetSessionCookie(request.Header.Get("Cookie"), options...)
}

// CookieHeaderGetter is implemented by net/http.Header and by header shims
// from other runtimes. It keeps GetSessionCookie usable across realm or wrapper
// boundaries without relying on a concrete header type.
type CookieHeaderGetter interface {
	Get(string) string
}

// GetSessionCookieFromHeaderGetter reads from any net/http-compatible header
// getter, including inherited and cross-runtime wrappers.
func GetSessionCookieFromHeaderGetter(headers CookieHeaderGetter, options ...SessionCookieLookupOptions) (string, bool) {
	if headers == nil {
		return "", false
	}
	return GetSessionCookie(headers.Get("Cookie"), options...)
}

// CookieCacheLookupOptions controls the public session-data cookie reader.
// ResolveVersion is the Go equivalent of upstream implementation's synchronous or async
// version callback; it takes precedence over Version when non-nil.
type CookieCacheLookupOptions struct {
	CookiePrefix   string
	CookieName     string
	IsSecure       *bool
	Secret         string
	Strategy       string
	Version        string
	ResolveVersion func(session, user map[string]any) (string, error)
	Clock          func() time.Time
}

// GetCookieCache verifies and decodes a upstream implementation session-data Cookie
// header. A missing cookie is not an error. A present cookie requires a secret,
// matching the upstream helper's fail-closed behavior.
func GetCookieCache(cookieHeader string, options ...CookieCacheLookupOptions) (map[string]any, error) {
	config := CookieCacheLookupOptions{}
	if len(options) != 0 {
		config = options[0]
	}
	prefix := config.CookiePrefix
	if prefix == "" {
		prefix = "single-auth"
	}
	name := config.CookieName
	if name == "" {
		name = "session_data"
	}
	secure := false
	if config.IsSecure != nil {
		secure = *config.IsSecure
	}
	cookieName := prefix + "." + name
	if secure {
		cookieName = cookies.SecurePrefix + cookieName
	}
	encoded, exists := cookies.GetChunked(cookieHeader, cookieName)
	if !exists || encoded == "" {
		return nil, nil
	}
	secret := config.Secret
	if secret == "" {
		secret = os.Getenv("SINGLE_AUTH_SECRET")
	}
	if secret == "" {
		return nil, &UpstreamError{message: "getCookieCache requires a secret to be provided. Either pass it as an option or set the SINGLE_AUTH_SECRET environment variable"}
	}
	now := time.Now()
	if config.Clock != nil {
		now = config.Clock()
	}
	strategy := strings.ToLower(config.Strategy)
	if strategy == "" {
		strategy = "compact"
	}

	var payload map[string]any
	switch strategy {
	case "jwe":
		claims, err := baCrypto.DecodeJWEAt(encoded, secret, "single-auth-session", now)
		if err != nil {
			return nil, nil
		}
		payload = claims
	case "jwt":
		claims, err := baCrypto.VerifyJWTAt(encoded, secret, now, 0)
		if err != nil {
			return nil, nil
		}
		payload = claims
	default:
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, nil
		}
		var envelope compactCacheEnvelope
		if err := json.Unmarshal(decoded, &envelope); err != nil || len(envelope.Session) == 0 {
			return nil, nil
		}
		signable := appendJSONObjectField(
			envelope.Session,
			"expiresAt",
			strconv.FormatInt(envelope.ExpiresAt, 10),
		)
		if !baCrypto.VerifyURLSignature(string(signable), envelope.Signature, secret) {
			return nil, nil
		}
		if envelope.ExpiresAt != 0 && envelope.ExpiresAt < now.UnixMilli() {
			return nil, nil
		}
		if err := json.Unmarshal(envelope.Session, &payload); err != nil {
			return nil, nil
		}
	}
	if payload == nil {
		return nil, nil
	}
	session, sessionOK := payload["session"].(map[string]any)
	user, userOK := payload["user"].(map[string]any)
	if !sessionOK || !userOK || embeddedSessionExpired(session, now) {
		return nil, nil
	}
	if config.Version != "" || config.ResolveVersion != nil {
		cookieVersion, _ := payload["version"].(string)
		if cookieVersion == "" {
			cookieVersion = "1"
		}
		expected := config.Version
		if expected == "" {
			expected = "1"
		}
		if config.ResolveVersion != nil {
			resolved, err := config.ResolveVersion(session, user)
			if err != nil {
				return nil, err
			}
			expected = resolved
		}
		if cookieVersion != expected {
			return nil, nil
		}
	}
	return payload, nil
}

// GetCookieCacheFromHTTPRequest is the net/http form of GetCookieCache.
func GetCookieCacheFromHTTPRequest(request *http.Request, options ...CookieCacheLookupOptions) (map[string]any, error) {
	if request == nil {
		return nil, nil
	}
	return GetCookieCache(request.Header.Get("Cookie"), options...)
}
