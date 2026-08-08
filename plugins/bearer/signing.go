package bearer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"unicode/utf8"
)

func signCookieValue(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return value + "." + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// verifySignedCookie mirrors @single-auth/utils' base64 decoder: standard and
// URL-safe alphabets are both accepted, padding is optional, and input after
// the first padding marker is ignored before constant-time HMAC comparison.
func verifySignedCookie(value, secret string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	signature, ok := decodeSignature(parts[1])
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0]))
	return hmac.Equal(signature, mac.Sum(nil))
}

func decodeSignature(value string) ([]byte, bool) {
	if padding := strings.IndexByte(value, '='); padding >= 0 {
		value = value[:padding]
	}
	var (
		decoded []byte
		err     error
	)
	if strings.ContainsAny(value, "-_") {
		decoded, err = base64.RawURLEncoding.DecodeString(value)
	} else {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	return decoded, err == nil
}

func tryDecodeURIComponent(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	decoded, err := url.PathUnescape(value)
	if err != nil || !utf8.ValidString(decoded) {
		return value
	}
	return decoded
}

func trimJavaScriptSpace(value string) string {
	return strings.TrimFunc(value, func(character rune) bool {
		switch character {
		case '\u0009', '\u000B', '\u000C', '\u0020', '\u00A0', '\u1680',
			'\u202F', '\u205F', '\u3000', '\uFEFF', '\u000A', '\u000D',
			'\u2028', '\u2029':
			return true
		default:
			return character >= '\u2000' && character <= '\u200A'
		}
	})
}

func hasBearerScheme(value string) bool {
	const prefix = "bearer "
	if len(value) < len(prefix) {
		return false
	}
	for index := range len(prefix) {
		character := value[index]
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		if character != prefix[index] {
			return false
		}
	}
	return true
}
