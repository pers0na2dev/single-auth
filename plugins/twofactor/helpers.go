package twofactor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const defaultRandomAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

func decodeObject(ctx *engine.Context) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(ctx.Request().Body()))
	decoder.UseNumber()
	var body map[string]any
	if err := decoder.Decode(&body); err != nil || body == nil {
		return nil, validationError("Invalid request body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, validationError("Invalid request body")
	}
	return body, nil
}

func decodeOptionalObject(ctx *engine.Context) (map[string]any, error) {
	if len(bytes.TrimSpace(ctx.Request().Body())) == 0 {
		return map[string]any{}, nil
	}
	return decodeObject(ctx)
}

func requiredString(body map[string]any, name string) (string, error) {
	value, exists := body[name]
	if !exists {
		return "", validationError(name + " is required")
	}
	result, ok := value.(string)
	if !ok {
		return "", validationError(name + " must be a string")
	}
	return result, nil
}

func optionalString(body map[string]any, name string) (*string, error) {
	value, exists := body[name]
	if !exists || value == nil {
		return nil, nil
	}
	result, ok := value.(string)
	if !ok {
		return nil, validationError(name + " must be a string")
	}
	return &result, nil
}

func optionalBool(body map[string]any, name string) (*bool, error) {
	value, exists := body[name]
	if !exists || value == nil {
		return nil, nil
	}
	result, ok := value.(bool)
	if !ok {
		return nil, validationError(name + " must be a boolean")
	}
	return &result, nil
}

func successResponse(value any) (contract.Response, error) {
	response, err := contract.JSONResponse(contract.StatusOK, value)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return response, nil
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

func recordBool(record storage.Record, field string) (bool, bool) {
	if record == nil {
		return false, false
	}
	value, exists := record[field]
	if !exists || value == nil {
		return false, false
	}
	result, ok := value.(bool)
	return result, ok
}

func recordInt(record storage.Record, field string) int {
	if record == nil {
		return 0
	}
	switch value := record[field].(type) {
	case int:
		return value
	case int8:
		return int(value)
	case int16:
		return int(value)
	case int32:
		return int(value)
	case int64:
		return int(value)
	case uint:
		return int(value)
	case uint8:
		return int(value)
	case uint16:
		return int(value)
	case uint32:
		return int(value)
	case uint64:
		return int(value)
	case float32:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		parsed, _ := value.Int64()
		return int(parsed)
	case string:
		parsed, _ := strconv.Atoi(value)
		return parsed
	default:
		return 0
	}
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
			parsed, err := time.Parse(layout, value)
			if err == nil {
				return parsed, true
			}
		}
	}
	return time.Time{}, false
}

func randomFromAlphabet(random io.Reader, length int, alphabet string) (string, error) {
	if random == nil {
		return "", errors.New("twofactor: random source is nil")
	}
	if length < 0 || alphabet == "" {
		return "", errors.New("twofactor: invalid random string parameters")
	}
	result := make([]byte, length)
	buffer := []byte{0}
	limit := 256 - (256 % len(alphabet))
	for index := range result {
		for {
			if _, err := io.ReadFull(random, buffer); err != nil {
				return "", err
			}
			if int(buffer[0]) >= limit {
				continue
			}
			result[index] = alphabet[int(buffer[0])%len(alphabet)]
			break
		}
	}
	return string(result), nil
}

func hashOTP(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func constantTimeStrings(left, right string) bool {
	if len(left) != len(right) {
		// Preserve a length-independent compare over the supplied bytes while
		// still rejecting unequal lengths.
		_ = subtle.ConstantTimeCompare([]byte(left), []byte(left))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func generateHOTP(secret string, counter uint64, digits int) (string, error) {
	if digits < 1 || digits > 8 {
		return "", errors.New("Digits must be between 1 and 8")
	}
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(counterBytes[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	truncated := (uint32(digest[offset]&0x7f) << 24) |
		(uint32(digest[offset+1]) << 16) |
		(uint32(digest[offset+2]) << 8) |
		uint32(digest[offset+3])
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, truncated%modulus), nil
}

// GenerateTOTP is the Go API equivalent of @single-auth/utils createOTP().totp().
func GenerateTOTP(secret string, at time.Time, digits int, period time.Duration) (string, error) {
	if period <= 0 {
		period = 30 * time.Second
	}
	if digits == 0 {
		digits = 6
	}
	counter := uint64(at.UnixMilli() / period.Milliseconds())
	return generateHOTP(secret, counter, digits)
}

// VerifyTOTP uses the upstream default window of one period on either side.
func VerifyTOTP(secret, input string, at time.Time, digits int, period time.Duration) (bool, error) {
	if period <= 0 {
		period = 30 * time.Second
	}
	if digits == 0 {
		digits = 6
	}
	base := at.UnixMilli() / period.Milliseconds()
	matched := false
	for offset := int64(-1); offset <= 1; offset++ {
		counter := base + offset
		if counter < 0 {
			continue
		}
		code, err := generateHOTP(secret, uint64(counter), digits)
		if err != nil {
			return false, err
		}
		matched = constantTimeStrings(input, code) || matched
	}
	return matched, nil
}

// TOTPURI reproduces @single-auth/utils 0.4.2 query and encoding order.
func TOTPURI(secret, issuer, account string, digits int, period time.Duration) string {
	if digits == 0 {
		digits = 6
	}
	if period <= 0 {
		period = 30 * time.Second
	}
	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
	return "otpauth://totp/" + encodeURIComponent(issuer) + ":" + encodeURIComponent(account) +
		"?secret=" + urlSearchParamsEncode(encodedSecret) +
		"&issuer=" + urlSearchParamsEncode(issuer) +
		"&digits=" + strconv.Itoa(digits) +
		"&period=" + strconv.FormatInt(int64(period/time.Second), 10)
}

func urlSearchParamsEncode(value string) string {
	var builder strings.Builder
	for _, b := range []byte(value) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') || b == '*' || b == '-' || b == '.' || b == '_' {
			builder.WriteByte(b)
			continue
		}
		if b == ' ' {
			builder.WriteByte('+')
			continue
		}
		_, _ = fmt.Fprintf(&builder, "%%%02X", b)
	}
	return builder.String()
}

func encodeURIComponent(value string) string {
	var builder strings.Builder
	for _, b := range []byte(value) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') || strings.ContainsRune("-_.!~*'()", rune(b)) {
			builder.WriteByte(b)
			continue
		}
		_, _ = fmt.Fprintf(&builder, "%%%02X", b)
	}
	return builder.String()
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
	return value, baCrypto.VerifySignature(value, signature, secret)
}

func signedCookieValue(value, secret string) string {
	return value + "." + baCrypto.MakeSignature(value, secret)
}

func setSignedCookie(ctx *engine.Context, cookie Cookie, value, secret string) {
	ctx.AddSetCookie(cookies.Serialize(cookie.Name, signedCookieValue(value, secret), cookie.Attributes))
}

func expireCookie(ctx *engine.Context, cookie Cookie) {
	toRemove := make([]string, 0)
	for _, line := range ctx.ResponseHeaderValues("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Name == cookie.Name || strings.HasPrefix(parsed.Name, cookie.Name+".") {
				toRemove = append(toRemove, line)
				break
			}
		}
	}
	ctx.RemoveResponseHeaderValues("Set-Cookie", toRemove...)
	attributes := cookie.Attributes
	zero := 0
	attributes.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(cookie.Name, "", attributes))
}

func stripResponseCookies(response contract.Response, exactNames ...string) contract.Response {
	headers := response.Headers()
	fields := headers.Fields()
	filtered := contract.Headers{}
	for _, field := range fields {
		if !strings.EqualFold(field.Name, "Set-Cookie") {
			filtered.Add(field.Name, field.Value)
			continue
		}
		keep := true
		for _, parsed := range cookies.ParseSetCookieHeader(field.Value) {
			for _, name := range exactNames {
				if parsed.Name == name || strings.HasPrefix(parsed.Name, name+".") {
					keep = false
					break
				}
			}
		}
		if keep {
			filtered.Add(field.Name, field.Value)
		}
	}
	return response.WithHeaders(filtered)
}

func scrubResponseCookies(
	ctx *engine.Context,
	response contract.Response,
	exactNames ...string,
) contract.Response {
	toRemove := make([]string, 0)
	for _, field := range response.Headers().Fields() {
		if !strings.EqualFold(field.Name, "Set-Cookie") {
			continue
		}
		for _, parsed := range cookies.ParseSetCookieHeader(field.Value) {
			matched := false
			for _, name := range exactNames {
				if parsed.Name == name || strings.HasPrefix(parsed.Name, name+".") {
					matched = true
					break
				}
			}
			if matched {
				toRemove = append(toRemove, field.Value)
				break
			}
		}
	}
	ctx.RemoveResponseHeaderValues("Set-Cookie", toRemove...)
	return stripResponseCookies(response, exactNames...)
}

func userID(user storage.Record) (string, error) {
	value, ok := recordString(user, "id")
	if !ok || value == "" {
		return "", errors.New("twofactor: user id is invalid")
	}
	return value, nil
}
