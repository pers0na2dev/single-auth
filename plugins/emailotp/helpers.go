package emailotp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/mail"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const maxRequestBodyBytes = 4 << 20

func decodeBody(ctx *engine.Context, target any) error {
	body := ctx.Request().Body()
	if len(body) > maxRequestBodyBytes {
		return validationError("Request body is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return validationError("Invalid request body").WithCause(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return validationError("Invalid request body")
	}
	return nil
}

func decodeObject(ctx *engine.Context) (map[string]any, error) {
	var body map[string]any
	if err := decodeBody(ctx, &body); err != nil {
		return nil, err
	}
	if body == nil {
		return nil, validationError("Invalid request body")
	}
	return body, nil
}

func requiredString(body map[string]any, name string) (string, error) {
	value, exists := body[name]
	if !exists {
		return "", validationError(name + " is required")
	}
	text, ok := value.(string)
	if !ok {
		return "", validationError(name + " must be a string")
	}
	return text, nil
}

func optionalString(body map[string]any, name string) (*string, error) {
	value, exists := body[name]
	if !exists || value == nil {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, validationError(name + " must be a string")
	}
	return &text, nil
}

func normalizeEmail(email string) string { return strings.ToLower(email) }

func validEmail(email string) bool {
	if email == "" || strings.ContainsAny(email, "\r\n\t ") {
		return false
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || strings.Count(email, "@") != 1 {
		return false
	}
	parts := strings.SplitN(email, "@", 2)
	return parts[0] != "" && parts[1] != "" && !strings.HasPrefix(parts[1], ".") && !strings.HasSuffix(parts[1], ".")
}

func parseOTPType(value string) (OTPType, bool) {
	typeValue := OTPType(value)
	switch typeValue {
	case TypeSignIn, TypeEmailVerification, TypeForgetPassword, TypeChangeEmail:
		return typeValue, true
	default:
		return "", false
	}
}

func recordString(record storage.Record, key string) (string, bool) {
	if record == nil {
		return "", false
	}
	value, exists := record[key]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func recordBool(record storage.Record, key string) (bool, bool) {
	if record == nil {
		return false, false
	}
	switch value := record[key].(type) {
	case bool:
		return value, true
	case int:
		return value != 0, true
	case int64:
		return value != 0, true
	case float64:
		return value != 0, true
	default:
		return false, false
	}
}

func recordTime(record storage.Record, key string) (time.Time, bool) {
	if record == nil {
		return time.Time{}, false
	}
	switch value := record[key].(type) {
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

func (p *plugin) serializeUser(user storage.Record) any {
	if serializer := p.options.Runtime.SerializeUser; serializer != nil {
		return serializer(cloneRecord(user))
	}
	return cloneRecord(user)
}

func successResponse() (contract.Response, error) {
	return contract.JSONResponse(contract.StatusOK, map[string]any{"success": true})
}

func (p *plugin) sendCSRFMiddleware(ctx *engine.Context, next engine.Next) (contract.Response, error) {
	if validator := p.options.Runtime.ValidateSendRequest; validator != nil {
		if err := validator(ctx); err != nil {
			return contract.ResponseFromError(err), err
		}
		return next()
	}
	request := ctx.Request()
	headers := request.Headers()
	site, _ := headers.Get("Sec-Fetch-Site")
	mode, _ := headers.Get("Sec-Fetch-Mode")
	destination, _ := headers.Get("Sec-Fetch-Dest")
	if strings.EqualFold(site, "cross-site") && strings.EqualFold(mode, "navigate") {
		err := apiError(contract.StatusForbidden, "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED", "Cross-site navigation login blocked. This request appears to be a CSRF attack.")
		return contract.ResponseFromError(err), err
	}
	origin, _ := headers.Get("Origin")
	if origin == "" {
		origin, _ = headers.Get("Referer")
	}
	hasMetadata := strings.TrimSpace(site) != "" || strings.TrimSpace(mode) != "" || strings.TrimSpace(destination) != ""
	shouldValidate := headers.Has("Cookie") || hasMetadata || origin != ""
	if !shouldValidate {
		return next()
	}
	if origin == "" || origin == "null" {
		err := apiError(contract.StatusForbidden, "MISSING_OR_NULL_ORIGIN", "Missing or null Origin")
		return contract.ResponseFromError(err), err
	}
	trusted := append([]string(nil), p.options.TrustedOrigins...)
	if request.Scheme() != "" && request.Host() != "" {
		trusted = append(trusted, request.Scheme()+"://"+request.Host())
	}
	parsedOrigin, err := url.Parse(origin)
	if err == nil && parsedOrigin.Scheme != "" && parsedOrigin.Host != "" {
		candidate := parsedOrigin.Scheme + "://" + parsedOrigin.Host
		for _, allowed := range trusted {
			if originPatternMatches(candidate, allowed) {
				return next()
			}
		}
	}
	apiErr := apiError(contract.StatusForbidden, "INVALID_ORIGIN", "Invalid origin")
	return contract.ResponseFromError(apiErr), apiErr
}

func originPatternMatches(candidate, pattern string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		parsed, err := url.Parse(pattern)
		if err == nil && parsed.Scheme != "" && parsed.Host != "" {
			return candidate == parsed.Scheme+"://"+parsed.Host
		}
		return candidate == pattern
	}
	matchCandidate := candidate
	if !strings.Contains(pattern, "://") {
		parsed, err := url.Parse(candidate)
		if err != nil {
			return false
		}
		matchCandidate = parsed.Host
	}
	matched, err := path.Match(pattern, matchCandidate)
	return err == nil && matched
}
