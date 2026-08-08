package magiclink

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const maxRequestBodyBytes = 4 << 20

func decodeObject(ctx *engine.Context) (map[string]any, error) {
	body := ctx.Request().Body()
	if len(body) > maxRequestBodyBytes {
		return nil, validationError("Request body is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, validationError("Invalid request body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, validationError("Invalid request body")
	}
	return value, nil
}

func requiredString(body map[string]any, field string) (string, error) {
	value, exists := body[field]
	if !exists {
		return "", validationError(field + " is required")
	}
	text, ok := value.(string)
	if !ok {
		return "", validationError(field + " must be a string")
	}
	return text, nil
}

func optionalString(body map[string]any, field string) (*string, error) {
	value, exists := body[field]
	if !exists {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, validationError(field + " must be a string")
	}
	return &text, nil
}

func optionalMetadata(body map[string]any) (map[string]any, error) {
	value, exists := body["metadata"]
	if !exists {
		return nil, nil
	}
	metadata, ok := value.(map[string]any)
	if !ok {
		return nil, validationError("metadata must be an object")
	}
	result := make(map[string]any, len(metadata))
	for key, item := range metadata {
		result[key] = item
	}
	return result, nil
}

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

func (p *plugin) serializeSession(session storage.Record) any {
	if serializer := p.options.Runtime.SerializeSession; serializer != nil {
		return serializer(cloneRecord(session))
	}
	return cloneRecord(session)
}

func (p *plugin) resolveBaseURL(ctx *engine.Context) (*url.URL, error) {
	configured := p.options.Runtime.BaseURL
	if resolver := p.options.Runtime.ResolveBaseURL; resolver != nil {
		value, err := resolver(ctx)
		if err != nil {
			return nil, err
		}
		configured = value
	}
	if configured == "" {
		request := ctx.Request()
		if request.Scheme() == "" || request.Host() == "" {
			return nil, errors.New("magiclink: Runtime.BaseURL or ResolveBaseURL is required when request scheme/host are unavailable")
		}
		configured = request.Scheme() + "://" + request.Host()
	}
	parsed, err := url.Parse(configured)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("magiclink: resolved base URL is invalid")
	}
	return parsed, nil
}

func resolveReference(base *url.URL, value string) (string, error) {
	reference, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(reference).String(), nil
}

func redirectResponse(location string) contract.Response {
	return contract.NewResponse(contract.StatusFound, contract.NewHeaders(contract.HeaderField{
		Name: "Location", Value: location,
	}), nil)
}

func redirectWithError(location, code string) (contract.Response, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	parsed.RawQuery = setQueryParameter(parsed.RawQuery, "error", code)
	return redirectResponse(parsed.String()), nil
}

func setQueryParameter(rawQuery, key, value string) string {
	encoded := formEscape(key) + "=" + formEscape(value)
	if rawQuery == "" {
		return encoded
	}
	parts := strings.Split(rawQuery, "&")
	result := make([]string, 0, len(parts)+1)
	replaced := false
	for _, part := range parts {
		rawKey, _, _ := strings.Cut(part, "=")
		decodedKey, err := url.QueryUnescape(rawKey)
		if err == nil && decodedKey == key {
			if !replaced {
				result = append(result, encoded)
				replaced = true
			}
			continue
		}
		result = append(result, part)
	}
	if !replaced {
		result = append(result, encoded)
	}
	return strings.Join(result, "&")
}
