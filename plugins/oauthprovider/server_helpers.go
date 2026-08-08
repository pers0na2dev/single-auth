package oauthprovider

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func serverDecodeObject(request contract.Request) (map[string]any, error) {
	body := request.Body()
	if len(body) == 0 {
		return nil, nil
	}
	contentType, _ := request.Headers().Get("Content-Type")
	if strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		result := make(map[string]any, len(values))
		for key, entries := range values {
			if len(entries) == 1 {
				result[key] = entries[0]
			} else if len(entries) > 1 {
				result[key] = append([]string(nil), entries...)
			}
		}
		return result, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("oauthprovider: request body contains trailing data")
	}
	return object, nil
}

func serverString(object map[string]any, key string) string {
	if object == nil {
		return ""
	}
	value, _ := object[key].(string)
	return value
}

func serverBool(object map[string]any, key string) (bool, bool) {
	if object == nil {
		return false, false
	}
	value, exists := object[key]
	if !exists || value == nil {
		return false, false
	}
	result, ok := value.(bool)
	return result, ok
}

func serverStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []GrantType:
		result := make([]string, len(typed))
		for index, item := range typed {
			result[index] = string(item)
		}
		return result
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	case string:
		return strings.Fields(typed)
	default:
		return nil
	}
}

func serverRecordString(record storage.Record, key string) string {
	if record == nil {
		return ""
	}
	value, _ := record[key].(string)
	return value
}

func serverRecordBool(record storage.Record, key string) bool {
	if record == nil {
		return false
	}
	value, _ := record[key].(bool)
	return value
}

func serverRecordTime(record storage.Record, key string) (time.Time, bool) {
	if record == nil {
		return time.Time{}, false
	}
	switch value := record[key].(type) {
	case time.Time:
		return value, !value.IsZero()
	case *time.Time:
		if value != nil {
			return *value, !value.IsZero()
		}
	}
	return time.Time{}, false
}

func serverContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func serverSubset(values, allowed []string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		set[value] = struct{}{}
	}
	for _, value := range values {
		if _, exists := set[value]; !exists {
			return false
		}
	}
	return true
}

func serverUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func serverOAuthError(status int, code, description string) (contract.Response, error) {
	err := contract.NewAPIError(status, strings.ToUpper(code), description).WithWireBody(map[string]any{
		"error": code, "error_description": description,
	})
	return contract.ResponseFromError(err), err
}

func serverInternalError(cause error) (contract.Response, error) {
	err := contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(fmt.Errorf("oauthprovider server: %w", cause))
	return contract.ResponseFromError(err), err
}

func serverJSON(status int, value any) (contract.Response, error) {
	return contract.JSONResponse(status, value)
}

func serverRedirect(ctx *engine.Context, location string) (contract.Response, error) {
	mode, _ := ctx.Request().Headers().Get("Sec-Fetch-Mode")
	accept, _ := ctx.Request().Headers().Get("Accept")
	if mode == "cors" || strings.Contains(strings.ToLower(accept), "application/json") {
		return serverJSON(contract.StatusOK, map[string]any{
			"redirect": true,
			"url":      location,
		})
	}
	return contract.NewResponse(
		contract.StatusFound,
		contract.NewHeaders(contract.HeaderField{Name: "Location", Value: location}),
		nil,
	), nil
}

func serverAppendQuery(destination string, values map[string]string) (string, error) {
	parsed, err := url.Parse(destination)
	if err != nil || destination == "" || (!parsed.IsAbs() && !strings.HasPrefix(parsed.Path, "/")) {
		if err == nil {
			err = errors.New("oauthprovider: redirect URI must be absolute or root-relative")
		}
		return "", err
	}
	query := parsed.Query()
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func serverErrorURL(destination, state, issuer, code, description string) string {
	result, err := serverAppendQuery(destination, map[string]string{
		"error": code, "error_description": description,
		"state": state, "iss": issuer,
	})
	if err != nil {
		return destination
	}
	return result
}

func serverPKCEChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func serverRandomToken(random io.Reader) (string, error) {
	buffer := make([]byte, 32)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func serverHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func serverConstantEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func serverSignQuery(values url.Values, secret string) string {
	copyValues := cloneURLValues(values)
	copyValues.Del("sig")
	SetSignedOAuthQueryParameterNames(copyValues)
	canonical := CanonicalizeOAuthQueryParams(copyValues)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	copyValues.Set("sig", base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return copyValues.Encode()
}

func serverVerifySignedQuery(raw, secret string, maxAge time.Duration, now time.Time) (url.Values, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, errors.New("oauthprovider: malformed oauth_query")
	}
	signatures := values["sig"]
	if len(signatures) != 1 || signatures[0] == "" {
		return nil, errors.New("oauthprovider: missing signed query signature")
	}
	provided, err := base64.RawURLEncoding.DecodeString(signatures[0])
	if err != nil {
		return nil, errors.New("oauthprovider: malformed signed query signature")
	}
	unsigned := cloneURLValues(values)
	unsigned.Del("sig")
	declared := unsigned[SignedQueryParameterNameParam]
	if len(declared) == 0 {
		return nil, errors.New("oauthprovider: signed query declaration missing")
	}
	allowed := make(map[string]struct{}, len(declared))
	for _, key := range declared {
		allowed[key] = struct{}{}
	}
	for key := range unsigned {
		if _, exists := allowed[key]; !exists {
			return nil, errors.New("oauthprovider: unsigned query parameter")
		}
	}
	canonical := CanonicalizeOAuthQueryParams(unsigned)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return nil, errors.New("oauthprovider: invalid signed query")
	}
	if maxAge > 0 {
		issuedAt, ok := GetSignedQueryIssuedAt(unsigned.Encode())
		if !ok || issuedAt.After(now.Add(time.Minute)) || now.Sub(issuedAt) > maxAge {
			return nil, errors.New("oauthprovider: signed query expired")
		}
	}
	unsigned.Del(SignedQueryParameterNameParam)
	return unsigned, nil
}

func serverRedirectMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	left, leftErr := url.Parse(registered)
	right, rightErr := url.Parse(requested)
	if leftErr != nil || rightErr != nil || left.Scheme != right.Scheme ||
		left.Hostname() != right.Hostname() || left.EscapedPath() != right.EscapedPath() ||
		left.RawQuery != right.RawQuery {
		return false
	}
	ip := net.ParseIP(left.Hostname())
	return ip != nil && ip.IsLoopback()
}

func serverPairwiseSubject(secret, userID, sector string) string {
	if secret == "" || sector == "" {
		return userID
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(sector))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func serverSignHS256(payload map[string]any, secret string) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
