package oidcprovider

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func jsonResponse(status int, value any) (contract.Response, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.NewResponse(status, contract.NewHeaders(
		contract.HeaderField{Name: "Content-Type", Value: "application/json"},
	), body), nil
}

func oauthError(status int, code, description string) *contract.APIError {
	typedCode := strings.ToUpper(strings.ReplaceAll(code, "-", "_"))
	return contract.NewAPIError(status, typedCode, description).WithWireBody(OAuthErrorBody{
		Error: code, ErrorDescription: description,
	})
}

func invalidRequest(description string) *contract.APIError {
	return oauthError(contract.StatusBadRequest, "invalid_request", description)
}

func invalidClient(description string) *contract.APIError {
	return oauthError(contract.StatusBadRequest, "invalid_client", description)
}

func internalError(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error",
	).WithCause(err)
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func redirect(location string) contract.Response {
	return contract.NewResponse(contract.StatusFound, contract.NewHeaders(
		contract.HeaderField{Name: "Location", Value: location},
	), nil)
}

func handleRedirect(ctx *engine.Context, location string) (contract.Response, error) {
	mode, _ := ctx.Request().Headers().Get("Sec-Fetch-Mode")
	if mode == "cors" {
		return jsonResponse(contract.StatusOK, map[string]any{"redirect": true, "url": location})
	}
	return redirect(location), nil
}

func decodeBody(ctx *engine.Context) (map[string]any, error) {
	request := ctx.Request()
	body := request.Body()
	if len(body) == 0 {
		return nil, nil
	}
	contentType, _ := request.Headers().Get("Content-Type")
	if strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, validationError("Invalid request body")
		}
		result := make(map[string]any, len(values))
		for key, entries := range values {
			if len(entries) > 0 {
				result[key] = entries[0]
			}
		}
		return result, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, validationError("Invalid request body")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, oauthError(contract.StatusBadRequest, "invalid_request", "request body is not an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, validationError("Invalid request body")
	}
	return object, nil
}

func valueString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	case float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, bool:
		return fmt.Sprint(typed), true
	default:
		return "", false
	}
}

func optionalBodyString(body map[string]any, field string) (string, bool, error) {
	value, exists := body[field]
	if !exists || value == nil {
		return "", false, nil
	}
	text, ok := valueString(value)
	if !ok {
		return "", true, validationError(field + " must be a string")
	}
	return text, true, nil
}

func bodyStringSlice(body map[string]any, field string) ([]string, bool, error) {
	raw, exists := body[field]
	if !exists || raw == nil {
		return nil, false, nil
	}
	values, ok := raw.([]any)
	if !ok {
		if typed, valid := raw.([]string); valid {
			return append([]string(nil), typed...), true, nil
		}
		return nil, true, validationError(field + " must be an array")
	}
	result := make([]string, len(values))
	for index, value := range values {
		text, valid := value.(string)
		if !valid {
			return nil, true, validationError(field + " must contain strings")
		}
		result[index] = text
	}
	return result, true, nil
}

func queryMap(ctx *engine.Context) (map[string]string, error) {
	values, err := ctx.Request().Query()
	if err != nil {
		return nil, validationError("Invalid query")
	}
	result := make(map[string]string, len(values))
	for key, entries := range values {
		if len(entries) > 0 {
			result[key] = entries[0]
		}
	}
	return result, nil
}

func appendURLQuery(raw string, values map[string]string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() {
		if err == nil {
			err = errors.New("URL must be absolute")
		}
		return "", err
	}
	query := parsed.Query()
	for key, value := range values {
		query.Set(key, value)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func formatErrorURL(raw, code, description string) string {
	separator := "?"
	if strings.Contains(raw, "?") {
		separator = "&"
	}
	return raw + separator + "error=" + code + "&error_description=" + description
}

func isSafeURLScheme(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" {
		return true
	}
	switch strings.ToLower(parsed.Scheme) {
	case "javascript", "data", "vbscript":
		return false
	default:
		return true
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func signCookie(value, secret string) string {
	return value + "." + baCrypto.MakeSignature(value, secret)
}

func readSignedCookie(request contract.Request, name, secret string) (string, bool) {
	header := strings.Join(request.Headers().Values("Cookie"), "; ")
	value, ok := cookies.Parse(header).Get(name)
	if !ok {
		return "", false
	}
	separator := strings.LastIndexByte(value, '.')
	if separator < 1 || !baCrypto.VerifySignature(value[:separator], value[separator+1:], secret) {
		return "", false
	}
	return value[:separator], true
}

func setSignedPromptCookie(ctx *engine.Context, name, value, secret string, maxAge int) {
	ctx.AddSetCookie(cookies.Serialize(name, signCookie(value, secret), cookies.Options{
		MaxAge: &maxAge, Path: "/", HTTPOnly: true, SameSite: "lax",
	}))
}

func expirePromptCookie(ctx *engine.Context, name string) {
	zero := 0
	ctx.AddSetCookie(cookies.Serialize(name, "", cookies.Options{
		MaxAge: &zero, Path: "/", HTTPOnly: true, SameSite: "lax",
	}))
}

func splitSessionCookieToken(value string) string {
	if separator := strings.IndexByte(value, '.'); separator >= 0 {
		return value[:separator]
	}
	return value
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

func recordTime(record storage.Record, field string) (time.Time, bool) {
	if record == nil {
		return time.Time{}, false
	}
	switch value := record[field].(type) {
	case time.Time:
		return value, true
	case *time.Time:
		if value != nil {
			return *value, true
		}
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, value)
		return parsed, err == nil
	}
	return time.Time{}, false
}

func clientFromRecord(record storage.Record) (Client, error) {
	if record == nil {
		return Client{}, errors.New("oidcprovider: client record is nil")
	}
	result := Client{ID: record["id"], Metadata: map[string]any{}}
	result.ClientID, _ = recordString(record, "clientId")
	result.ClientSecret, _ = recordString(record, "clientSecret")
	result.Type, _ = recordString(record, "type")
	result.Name, _ = recordString(record, "name")
	if icon, ok := recordString(record, "icon"); ok {
		result.Icon = &icon
	}
	if metadata, ok := recordString(record, "metadata"); ok && metadata != "" {
		if err := json.Unmarshal([]byte(metadata), &result.Metadata); err != nil {
			return Client{}, err
		}
	}
	result.Disabled, _ = recordBool(record, "disabled")
	redirects, _ := recordString(record, "redirectUrls")
	result.RedirectURLs = strings.Split(redirects, ",")
	if userID, ok := recordString(record, "userId"); ok {
		result.UserID = &userID
	}
	result.AuthenticationScheme, _ = recordString(record, "authenticationScheme")
	result.CreatedAt, _ = recordTime(record, "createdAt")
	result.UpdatedAt, _ = recordTime(record, "updatedAt")
	return result, nil
}

func accessTokenFromRecord(record storage.Record) (AccessToken, error) {
	if record == nil {
		return AccessToken{}, errors.New("oidcprovider: access token record is nil")
	}
	result := AccessToken{ID: record["id"]}
	result.AccessToken, _ = recordString(record, "accessToken")
	result.RefreshToken, _ = recordString(record, "refreshToken")
	var ok bool
	if result.AccessTokenExpiresAt, ok = recordTime(record, "accessTokenExpiresAt"); !ok {
		return AccessToken{}, errors.New("oidcprovider: access token expiry is missing")
	}
	if result.RefreshTokenExpiresAt, ok = recordTime(record, "refreshTokenExpiresAt"); !ok {
		return AccessToken{}, errors.New("oidcprovider: refresh token expiry is missing")
	}
	result.ClientID, _ = recordString(record, "clientId")
	result.UserID, _ = recordString(record, "userId")
	result.Scopes, _ = recordString(record, "scopes")
	result.CreatedAt, _ = recordTime(record, "createdAt")
	result.UpdatedAt, _ = recordTime(record, "updatedAt")
	return result, nil
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		switch typed := value.(type) {
		case map[string]any:
			result[key] = cloneMap(typed)
		case []string:
			result[key] = append([]string(nil), typed...)
		case []any:
			result[key] = append([]any(nil), typed...)
		default:
			result[key] = typed
		}
	}
	return result
}

func cloneClient(input Client) Client {
	result := input
	result.RedirectURLs = append([]string(nil), input.RedirectURLs...)
	result.Metadata = cloneMap(input.Metadata)
	if input.Icon != nil {
		value := *input.Icon
		result.Icon = &value
	}
	if input.UserID != nil {
		value := *input.UserID
		result.UserID = &value
	}
	return result
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		leftHash := sha256.Sum256([]byte(left))
		rightHash := sha256.Sum256([]byte(right))
		_ = subtle.ConstantTimeCompare(leftHash[:], rightHash[:])
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func signHS256(payload map[string]any, secret string) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "HS256"})
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

func verifyHS256(token, secret string, now time.Time) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	var header map[string]any
	if json.Unmarshal(headerBytes, &header) != nil || header["alg"] != "HS256" {
		return nil
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	payload := map[string]any{}
	if decoder.Decode(&payload) != nil {
		return nil
	}
	if raw, exists := payload["exp"]; exists {
		exp, err := numericValue(raw)
		if err != nil || now.Unix() >= exp {
			return nil
		}
	}
	return payload
}

func numericValue(value any) (int64, error) {
	switch typed := value.(type) {
	case json.Number:
		return typed.Int64()
	case float64:
		return int64(typed), nil
	case int64:
		return typed, nil
	case int:
		return int64(typed), nil
	default:
		return 0, fmt.Errorf("not a number")
	}
}
