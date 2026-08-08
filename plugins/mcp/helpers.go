package mcp

import (
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

func addProtocolCORS(ctx *engine.Context) {
	ctx.AddResponseHeader("Access-Control-Allow-Origin", "*")
	ctx.AddResponseHeader("Access-Control-Allow-Methods", "POST, OPTIONS")
	ctx.AddResponseHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")
	ctx.AddResponseHeader("Access-Control-Max-Age", "86400")
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

func requiredBodyString(body map[string]any, field string) (string, error) {
	value, exists, err := optionalBodyString(body, field)
	if err != nil {
		return "", err
	}
	if !exists || value == "" {
		return "", validationError(field + " is required")
	}
	return value, nil
}

func bodyStringSlice(body map[string]any, field string) ([]string, bool, error) {
	raw, exists := body[field]
	if !exists || raw == nil {
		return nil, false, nil
	}
	values, ok := raw.([]any)
	if !ok {
		if stringsValue, stringsOK := raw.([]string); stringsOK {
			return append([]string(nil), stringsValue...), true, nil
		}
		return nil, true, validationError(field + " must be an array")
	}
	result := make([]string, len(values))
	for index, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, true, validationError(field + " must contain only strings")
		}
		result[index] = text
	}
	return result, true, nil
}

func recordString(record storage.Record, field string) (string, bool) {
	if record == nil {
		return "", false
	}
	value, exists := record[field]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
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
	value, exists := record[field]
	if !exists || value == nil {
		return time.Time{}, false
	}
	switch typed := value.(type) {
	case time.Time:
		return typed, true
	case *time.Time:
		if typed != nil {
			return *typed, true
		}
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		return parsed, err == nil
	}
	return time.Time{}, false
}

func clientFromRecord(record storage.Record) (Client, error) {
	if record == nil {
		return Client{}, errors.New("mcp: nil oauth client")
	}
	clientID, ok := recordString(record, "clientId")
	if !ok || clientID == "" {
		return Client{}, errors.New("mcp: oauth client has no clientId")
	}
	redirects, ok := recordString(record, "redirectUrls")
	if !ok {
		return Client{}, errors.New("mcp: oauth client has no redirectUrls")
	}
	client := Client{ID: record["id"], ClientID: clientID, RedirectURLs: strings.Split(redirects, ",")}
	client.ClientSecret, _ = recordString(record, "clientSecret")
	client.Type, _ = recordString(record, "type")
	client.Name, _ = recordString(record, "name")
	client.AuthenticationScheme, _ = recordString(record, "authenticationScheme")
	client.Disabled, _ = recordBool(record, "disabled")
	client.CreatedAt, _ = recordTime(record, "createdAt")
	client.UpdatedAt, _ = recordTime(record, "updatedAt")
	if icon, exists := recordString(record, "icon"); exists {
		client.Icon = &icon
	}
	if userID, exists := recordString(record, "userId"); exists {
		client.UserID = &userID
	}
	client.Metadata = map[string]any{}
	if raw, exists := recordString(record, "metadata"); exists && raw != "" {
		if err := json.Unmarshal([]byte(raw), &client.Metadata); err != nil {
			return Client{}, fmt.Errorf("mcp: decode client metadata: %w", err)
		}
	}
	return client, nil
}

func accessTokenFromRecord(record storage.Record) (AccessToken, error) {
	if record == nil {
		return AccessToken{}, errors.New("mcp: nil access token")
	}
	result := AccessToken{ID: record["id"]}
	var ok bool
	if result.AccessToken, ok = recordString(record, "accessToken"); !ok {
		return AccessToken{}, errors.New("mcp: access token value is missing")
	}
	result.RefreshToken, _ = recordString(record, "refreshToken")
	if result.AccessTokenExpiresAt, ok = recordTime(record, "accessTokenExpiresAt"); !ok {
		return AccessToken{}, errors.New("mcp: access token expiry is missing")
	}
	if result.RefreshTokenExpiresAt, ok = recordTime(record, "refreshTokenExpiresAt"); !ok {
		return AccessToken{}, errors.New("mcp: refresh token expiry is missing")
	}
	result.ClientID, _ = recordString(record, "clientId")
	result.UserID, _ = recordString(record, "userId")
	result.Scopes, _ = recordString(record, "scopes")
	result.CreatedAt, _ = recordTime(record, "createdAt")
	result.UpdatedAt, _ = recordTime(record, "updatedAt")
	return result, nil
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		// Compare a fixed digest as well so an attacker cannot distinguish the
		// mismatch branch from an empty secret by gross timing alone.
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

func isSafeURLScheme(value string) bool {
	trimmed := strings.TrimSpace(value)
	parsed, err := url.Parse(trimmed)
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

func redirectErrorURL(raw, code, description string) string {
	separator := "?"
	if strings.Contains(raw, "?") {
		separator = "&"
	}
	return raw + separator + "error=" + code + "&error_description=" + description
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
	epoch := time.Unix(0, 0).UTC()
	ctx.AddSetCookie(cookies.Serialize(name, "", cookies.Options{
		MaxAge: &zero, Expires: &epoch, Path: "/", HTTPOnly: true, SameSite: "lax",
	}))
}

func splitSessionCookieToken(value string) string {
	if index := strings.IndexByte(value, '.'); index >= 0 {
		return value[:index]
	}
	return value
}

func recordID(record storage.Record) any {
	if record == nil {
		return nil
	}
	return record["id"]
}
