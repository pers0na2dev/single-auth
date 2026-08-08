package deviceauthorization

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	deviceCodeAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	userCodeAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	maxRequestBody     = 4 << 20
)

func (p *plugin) randomString(length int, alphabet string, modulo bool) (string, error) {
	if length <= 0 || len(alphabet) < 2 || len(alphabet) > 256 {
		return "", fmt.Errorf("deviceauthorization: invalid random string configuration")
	}
	result := make([]byte, length)
	buffer := make([]byte, length*2+1)
	written := 0
	ceiling := 256 - 256%len(alphabet)
	for written < length {
		if _, err := io.ReadFull(p.random, buffer); err != nil {
			return "", fmt.Errorf("deviceauthorization: generate random code: %w", err)
		}
		for _, value := range buffer {
			if !modulo && int(value) >= ceiling {
				continue
			}
			result[written] = alphabet[int(value)%len(alphabet)]
			written++
			if written == length {
				break
			}
		}
	}
	return string(result), nil
}

func decodeObject(ctx *engine.Context) (map[string]any, error) {
	body := ctx.Request().Body()
	if len(body) > maxRequestBody {
		return nil, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Request body is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil || result == nil {
		return nil, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body").WithCause(err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	return result, nil
}

func requiredString(object map[string]any, key string) (string, error) {
	value, exists := object[key]
	text, ok := value.(string)
	if !exists || !ok {
		return "", contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", key+" is required")
	}
	return text, nil
}

func optionalString(object map[string]any, key string) (*string, error) {
	value, exists := object[key]
	if !exists {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", key+" must be a string")
	}
	return &text, nil
}

func jsonSuccess(status int, value any) (contract.Response, error) {
	return contract.JSONResponse(status, value)
}

func cleanUserCode(value string) string { return strings.ReplaceAll(value, "-", "") }

func floorDurationSeconds(value time.Duration) int64 {
	milliseconds := value.Milliseconds()
	seconds := milliseconds / int64(time.Second/time.Millisecond)
	if milliseconds < 0 && milliseconds%int64(time.Second/time.Millisecond) != 0 {
		seconds--
	}
	return seconds
}

func formEncode(value string) string {
	const hex = "0123456789ABCDEF"
	var builder strings.Builder
	for _, value := range []byte(value) {
		switch {
		case value >= 'a' && value <= 'z', value >= 'A' && value <= 'Z', value >= '0' && value <= '9', value == '*', value == '-', value == '.', value == '_':
			builder.WriteByte(value)
		case value == ' ':
			builder.WriteByte('+')
		default:
			builder.WriteByte('%')
			builder.WriteByte(hex[value>>4])
			builder.WriteByte(hex[value&15])
		}
	}
	return builder.String()
}

func setQueryParameter(rawQuery, name, value string) string {
	encoded := formEncode(name) + "=" + formEncode(value)
	if rawQuery == "" {
		return encoded
	}
	parts := strings.Split(rawQuery, "&")
	replaced := false
	kept := parts[:0]
	for _, part := range parts {
		key := part
		if index := strings.IndexByte(key, '='); index >= 0 {
			key = key[:index]
		}
		decoded, err := url.QueryUnescape(key)
		if err == nil && decoded == name {
			if !replaced {
				kept = append(kept, encoded)
				replaced = true
			}
			continue
		}
		kept = append(kept, part)
	}
	if !replaced {
		kept = append(kept, encoded)
	}
	return strings.Join(kept, "&")
}

func buildVerificationURIs(configured, baseURL, userCode string) (string, string, error) {
	uri := configured
	if uri == "" {
		uri = DeviceVerifyPath
	}
	reference, err := url.Parse(uri)
	if err != nil {
		return "", "", err
	}
	verification := reference
	if !reference.IsAbs() {
		base, parseErr := url.Parse(baseURL)
		if parseErr != nil || base.Scheme == "" || base.Host == "" {
			if parseErr == nil {
				parseErr = fmt.Errorf("base URL must be absolute")
			}
			return "", "", parseErr
		}
		verification = base.ResolveReference(reference)
	}
	complete := *verification
	complete.RawQuery = setQueryParameter(verification.RawQuery, "user_code", userCode)
	return verification.String(), complete.String(), nil
}

func (p *plugin) resolveBaseURL(ctx *engine.Context) (string, error) {
	if p.options.Runtime.ResolveBaseURL != nil {
		return p.options.Runtime.ResolveBaseURL(ctx)
	}
	if p.options.Runtime.BaseURL != "" {
		return p.options.Runtime.BaseURL, nil
	}
	request := ctx.Request()
	scheme := request.Scheme()
	if scheme == "" {
		scheme = "http"
	}
	if request.Host() == "" {
		return "", fmt.Errorf("deviceauthorization: base URL is unavailable")
	}
	return scheme + "://" + request.Host(), nil
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

func recordTime(record storage.Record, key string) (time.Time, bool) {
	if record == nil {
		return time.Time{}, false
	}
	switch value := record[key].(type) {
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

func recordMilliseconds(record storage.Record, key string) (int64, bool) {
	if record == nil {
		return 0, false
	}
	switch value := record[key].(type) {
	case int:
		return int64(value), true
	case int64:
		return value, true
	case int32:
		return int64(value), true
	case float64:
		return int64(value), true
	case float32:
		return int64(value), true
	case json.Number:
		integer, err := strconv.ParseInt(string(value), 10, 64)
		if err == nil {
			return integer, true
		}
		decimal, err := strconv.ParseFloat(string(value), 64)
		return int64(decimal), err == nil
	}
	return 0, false
}

func deviceCodeFromRecord(record storage.Record) (DeviceCode, error) {
	id, idOK := recordString(record, "id")
	deviceCode, deviceOK := recordString(record, "deviceCode")
	userCode, userOK := recordString(record, "userCode")
	expiresAt, expiryOK := recordTime(record, "expiresAt")
	status, statusOK := recordString(record, "status")
	if !idOK || !deviceOK || !userOK || !expiryOK || !statusOK {
		return DeviceCode{}, fmt.Errorf("deviceauthorization: malformed deviceCode record")
	}
	result := DeviceCode{ID: id, DeviceCode: deviceCode, UserCode: userCode, ExpiresAt: expiresAt, Status: status}
	if value, ok := recordString(record, "userId"); ok {
		result.UserID = &value
	}
	if value, ok := recordTime(record, "lastPolledAt"); ok {
		result.LastPolledAt = &value
	}
	if value, ok := recordMilliseconds(record, "pollingInterval"); ok {
		result.PollingInterval = value
	}
	if value, ok := recordString(record, "clientId"); ok {
		result.ClientID = value
	}
	if value, ok := recordString(record, "scope"); ok {
		result.Scope = &value
	}
	return result, nil
}
