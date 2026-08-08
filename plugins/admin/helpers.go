package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/pers0na2dev/single-auth/security/authorization"
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
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, validationError("Invalid request body").WithCause(err)
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

func requiredCoercedString(body map[string]any, field string) (string, error) {
	value, exists := body[field]
	if !exists {
		return "", validationError(field + " is required")
	}
	if value == nil {
		return "null", nil
	}
	switch typed := value.(type) {
	case string:
		return typed, nil
	case json.Number:
		return typed.String(), nil
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), nil
	case float32:
		return strconv.FormatFloat(float64(typed), 'f', -1, 32), nil
	case int:
		return strconv.Itoa(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case bool:
		return strconv.FormatBool(typed), nil
	default:
		return "", validationError(field + " must be coercible to a string")
	}
}

func optionalString(body map[string]any, field string) (*string, error) {
	value, exists := body[field]
	if !exists || value == nil {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, validationError(field + " must be a string")
	}
	return &text, nil
}

func optionalNumber(body map[string]any, field string) (*float64, error) {
	value, exists := body[field]
	if !exists || value == nil {
		return nil, nil
	}
	parsed, ok := numberValue(value)
	if !ok {
		return nil, validationError(field + " must be a number")
	}
	return &parsed, nil
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	default:
		return 0, false
	}
}

func roleValue(value any) ([]string, error) {
	switch typed := value.(type) {
	case string:
		return []string{typed}, nil
	case []string:
		return append([]string(nil), typed...), nil
	case []any:
		result := make([]string, len(typed))
		for index, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, adminError(contract.StatusBadRequest, ErrorInvalidRoleType)
			}
			result[index] = text
		}
		return result, nil
	default:
		return nil, adminError(contract.StatusBadRequest, ErrorInvalidRoleType)
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
	if ok {
		return text, true
	}
	if key == "id" || key == "userId" {
		switch typed := value.(type) {
		case json.Number:
			return typed.String(), true
		case int:
			return strconv.Itoa(typed), true
		case int64:
			return strconv.FormatInt(typed, 10), true
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64), true
		}
	}
	return "", false
}

func recordBool(record storage.Record, key string) bool {
	value, _ := record[key].(bool)
	return value
}

func recordTime(record storage.Record, key string) (time.Time, bool) {
	if record == nil {
		return time.Time{}, false
	}
	switch value := record[key].(type) {
	case time.Time:
		return value, !value.IsZero()
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, value)
		return parsed, err == nil
	default:
		return time.Time{}, false
	}
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func splitComma(value string) []string { return strings.Split(value, ",") }

func joinRoles(roles []string) string { return strings.Join(roles, ",") }

func permission(resource string, actions ...string) authorization.AuthorizeRequest {
	return authorization.AuthorizeRequest{{Resource: resource, Actions: actions}}
}

func validEmail(value string) bool {
	if value == "" || strings.Contains(value, "..") || strings.Count(value, "@") != 1 {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && !strings.HasPrefix(value, ".")
}

func passwordLength(value string) int { return len(utf16.Encode([]rune(value))) }

func jsonSuccess(value any) (contract.Response, error) {
	return contract.JSONResponse(contract.StatusOK, value)
}

func stringQuery(values map[string][]string, name string) (string, bool) {
	items, ok := values[name]
	if !ok || len(items) == 0 {
		return "", false
	}
	return items[0], true
}

func parseQueryScalar(value string) any {
	if value == "true" {
		return true
	}
	if value == "false" {
		return false
	}
	if integer, err := strconv.ParseInt(value, 10, 64); err == nil {
		return integer
	}
	return value
}
