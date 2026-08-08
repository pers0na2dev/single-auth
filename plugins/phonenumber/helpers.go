package phonenumber

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"time"
	"unicode/utf16"

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

func optionalBool(body map[string]any, field string) (*bool, error) {
	value, exists := body[field]
	if !exists || value == nil {
		return nil, nil
	}
	boolean, ok := value.(bool)
	if !ok {
		return nil, validationError(field + " must be a boolean")
	}
	return &boolean, nil
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

func cloneObject(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
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

func parseAttempts(value string) int {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func utf16Length(value string) int { return len(utf16.Encode([]rune(value))) }

func (p *plugin) serializeUser(user storage.Record) any {
	if p.options.Runtime.SerializeUser != nil {
		return p.options.Runtime.SerializeUser(cloneRecord(user))
	}
	return cloneRecord(user)
}

func successResponse(value map[string]any) (contract.Response, error) {
	return contract.JSONResponse(contract.StatusOK, value)
}
