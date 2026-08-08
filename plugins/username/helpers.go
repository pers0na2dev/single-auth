package username

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

const maxRequestBodyBytes = 4 << 20

func decodeObject(ctx *engine.Context) (map[string]any, error) {
	request := ctx.Request()
	body := request.Body()
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

func decodeEndpointObject(request contract.Request) (map[string]any, bool) {
	body := bytes.TrimSpace(request.Body())
	if len(body) == 0 || len(body) > maxRequestBodyBytes {
		return nil, false
	}
	contentType := strings.Join(request.Headers().Values("Content-Type"), ", ")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if mediaType == "application/x-www-form-urlencoded" {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, false
		}
		result := make(map[string]any, len(values))
		for key, entries := range values {
			if len(entries) == 0 {
				result[key] = ""
				continue
			}
			switch entries[0] {
			case "true":
				result[key] = true
			case "false":
				result[key] = false
			default:
				result[key] = entries[0]
			}
		}
		return result, true
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	object, ok := decoded.(map[string]any)
	return object, ok
}

func replaceEndpointObject(ctx *engine.Context, body map[string]any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return internalError(err)
	}
	request := ctx.Request()
	headers := request.Headers()
	headers.Set("Content-Type", "application/json")
	ctx.ReplaceRequest(request.WithHeaders(headers).WithBody(encoded))
	return nil
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

func optionalBool(body map[string]any, field string) (*bool, error) {
	value, exists := body[field]
	if !exists {
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

func modelUserFromRecord(record storage.Record) model.User {
	id, _ := recordString(record, "id")
	name, _ := recordString(record, "name")
	email, _ := recordString(record, "email")
	verified, _ := recordBool(record, "emailVerified")
	createdAt, _ := recordTime(record, "createdAt")
	updatedAt, _ := recordTime(record, "updatedAt")
	user := model.User{
		Core: model.Core{ID: id, CreatedAt: createdAt, UpdatedAt: updatedAt},
		Name: name, Email: email, EmailVerified: verified,
		AdditionalFields: model.FieldsFromRecord(record,
			"id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt"),
	}
	if image, exists := record["image"]; exists {
		if image == nil {
			user.Image = model.Null[string]()
		} else if text, ok := image.(string); ok {
			user.Image = model.Present(text)
		}
	}
	return user
}

func usernameError(status int, code string) *contract.APIError {
	return contract.NewAPIError(status, code, errorMessages[code])
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func internalError(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(err)
}

func failedToCreateSession(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"FAILED_TO_CREATE_SESSION",
		"Failed to create session",
	).WithCause(err)
}

// encodeURIComponent implements JavaScript's UTF-8 encodeURIComponent set.
func encodeURIComponent(value string) string {
	const hex = "0123456789ABCDEF"
	var encoded strings.Builder
	for _, b := range []byte(value) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') || strings.ContainsRune("-_.!~*'()", rune(b)) {
			encoded.WriteByte(b)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hex[b>>4])
		encoded.WriteByte(hex[b&15])
	}
	return encoded.String()
}
