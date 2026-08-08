// Package httpio contains transport-neutral HTTP request decoding helpers used
// by the authentication runtime.
package httpio

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/url"

	"github.com/pers0na2dev/single-auth/core/contract"
)

// DecodeObjectBody decodes a JSON object or URL-encoded form body. The caller
// supplies the stable public error code and message used for non-object input.
func DecodeObjectBody(request contract.Request, objectErrorCode, objectErrorMessage string) (map[string]any, error) {
	body := request.Body()
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, contract.NewAPIError(
			contract.StatusBadRequest,
			objectErrorCode,
			objectErrorMessage,
		)
	}
	contentType, _ := request.Headers().Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if mediaType == "application/x-www-form-urlencoded" {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, contract.NewAPIError(contract.StatusBadRequest, "INVALID_BODY", "Invalid request body").WithCause(err)
		}
		result := make(map[string]any, len(values))
		for key, list := range values {
			if len(list) == 0 {
				result[key] = ""
				continue
			}
			switch list[0] {
			case "true":
				result[key] = true
			case "false":
				result[key] = false
			default:
				result[key] = list[0]
			}
		}
		return result, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil || result == nil {
		return nil, contract.NewAPIError(
			contract.StatusBadRequest,
			objectErrorCode,
			objectErrorMessage,
		).WithCause(err)
	}
	var trailing any
	if trailingErr := decoder.Decode(&trailing); trailingErr != io.EOF {
		return nil, contract.NewAPIError(
			contract.StatusBadRequest,
			objectErrorCode,
			objectErrorMessage,
		).WithCause(trailingErr)
	}
	return result, nil
}

// RequiredString reads a required string field.
func RequiredString(body map[string]any, name string) (string, bool) {
	value, exists := body[name]
	if !exists {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

// OptionalString distinguishes an absent field from an explicit null.
func OptionalString(body map[string]any, name string) (*string, bool) {
	value, exists := body[name]
	if !exists {
		return nil, false
	}
	if value == nil {
		return nil, true
	}
	text, ok := value.(string)
	if !ok {
		return nil, false
	}
	return &text, true
}

// OptionalBool distinguishes an absent field from an explicit null.
func OptionalBool(body map[string]any, name string) (*bool, bool) {
	value, exists := body[name]
	if !exists {
		return nil, false
	}
	if value == nil {
		return nil, true
	}
	boolean, ok := value.(bool)
	if !ok {
		return nil, false
	}
	return &boolean, true
}
