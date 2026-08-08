package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

const privateKeyDecryptMessage = "Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption."

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (reader *lockedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.r.Read(target)
}

func cloneRecord(source storage.Record) storage.Record {
	if source == nil {
		return nil
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		clone := make(storage.Record, len(source))
		for key, value := range source {
			clone[key] = value
		}
		return clone
	}
	var clone storage.Record
	if json.Unmarshal(encoded, &clone) != nil {
		return nil
	}
	return clone
}

func cloneMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func recordString(record storage.Record, field string) (string, bool) {
	value, exists := record[field]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func recordTime(record storage.Record, field string) (time.Time, bool) {
	value, exists := record[field]
	if !exists || value == nil {
		return time.Time{}, false
	}
	switch item := value.(type) {
	case time.Time:
		return item, true
	case *time.Time:
		if item != nil {
			return *item, true
		}
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, item)
		return parsed, err == nil
	}
	return time.Time{}, false
}

func decodeObject(body []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, badRequest("VALIDATION_ERROR", "Invalid request body", err)
	}
	if value == nil {
		return nil, badRequest("VALIDATION_ERROR", "Invalid request body", nil)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, badRequest("VALIDATION_ERROR", "Invalid request body", err)
	}
	return value, nil
}

func badRequest(code, message string, cause error) error {
	return contract.NewAPIError(contract.StatusBadRequest, code, message).WithCause(cause)
}

func internalError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(err)
}

func notFound() error {
	return contract.NewAPIError(contract.StatusNotFound, "NOT_FOUND", "Not Found")
}

func normalizeAudience(value any) (any, error) {
	switch audience := value.(type) {
	case nil:
		return nil, nil
	case string:
		return audience, nil
	case []string:
		return append([]string(nil), audience...), nil
	case []any:
		result := make([]string, len(audience))
		for index, item := range audience {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("jwt: Token.Audience must be a string or []string")
			}
			result[index] = text
		}
		return result, nil
	default:
		return nil, fmt.Errorf("jwt: Token.Audience must be a string or []string")
	}
}

func audiences(value any) []string {
	switch audience := value.(type) {
	case string:
		return []string{audience}
	case []string:
		return append([]string(nil), audience...)
	case []any:
		result := make([]string, 0, len(audience))
		for _, item := range audience {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func headerList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts)+1)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		result = append(result, part)
	}
	if _, exists := seen["set-auth-jwt"]; !exists {
		result = append(result, "set-auth-jwt")
	}
	return result
}
