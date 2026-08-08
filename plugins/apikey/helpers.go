package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

const keyAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateKey(reader io.Reader, length int, prefix string) (string, error) {
	if length <= 0 {
		length = 64
	}
	if reader == nil {
		reader = rand.Reader
	}
	random := make([]byte, length)
	if _, err := io.ReadFull(reader, random); err != nil {
		return "", fmt.Errorf("apikey: generate key: %w", err)
	}
	for index := range random {
		random[index] = keyAlphabet[int(random[index])%len(keyAlphabet)]
	}
	return prefix + string(random), nil
}

// HashKey returns single-auth's SHA-256 base64url-without-padding key hash.
func HashKey(key string) string {
	digest := sha256.Sum256([]byte(key))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func recordString(record storage.Record, key string) (string, bool) {
	value, exists := record[key]
	if !exists || value == nil {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return typed, true
	case []byte:
		return string(typed), true
	default:
		return fmt.Sprint(value), true
	}
}

func recordBool(record storage.Record, key string, fallback bool) bool {
	value, exists := record[key]
	if !exists || value == nil {
		return fallback
	}
	typed, ok := value.(bool)
	return ok && typed
}

func recordInt64(record storage.Record, key string) *int64 {
	value, exists := record[key]
	if !exists || value == nil {
		return nil
	}
	var result int64
	switch typed := value.(type) {
	case int:
		result = int64(typed)
	case int64:
		result = typed
	case float64:
		result = int64(typed)
	case float32:
		result = int64(typed)
	default:
		return nil
	}
	return &result
}

func recordTime(record storage.Record, key string) *time.Time {
	value, exists := record[key]
	if !exists || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case time.Time:
		result := typed
		return &result
	case *time.Time:
		if typed == nil {
			return nil
		}
		result := *typed
		return &result
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		if err == nil {
			return &parsed
		}
	}
	return nil
}

func recordJSON(record storage.Record, key string) any {
	value, exists := record[key]
	if !exists || value == nil {
		return nil
	}
	return cloneJSONValue(value)
}

func recordPermissions(record storage.Record) map[string][]string {
	value, exists := record["permissions"]
	if !exists || value == nil {
		return nil
	}
	result := map[string][]string{}
	switch typed := value.(type) {
	case map[string][]string:
		for resource, actions := range typed {
			result[resource] = append([]string(nil), actions...)
		}
	case map[string]any:
		for resource, raw := range typed {
			switch actions := raw.(type) {
			case []string:
				result[resource] = append([]string(nil), actions...)
			case []any:
				for _, action := range actions {
					if text, ok := action.(string); ok {
						result[resource] = append(result[resource], text)
					}
				}
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func apiKeyFromRecord(record storage.Record) APIKey {
	id, _ := recordString(record, "id")
	configID, _ := recordString(record, "configId")
	if configID == "" {
		configID = "default"
	}
	referenceID, _ := recordString(record, "referenceId")
	key, _ := recordString(record, "key")
	createdAt := recordTime(record, "createdAt")
	updatedAt := recordTime(record, "updatedAt")
	result := APIKey{
		ID: id, ConfigID: configID, ReferenceID: referenceID, Key: key,
		Enabled:             recordBool(record, "enabled", true),
		RateLimitEnabled:    recordBool(record, "rateLimitEnabled", true),
		RefillInterval:      recordInt64(record, "refillInterval"),
		RefillAmount:        recordInt64(record, "refillAmount"),
		RateLimitTimeWindow: recordInt64(record, "rateLimitTimeWindow"),
		RateLimitMax:        recordInt64(record, "rateLimitMax"),
		Remaining:           recordInt64(record, "remaining"),
		LastRefillAt:        recordTime(record, "lastRefillAt"),
		LastRequest:         recordTime(record, "lastRequest"),
		ExpiresAt:           recordTime(record, "expiresAt"),
		Metadata:            recordJSON(record, "metadata"),
		Permissions:         recordPermissions(record),
	}
	if createdAt != nil {
		result.CreatedAt = *createdAt
	}
	if updatedAt != nil {
		result.UpdatedAt = *updatedAt
	}
	if name, ok := recordString(record, "name"); ok {
		result.Name = &name
	}
	if start, ok := recordString(record, "start"); ok {
		result.Start = &start
	}
	if prefix, ok := recordString(record, "prefix"); ok {
		result.Prefix = &prefix
	}
	if count := recordInt64(record, "requestCount"); count != nil {
		result.RequestCount = *count
	}
	return result
}

func withoutSecret(key APIKey) APIKey {
	key.Key = ""
	return key
}

func normalizeConfigID(value string) string {
	if strings.TrimSpace(value) == "" {
		return "default"
	}
	return value
}
