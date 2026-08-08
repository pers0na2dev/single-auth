// Package recordutil contains conversions for storage records used by the
// server runtime. It is deliberately internal: storage.Record remains the
// public adapter boundary.
package recordutil

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// String reads a record value using the compatibility string conversions.
func String(record storage.Record, key string) (string, bool) {
	if record == nil {
		return "", false
	}
	value, ok := record[key]
	if !ok || value == nil {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return typed, true
	case fmt.Stringer:
		return typed.String(), true
	case json.Number:
		return typed.String(), true
	default:
		return fmt.Sprint(value), true
	}
}

// Bool reads a record value using the compatibility boolean conversions.
func Bool(record storage.Record, key string) (bool, bool) {
	value, ok := record[key]
	if !ok || value == nil {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(typed)
		return parsed, err == nil
	case int:
		return typed != 0, true
	case int64:
		return typed != 0, true
	case float64:
		return typed != 0, true
	default:
		return false, false
	}
}

// Time reads a timestamp stored as time.Time, RFC3339 text, or Unix millis.
func Time(record storage.Record, key string) (time.Time, bool) {
	value, ok := record[key]
	if !ok || value == nil {
		return time.Time{}, false
	}
	switch typed := value.(type) {
	case time.Time:
		return typed, true
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		return parsed, err == nil
	case int64:
		return time.UnixMilli(typed), true
	case float64:
		return time.UnixMilli(int64(typed)), true
	default:
		return time.Time{}, false
	}
}
