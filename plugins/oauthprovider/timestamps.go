package oauthprovider

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// JavaScript Date accepts values only inside the TimeClip range.
const javascriptDateLimitMilliseconds = 8.64e15

// NormalizeTimestampValue implements the timestamp normalization used by the
// single-auth OAuth provider. It accepts dates, epoch milliseconds, numeric
// millisecond strings, and common ISO/RFC date strings.
func NormalizeTimestampValue(value any) (time.Time, bool) {
	if value == nil {
		return time.Time{}, false
	}

	switch typed := value.(type) {
	case time.Time:
		return normalizeTimestampTime(typed)
	case *time.Time:
		if typed == nil {
			return time.Time{}, false
		}
		return normalizeTimestampTime(*typed)
	case string:
		return normalizeTimestampString(typed)
	case json.Number:
		number, err := strconv.ParseFloat(string(typed), 64)
		if err != nil {
			return time.Time{}, false
		}
		return normalizeTimestampNumber(number)
	case float64:
		return normalizeTimestampNumber(typed)
	case float32:
		return normalizeTimestampNumber(float64(typed))
	case int:
		return normalizeTimestampNumber(float64(typed))
	case int8:
		return normalizeTimestampNumber(float64(typed))
	case int16:
		return normalizeTimestampNumber(float64(typed))
	case int32:
		return normalizeTimestampNumber(float64(typed))
	case int64:
		return normalizeTimestampNumber(float64(typed))
	case uint:
		return normalizeTimestampNumber(float64(typed))
	case uint8:
		return normalizeTimestampNumber(float64(typed))
	case uint16:
		return normalizeTimestampNumber(float64(typed))
	case uint32:
		return normalizeTimestampNumber(float64(typed))
	case uint64:
		return normalizeTimestampNumber(float64(typed))
	default:
		return time.Time{}, false
	}
}

// ResolveSessionAuthTime reads createdAt or created_at from a direct session
// object, then from a nested session object. updatedAt fields are deliberately
// ignored, matching single-auth.
func ResolveSessionAuthTime(value any) (time.Time, bool) {
	if _, isTime := value.(time.Time); isTime {
		return NormalizeTimestampValue(value)
	}
	if _, isTimePointer := value.(*time.Time); isTimePointer {
		return NormalizeTimestampValue(value)
	}

	direct, object := timestampObjectValue(value)
	if !object {
		return NormalizeTimestampValue(value)
	}
	if candidate, exists := lookupTimestampObjectField(direct, "createdAt"); exists {
		if normalized, ok := NormalizeTimestampValue(candidate); ok {
			return normalized, true
		}
	}
	if candidate, exists := lookupTimestampObjectField(direct, "created_at"); exists {
		if normalized, ok := NormalizeTimestampValue(candidate); ok {
			return normalized, true
		}
	}

	nestedValue, exists := lookupTimestampObjectField(direct, "session")
	if !exists {
		return time.Time{}, false
	}
	nested, nestedObject := timestampObjectValue(nestedValue)
	if !nestedObject {
		return time.Time{}, false
	}
	if candidate, exists := lookupTimestampObjectField(nested, "createdAt"); exists {
		if normalized, ok := NormalizeTimestampValue(candidate); ok {
			return normalized, true
		}
	}
	if candidate, exists := lookupTimestampObjectField(nested, "created_at"); exists {
		return NormalizeTimestampValue(candidate)
	}
	return time.Time{}, false
}

func normalizeTimestampNumber(value float64) (time.Time, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > javascriptDateLimitMilliseconds {
		return time.Time{}, false
	}
	milliseconds := int64(math.Trunc(value))
	return time.UnixMilli(milliseconds).UTC(), true
}

func normalizeTimestampTime(value time.Time) (time.Time, bool) {
	milliseconds := value.UnixMilli()
	if math.Abs(float64(milliseconds)) > javascriptDateLimitMilliseconds {
		return time.Time{}, false
	}
	return time.UnixMilli(milliseconds).UTC(), true
}

func normalizeTimestampString(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}
	if number, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(number) && !math.IsInf(number, 0) {
		return normalizeTimestampNumber(number)
	}

	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02",
		time.RFC1123Z,
		time.RFC1123,
		time.RFC822Z,
		time.RFC822,
		time.ANSIC,
		time.UnixDate,
		time.RubyDate,
	} {
		parsed, err := time.Parse(layout, trimmed)
		if err == nil {
			return normalizeTimestampTime(parsed)
		}
	}
	return time.Time{}, false
}

func timestampObjectValue(value any) (reflect.Value, bool) {
	if value == nil {
		return reflect.Value{}, false
	}
	reflected := reflect.ValueOf(value)
	for reflected.IsValid() && (reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Interface) {
		if reflected.IsNil() {
			return reflect.Value{}, false
		}
		reflected = reflected.Elem()
	}
	if !reflected.IsValid() || (reflected.Kind() != reflect.Map && reflected.Kind() != reflect.Struct) {
		return reflect.Value{}, false
	}
	return reflected, true
}

func lookupTimestampObjectField(object reflect.Value, name string) (any, bool) {
	switch object.Kind() {
	case reflect.Map:
		if object.Type().Key().Kind() != reflect.String {
			return nil, false
		}
		field := object.MapIndex(reflect.ValueOf(name).Convert(object.Type().Key()))
		if !field.IsValid() {
			return nil, false
		}
		return field.Interface(), true
	case reflect.Struct:
		typeOfObject := object.Type()
		for index := 0; index < object.NumField(); index++ {
			fieldType := typeOfObject.Field(index)
			jsonName := strings.Split(fieldType.Tag.Get("json"), ",")[0]
			if fieldType.Name != name && jsonName != name {
				continue
			}
			field := object.Field(index)
			if !field.CanInterface() {
				return nil, false
			}
			return field.Interface(), true
		}
	}
	return nil, false
}
