package webauthn

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

const (
	maxCBORDepth      = 16
	maxCBORArrayItems = 256
	maxCBORMapPairs   = 256
)

var (
	webAuthnCBORDecode cbor.DecMode
	webAuthnCBOREncode cbor.EncMode
)

func init() {
	var err error
	webAuthnCBORDecode, err = cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  maxCBORDepth,
		MaxArrayElements: maxCBORArrayItems,
		MaxMapPairs:      maxCBORMapPairs,
		IndefLength:      cbor.IndefLengthAllowed,
		TagsMd:           cbor.TagsForbidden,
		IntDec:           cbor.IntDecConvertSignedOrFail,
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	webAuthnCBOREncode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
}

func decodeCBORFirst(data []byte, target any) (consumed int, err error) {
	if len(data) == 0 {
		return 0, errors.New("empty CBOR input")
	}
	rest, err := webAuthnCBORDecode.UnmarshalFirst(data, target)
	if err != nil {
		return 0, fmt.Errorf("decode CBOR: %w", err)
	}
	return len(data) - len(rest), nil
}

func decodeCBORExact(data []byte, target any) error {
	consumed, err := decodeCBORFirst(data, target)
	if err != nil {
		return err
	}
	if consumed != len(data) {
		return fmt.Errorf("decode CBOR: %d trailing bytes", len(data)-consumed)
	}
	return nil
}

func encodeCBOR(value any) ([]byte, error) {
	encoded, err := webAuthnCBOREncode.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode CBOR: %w", err)
	}
	return encoded, nil
}

func mapStringAny(value any) (map[string]any, error) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, nested := range typed {
			converted, err := normalizeCBORValue(nested)
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, nested := range typed {
			text, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("CBOR map key had type %T, expected string", key)
			}
			converted, err := normalizeCBORValue(nested)
			if err != nil {
				return nil, err
			}
			result[text] = converted
		}
		return result, nil
	default:
		return nil, fmt.Errorf("CBOR value had type %T, expected map", value)
	}
}

func normalizeCBORValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any, map[any]any:
		return mapStringAny(typed)
	case []any:
		result := make([]any, len(typed))
		for index, nested := range typed {
			converted, err := normalizeCBORValue(nested)
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	default:
		return value, nil
	}
}

func byteString(value any, name string) ([]byte, error) {
	valueBytes, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("%s had type %T, expected byte string", name, value)
	}
	return append([]byte(nil), valueBytes...), nil
}

func integer(value any, name string) (int, error) {
	switch typed := value.(type) {
	case int64:
		converted := int(typed)
		if int64(converted) != typed {
			return 0, fmt.Errorf("%s integer overflow", name)
		}
		return converted, nil
	case uint64:
		if typed > uint64(^uint(0)>>1) {
			return 0, fmt.Errorf("%s integer overflow", name)
		}
		return int(typed), nil
	case int:
		return typed, nil
	default:
		return 0, fmt.Errorf("%s had type %T, expected integer", name, value)
	}
}

func stringField(value any, name string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s had type %T, expected text string", name, value)
	}
	return text, nil
}

func byteStringArray(value any, name string) ([][]byte, error) {
	items, ok := value.([]any)
	if !ok {
		// Decoding into interface sometimes preserves a concrete [][]byte.
		if bytesList, ok := value.([][]byte); ok {
			result := make([][]byte, len(bytesList))
			for index := range bytesList {
				result[index] = append([]byte(nil), bytesList[index]...)
			}
			return result, nil
		}
		return nil, fmt.Errorf("%s had type %T, expected array", name, value)
	}
	result := make([][]byte, len(items))
	for index, item := range items {
		bytesValue, ok := item.([]byte)
		if !ok {
			return nil, fmt.Errorf("%s[%d] had type %T, expected byte string", name, index, item)
		}
		result[index] = append([]byte(nil), bytesValue...)
	}
	return result, nil
}

func mapsEqualBytes(first, second []byte) bool { return bytes.Equal(first, second) }

func cloneAnyMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	target := make(map[string]any, len(source))
	for key, value := range source {
		target[key] = value
	}
	return target
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
