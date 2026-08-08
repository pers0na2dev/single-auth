package storage

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// IDGenerationMode is the Go representation of reference implementation's
// advanced.database.generateId option. IDGenerationNone corresponds to the
// JavaScript value false; IDGenerationDefault corresponds to an omitted
// option.
type IDGenerationMode string

const (
	IDGenerationDefault IDGenerationMode = ""
	IDGenerationNone    IDGenerationMode = "none"
	IDGenerationSerial  IDGenerationMode = "serial"
	IDGenerationUUID    IDGenerationMode = "uuid"
)

// IDGenerator generates an ID for a canonical schema model.
type IDGenerator func(model string) (any, error)

// IDFieldFactoryOptions configures InitGetIDField. GenerateIDFunc has the same
// priority as a function-valued reference implementation generateId option, followed by the
// UUID mode, CustomIDGenerator, and the built-in 32-character generator.
type IDFieldFactoryOptions struct {
	Schema              Schema
	UsePlural           bool
	DisableIDGeneration bool
	GenerateID          IDGenerationMode
	GenerateIDFunc      IDGenerator
	CustomIDGenerator   IDGenerator
	SupportsUUIDs       bool
	Random              io.Reader
	Warn                func(message string)
}

// IDFieldOptions are the per-model arguments accepted by an IDFieldFactory.
type IDFieldOptions struct {
	CustomModelName string
	ForceAllowID    bool
}

// IDFieldFactory resolves the implicit ID field for one schema model.
type IDFieldFactory func(IDFieldOptions) (FieldAttribute, error)

var validIDUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const (
	defaultIDAlphabet  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	invalidUUIDWarning = "[Adapter Factory] - Invalid UUID value for field `id` provided when `forceAllowId` is true. Generating a new UUID."
)

// InitGetIDField is the Go equivalent of reference implementation's initGetIdField. The
// returned FieldAttribute plugs directly into the existing adapter schema and
// keeps the upstream default-value and transform ordering.
func InitGetIDField(options IDFieldFactoryOptions) IDFieldFactory {
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	usePlural := options.UsePlural || options.Schema.UsePlural

	return func(fieldOptions IDFieldOptions) (FieldAttribute, error) {
		mode := options.GenerateID
		if options.GenerateIDFunc != nil {
			// A function is a distinct member of the upstream union and takes
			// precedence if a Go caller also populated GenerateID.
			mode = IDGenerationDefault
		}
		useNumberID := mode == IDGenerationSerial
		useUUIDs := mode == IDGenerationUUID
		shouldGenerateID := true
		switch {
		case options.DisableIDGeneration:
			shouldGenerateID = false
		case useNumberID && !fieldOptions.ForceAllowID:
			shouldGenerateID = false
		case useUUIDs:
			shouldGenerateID = !options.SupportsUUIDs
		}

		candidate := fieldOptions.CustomModelName
		if candidate == "" {
			candidate = "id"
		}
		model, err := resolveIDModel(options.Schema, usePlural, candidate)
		if err != nil {
			return FieldAttribute{}, err
		}

		fieldType := FieldString
		if useNumberID {
			fieldType = FieldNumber
		}
		field := FieldAttribute{
			Type:     fieldType,
			Required: Bool(shouldGenerateID),
		}
		if shouldGenerateID {
			field.DefaultValue = func(ValueContext) (any, error) {
				switch {
				case options.DisableIDGeneration:
					return nil, nil
				case options.GenerateIDFunc != nil:
					return options.GenerateIDFunc(model)
				case mode == IDGenerationNone || mode == IDGenerationSerial:
					return nil, nil
				case mode == IDGenerationUUID:
					return generateIDUUID(random)
				case options.CustomIDGenerator != nil:
					return options.CustomIDGenerator(model)
				default:
					return generateDefaultID(random, 32)
				}
			}
		}

		field.Transform = FieldTransform{
			Input: func(value any) (any, error) {
				if isJavaScriptFalsy(value) {
					return nil, nil
				}
				if useNumberID {
					if number, ok := javascriptNumber(value); ok {
						return number, nil
					}
					return nil, nil
				}
				if useUUIDs {
					if shouldGenerateID && !fieldOptions.ForceAllowID {
						return value, nil
					}
					if options.DisableIDGeneration {
						return nil, nil
					}
					if fieldOptions.ForceAllowID {
						if text, ok := value.(string); ok {
							if validIDUUID.MatchString(text) {
								return text, nil
							}
							if options.Warn != nil {
								options.Warn(invalidUUIDWarning)
							}
						}
					}
					if options.SupportsUUIDs {
						return nil, nil
					}
					if _, isString := value.(string); !isString {
						return generateIDUUID(random)
					}
					return nil, nil
				}
				return value, nil
			},
			Output: func(value any) (any, error) {
				if isJavaScriptFalsy(value) {
					return nil, nil
				}
				return javascriptString(value), nil
			},
		}
		return field, nil
	}
}

func resolveIDModel(schema Schema, usePlural bool, candidate string) (string, error) {
	resolve := func(value string) (string, bool) {
		if _, ok := schema.Models[value]; ok {
			return value, true
		}
		// Go maps do not retain insertion order. Sorting makes alias resolution
		// stable for malformed schemas with duplicate physical names.
		models := make([]string, 0, len(schema.Models))
		for canonical := range schema.Models {
			models = append(models, canonical)
		}
		sort.Strings(models)
		for _, canonical := range models {
			physical := schema.Models[canonical].ModelName
			if physical == "" {
				physical = canonical
			}
			if physical == value {
				return canonical, true
			}
		}
		return "", false
	}

	if usePlural && strings.HasSuffix(candidate, "s") {
		if model, ok := resolve(strings.TrimSuffix(candidate, "s")); ok {
			return model, nil
		}
	}
	if model, ok := resolve(candidate); ok {
		return model, nil
	}
	return "", fmt.Errorf("%w: %q", ErrModelNotFound, candidate)
}

func generateDefaultID(random io.Reader, length int) (string, error) {
	const alphabetLength = byte(len(defaultIDAlphabet))
	const maxValid = byte(256 / len(defaultIDAlphabet) * len(defaultIDAlphabet))
	buffer := make([]byte, length*2)
	result := make([]byte, 0, length)
	index := len(buffer)
	for len(result) < length {
		if index >= len(buffer) {
			if _, err := io.ReadFull(random, buffer); err != nil {
				return "", fmt.Errorf("storage: generate ID: %w", err)
			}
			index = 0
		}
		value := buffer[index]
		index++
		if value < maxValid {
			result = append(result, defaultIDAlphabet[value%alphabetLength])
		}
	}
	return string(result), nil
}

func generateIDUUID(random io.Reader) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(random, value[:]); err != nil {
		return "", fmt.Errorf("storage: generate UUID: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	), nil
}

func isJavaScriptFalsy(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	if (reflected.Kind() == reflect.Chan || reflected.Kind() == reflect.Func ||
		reflected.Kind() == reflect.Interface || reflected.Kind() == reflect.Map ||
		reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Slice) && reflected.IsNil() {
		return true
	}
	switch typed := value.(type) {
	case bool:
		return !typed
	case string:
		return typed == ""
	case float32:
		return typed == 0 || math.IsNaN(float64(typed))
	case float64:
		return typed == 0 || math.IsNaN(typed)
	case int:
		return typed == 0
	case int8:
		return typed == 0
	case int16:
		return typed == 0
	case int32:
		return typed == 0
	case int64:
		return typed == 0
	case uint:
		return typed == 0
	case uint8:
		return typed == 0
	case uint16:
		return typed == 0
	case uint32:
		return typed == 0
	case uint64:
		return typed == 0
	case uintptr:
		return typed == 0
	case json.Number:
		if number, err := strconv.ParseFloat(string(typed), 64); err == nil {
			return number == 0 || math.IsNaN(number)
		}
	}
	return false
}

func javascriptNumber(value any) (float64, bool) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, true
		}
		if trimmed == "Infinity" || trimmed == "+Infinity" {
			return math.Inf(1), true
		}
		if trimmed == "-Infinity" {
			return math.Inf(-1), true
		}
		value, err := strconv.ParseFloat(trimmed, 64)
		return value, err == nil
	case bool:
		if typed {
			return 1, true
		}
		return 0, true
	case json.Number:
		number, err := strconv.ParseFloat(string(typed), 64)
		return number, err == nil
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(reflected.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return float64(reflected.Uint()), true
	case reflect.Float32, reflect.Float64:
		return reflected.Convert(reflect.TypeOf(float64(0))).Float(), true
	default:
		return 0, false
	}
}

func javascriptString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float32:
		return strconv.FormatFloat(float64(typed), 'g', -1, 32)
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64)
	case json.Number:
		return string(typed)
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(reflected.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(reflected.Uint(), 10)
	default:
		return fmt.Sprint(value)
	}
}
