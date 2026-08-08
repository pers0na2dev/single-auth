package openapi

import (
	"encoding/json"
	"sort"
)

type inputKind uint8

const (
	inputAny inputKind = iota
	inputString
	inputNumber
	inputBoolean
	inputObject
	inputRecord
	inputIntersection
	inputUnion
	inputArray
	inputLiteral
	inputEnum
	inputNull
	inputUndefined
	inputOptional
	inputNullable
	inputDefault
	inputPrefault
	inputNonOptional
)

// Input is a transport-neutral request/query schema. It models the Zod
// constructs used by single-auth's endpoint metadata without evaluating
// runtime defaults.
type Input struct {
	kind           inputKind
	description    string
	minLength      *int
	maxLength      *int
	properties     []Property
	inner          *Input
	left           *Input
	right          *Input
	options        []Input
	key            *Input
	value          *Input
	literal        any
	enum           []string
	exclusive      bool
	defaultValue   any
	defaultFactory func() any
}

type Property struct {
	Name   string
	Schema Input
}

func Prop(name string, schema Input) Property { return Property{Name: name, Schema: schema} }
func Any() Input                              { return Input{kind: inputAny} }
func String() Input                           { return Input{kind: inputString} }
func Number() Input                           { return Input{kind: inputNumber} }
func Boolean() Input                          { return Input{kind: inputBoolean} }
func Null() Input                             { return Input{kind: inputNull} }
func Undefined() Input                        { return Input{kind: inputUndefined} }
func Object(properties ...Property) Input {
	return Input{kind: inputObject, properties: append([]Property(nil), properties...)}
}
func Record(key, value Input) Input {
	return Input{kind: inputRecord, key: inputPtr(key), value: inputPtr(value)}
}
func Intersection(left, right Input) Input {
	return Input{kind: inputIntersection, left: inputPtr(left), right: inputPtr(right)}
}
func Union(options ...Input) Input {
	return Input{kind: inputUnion, options: append([]Input(nil), options...)}
}
func ExclusiveUnion(options ...Input) Input {
	return Input{kind: inputUnion, options: append([]Input(nil), options...), exclusive: true}
}
func Array(item Input) Input  { return Input{kind: inputArray, inner: inputPtr(item)} }
func Literal(value any) Input { return Input{kind: inputLiteral, literal: value} }
func Enum(values ...string) Input {
	return Input{kind: inputEnum, enum: append([]string(nil), values...)}
}

func inputPtr(value Input) *Input { clone := value; return &clone }

// InputRef returns an independent pointer suitable for Metadata.Query or
// Metadata.Body.
func InputRef(value Input) *Input { return inputPtr(value) }

// OpenAPISchema converts this input into its OpenAPI 3.1 representation.
func (input Input) OpenAPISchema() Schema { return toSchema(input) }

// AcceptsUndefined reports whether a request body using this input is
// optional under single-auth's wrapper semantics.
func (input Input) AcceptsUndefined() bool { return acceptsUndefined(input) }

func (input Input) Optional() Input {
	return Input{kind: inputOptional, inner: inputPtr(input)}
}
func (input Input) Nullable() Input {
	return Input{kind: inputNullable, inner: inputPtr(input)}
}
func (input Input) Default(value any) Input {
	return Input{kind: inputDefault, inner: inputPtr(input), defaultValue: value}
}
func (input Input) DefaultFactory(factory func() any) Input {
	return Input{kind: inputDefault, inner: inputPtr(input), defaultFactory: factory}
}
func (input Input) Prefault(value any) Input {
	return Input{kind: inputPrefault, inner: inputPtr(input), defaultValue: value}
}
func (input Input) NonOptional() Input {
	return Input{kind: inputNonOptional, inner: inputPtr(input)}
}
func (input Input) Describe(description string) Input {
	input.description = description
	return input
}
func (input Input) Min(length int) Input { input.minLength = &length; return input }
func (input Input) Max(length int) Input { input.maxLength = &length; return input }

func acceptsUndefined(input Input) bool {
	switch input.kind {
	case inputOptional, inputDefault, inputPrefault, inputUndefined:
		return true
	case inputNonOptional:
		return false
	case inputNullable:
		return input.inner != nil && acceptsUndefined(*input.inner)
	case inputUnion:
		for _, option := range input.options {
			if acceptsUndefined(option) {
				return true
			}
		}
		return false
	case inputIntersection:
		return input.left != nil && input.right != nil &&
			acceptsUndefined(*input.left) && acceptsUndefined(*input.right)
	default:
		return false
	}
}

func toSchema(input Input) Schema {
	var schema Schema
	switch input.kind {
	case inputOptional, inputDefault, inputPrefault, inputNonOptional:
		if input.inner != nil {
			schema = toSchema(*input.inner)
		}
	case inputNullable:
		if input.inner != nil {
			schema = addNull(toSchema(*input.inner))
		}
	case inputAny, inputUndefined:
		schema = Schema{}
	case inputString:
		schema = Schema{Type: "string", MinLength: input.minLength, MaxLength: input.maxLength}
	case inputNumber:
		schema = Schema{Type: "number"}
	case inputBoolean:
		schema = Schema{Type: "boolean"}
	case inputNull:
		schema = Schema{Type: "null"}
	case inputObject:
		properties := make(map[string]Schema, len(input.properties))
		required := make([]string, 0, len(input.properties))
		for _, property := range input.properties {
			properties[property.Name] = toSchema(property.Schema)
			if !acceptsUndefined(property.Schema) {
				required = append(required, property.Name)
			}
		}
		schema = Schema{Type: "object", Properties: properties, Required: required}
	case inputRecord:
		schema = Schema{Type: "object"}
		if input.key != nil {
			value := toSchema(*input.key)
			schema.PropertyNames = &value
		}
		if input.value != nil {
			schema.AdditionalProperties = toSchema(*input.value)
		}
	case inputIntersection:
		left, right := Schema{}, Schema{}
		if input.left != nil {
			left = toSchema(*input.left)
		}
		if input.right != nil {
			right = toSchema(*input.right)
		}
		if merged, ok := mergeObjectSchemas(left, right); ok {
			schema = merged
		} else {
			schema = Schema{AllOf: []Schema{left, right}}
		}
	case inputUnion:
		options := make([]Schema, 0, len(input.options))
		for _, option := range input.options {
			if option.kind != inputUndefined {
				options = append(options, toSchema(option))
			}
		}
		switch len(options) {
		case 0:
			schema = Schema{}
		case 1:
			schema = options[0]
		default:
			if input.exclusive {
				schema.OneOf = options
			} else {
				schema.AnyOf = options
			}
		}
	case inputArray:
		schema = Schema{Type: "array"}
		if input.inner != nil {
			item := toSchema(*input.inner)
			schema.Items = &item
		}
	case inputLiteral:
		schema = Schema{Enum: []any{input.literal}}
	case inputEnum:
		schema = Schema{Type: "string", Enum: make([]any, len(input.enum))}
		for index, value := range input.enum {
			schema.Enum[index] = value
		}
	}
	if input.description != "" {
		schema.Description = input.description
	}
	return schema
}

func addNull(schema Schema) Schema {
	switch value := schema.Type.(type) {
	case string:
		if value == "null" {
			return schema
		}
		schema.Type = []string{value, "null"}
	case []string:
		for _, kind := range value {
			if kind == "null" {
				return schema
			}
		}
		schema.Type = append(append([]string(nil), value...), "null")
	case nil:
		schema = Schema{AnyOf: []Schema{schema, {Type: "null"}}}
	}
	return schema
}

func mergeObjectSchemas(left, right Schema) (Schema, bool) {
	if !mergeableObject(left) || !mergeableObject(right) {
		return Schema{}, false
	}
	properties := make(map[string]Schema, len(left.Properties)+len(right.Properties))
	for key, value := range left.Properties {
		properties[key] = value
	}
	for key, value := range right.Properties {
		if existing, exists := properties[key]; exists && !schemasEqual(existing, value) {
			return Schema{}, false
		}
		properties[key] = value
	}
	if !schemaMembersCompatible(left.AdditionalProperties, right.AdditionalProperties) ||
		!schemaPointersCompatible(left.PropertyNames, right.PropertyNames) {
		return Schema{}, false
	}
	required := append([]string(nil), left.Required...)
	seen := make(map[string]struct{}, len(required))
	for _, name := range required {
		seen[name] = struct{}{}
	}
	for _, name := range right.Required {
		if _, exists := seen[name]; !exists {
			required = append(required, name)
			seen[name] = struct{}{}
		}
	}
	kind := any("object")
	if allowsNull(left) && allowsNull(right) {
		kind = []string{"object", "null"}
	}
	result := Schema{Type: kind, Properties: properties, Required: required}
	if left.AdditionalProperties != nil {
		result.AdditionalProperties = left.AdditionalProperties
	} else {
		result.AdditionalProperties = right.AdditionalProperties
	}
	if left.PropertyNames != nil {
		value := *left.PropertyNames
		result.PropertyNames = &value
	} else if right.PropertyNames != nil {
		value := *right.PropertyNames
		result.PropertyNames = &value
	}
	return result, true
}

func mergeableObject(schema Schema) bool {
	if schema.Ref != "" || len(schema.AllOf) != 0 || len(schema.AnyOf) != 0 {
		return false
	}
	switch value := schema.Type.(type) {
	case string:
		return value == "object"
	case []string:
		for _, kind := range value {
			if kind == "object" {
				return true
			}
		}
	}
	return false
}

func allowsNull(schema Schema) bool {
	values, ok := schema.Type.([]string)
	if !ok {
		return false
	}
	for _, value := range values {
		if value == "null" {
			return true
		}
	}
	return false
}

func schemasEqual(left, right Schema) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

func schemaMembersCompatible(left, right any) bool {
	if left == nil || right == nil {
		return true
	}
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

func schemaPointersCompatible(left, right *Schema) bool {
	if left == nil || right == nil {
		return true
	}
	return schemasEqual(*left, *right)
}

func sortedPropertyNames(properties map[string]Schema) []string {
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
