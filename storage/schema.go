package storage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type FieldType string

const (
	FieldString      FieldType = "string"
	FieldNumber      FieldType = "number"
	FieldBoolean     FieldType = "boolean"
	FieldDate        FieldType = "date"
	FieldJSON        FieldType = "json"
	FieldStringArray FieldType = "string[]"
	FieldNumberArray FieldType = "number[]"
	FieldEnum        FieldType = "enum"
)

type DeleteAction string

const (
	NoAction   DeleteAction = "no action"
	Restrict   DeleteAction = "restrict"
	Cascade    DeleteAction = "cascade"
	SetNull    DeleteAction = "set null"
	SetDefault DeleteAction = "set default"
)

type Reference struct {
	Model        string
	Field        string
	OnDelete     DeleteAction
	RelationName string
}

// ValueContext makes defaults and on-update values deterministic in tests.
type ValueContext struct {
	Now func() time.Time
}

type ValueFactory func(ValueContext) (any, error)
type Transform func(any) (any, error)

type FieldTransform struct {
	Input  Transform
	Output Transform
}

// FieldAttribute is the Go equivalent of reference implementation's DBFieldAttribute.
// Pointer booleans preserve the distinction between omitted (upstream default)
// and explicitly false.
type FieldAttribute struct {
	Type         FieldType
	Enum         []string
	Required     *bool
	Returned     *bool
	Input        *bool
	DefaultValue ValueFactory
	OnUpdate     ValueFactory
	Transform    FieldTransform
	References   *Reference
	Unique       bool
	BigInt       bool
	FieldName    string
	Sortable     bool
	Index        bool
}

func (f FieldAttribute) IsRequired() bool { return f.Required == nil || *f.Required }
func (f FieldAttribute) IsReturned() bool { return f.Returned == nil || *f.Returned }
func (f FieldAttribute) IsInput() bool    { return f.Input == nil || *f.Input }

type ModelSchema struct {
	ModelName         string
	Fields            map[string]FieldAttribute
	DisableMigrations bool
	Order             int
}

// Schema maps canonical model names to their fields and optional physical
// names. Canonical names win over aliases when the two collide, matching the
// reference implementation resolver.
type Schema struct {
	Models    map[string]ModelSchema
	UsePlural bool
}

// Bool returns a bool pointer for explicit DB field flags.
func Bool(value bool) *bool { return &value }

// StaticValue adapts a constant into a schema default/on-update factory.
func StaticValue(value any) ValueFactory {
	return func(ValueContext) (any, error) { return value, nil }
}

// CoreSchema returns the five base reference implementation tables. Session, verification,
// and rateLimit can be omitted by higher-level configuration when secondary
// storage is selected.
func CoreSchema() Schema {
	now := func(ctx ValueContext) (any, error) {
		if ctx.Now != nil {
			return ctx.Now(), nil
		}
		return time.Now(), nil
	}
	optional := Bool(false)
	notReturned := Bool(false)
	notInput := Bool(false)

	coreDates := func() map[string]FieldAttribute {
		return map[string]FieldAttribute{
			"createdAt": {Type: FieldDate, DefaultValue: now},
			"updatedAt": {Type: FieldDate, DefaultValue: now, OnUpdate: now},
		}
	}
	withCoreDates := func(fields map[string]FieldAttribute) map[string]FieldAttribute {
		for name, field := range coreDates() {
			fields[name] = field
		}
		return fields
	}

	return Schema{Models: map[string]ModelSchema{
		"user": {
			ModelName: "user",
			Order:     1,
			Fields: withCoreDates(map[string]FieldAttribute{
				"name":          {Type: FieldString, Sortable: true},
				"email":         {Type: FieldString, Unique: true, Sortable: true},
				"emailVerified": {Type: FieldBoolean, DefaultValue: StaticValue(false), Input: notInput},
				"image":         {Type: FieldString, Required: optional},
			}),
		},
		"session": {
			ModelName: "session",
			Order:     2,
			Fields: withCoreDates(map[string]FieldAttribute{
				"expiresAt": {Type: FieldDate},
				"token":     {Type: FieldString, Unique: true},
				"ipAddress": {Type: FieldString, Required: optional},
				"userAgent": {Type: FieldString, Required: optional},
				"userId": {
					Type:       FieldString,
					Index:      true,
					References: &Reference{Model: "user", Field: "id", OnDelete: Cascade},
				},
			}),
		},
		"account": {
			ModelName: "account",
			Order:     3,
			Fields: withCoreDates(map[string]FieldAttribute{
				"accountId":  {Type: FieldString},
				"providerId": {Type: FieldString},
				"userId": {
					Type:       FieldString,
					Index:      true,
					References: &Reference{Model: "user", Field: "id", OnDelete: Cascade},
				},
				"accessToken":           {Type: FieldString, Required: optional, Returned: notReturned},
				"refreshToken":          {Type: FieldString, Required: optional, Returned: notReturned},
				"idToken":               {Type: FieldString, Required: optional, Returned: notReturned},
				"accessTokenExpiresAt":  {Type: FieldDate, Required: optional, Returned: notReturned},
				"refreshTokenExpiresAt": {Type: FieldDate, Required: optional, Returned: notReturned},
				"scope":                 {Type: FieldString, Required: optional},
				"password":              {Type: FieldString, Required: optional, Returned: notReturned},
			}),
		},
		"verification": {
			ModelName: "verification",
			Order:     4,
			Fields: withCoreDates(map[string]FieldAttribute{
				"identifier": {Type: FieldString, Index: true},
				"value":      {Type: FieldString},
				"expiresAt":  {Type: FieldDate},
			}),
		},
		"rateLimit": {
			ModelName: "rateLimit",
			Fields: map[string]FieldAttribute{
				"key":         {Type: FieldString, Unique: true},
				"count":       {Type: FieldNumber},
				"lastRequest": {Type: FieldNumber, BigInt: true},
			},
		},
	}}
}

// Clone returns a deep copy safe for independent plugin composition.
func (s Schema) Clone() Schema {
	clone := Schema{Models: make(map[string]ModelSchema, len(s.Models)), UsePlural: s.UsePlural}
	for name, table := range s.Models {
		fields := make(map[string]FieldAttribute, len(table.Fields))
		for fieldName, field := range table.Fields {
			field.Enum = append([]string(nil), field.Enum...)
			if field.References != nil {
				reference := *field.References
				field.References = &reference
			}
			fields[fieldName] = field
		}
		table.Fields = fields
		clone.Models[name] = table
	}
	return clone
}

// Merge composes plugin/additional schemas. Later fields replace earlier
// fields with the same canonical name, as reference implementation does.
func (s Schema) Merge(extension Schema) (Schema, error) {
	merged := s.Clone()
	extension = extension.Clone()
	for name, extra := range extension.Models {
		current, exists := merged.Models[name]
		if !exists {
			current = ModelSchema{ModelName: name, Fields: map[string]FieldAttribute{}}
		}
		if extra.ModelName != "" {
			current.ModelName = extra.ModelName
		}
		if extra.DisableMigrations {
			current.DisableMigrations = true
		}
		if extra.Order != 0 {
			current.Order = extra.Order
		}
		if current.Fields == nil {
			current.Fields = map[string]FieldAttribute{}
		}
		for field, attribute := range extra.Fields {
			current.Fields[field] = attribute
		}
		merged.Models[name] = current
	}
	merged.UsePlural = s.UsePlural || extension.UsePlural
	if err := merged.Validate(); err != nil {
		return Schema{}, err
	}
	return merged, nil
}

// Validate checks names, field kinds, aliases, and references.
func (s Schema) Validate() error {
	physicalModels := map[string]string{}
	for name, table := range s.Models {
		if name == "" {
			return fmt.Errorf("%w: schema contains an empty model name", ErrInvalidQuery)
		}
		physical := table.ModelName
		if physical == "" {
			physical = name
		}
		if s.UsePlural {
			physical += "s"
		}
		if prior, exists := physicalModels[physical]; exists && prior != name {
			return fmt.Errorf("%w: models %q and %q resolve to %q", ErrInvalidQuery, prior, name, physical)
		}
		physicalModels[physical] = name

		physicalFields := map[string]string{"id": "id"}
		for fieldName, field := range table.Fields {
			if fieldName == "" {
				return fmt.Errorf("%w: model %q contains an empty field name", ErrInvalidQuery, name)
			}
			if !validFieldType(field) {
				return fmt.Errorf("%w: model %q field %q has invalid type %q", ErrInvalidQuery, name, fieldName, field.Type)
			}
			physicalField := field.FieldName
			if physicalField == "" {
				physicalField = fieldName
			}
			if prior, exists := physicalFields[physicalField]; exists && prior != fieldName {
				return fmt.Errorf("%w: model %q fields %q and %q resolve to %q", ErrInvalidQuery, name, prior, fieldName, physicalField)
			}
			physicalFields[physicalField] = fieldName
		}
	}
	for modelName, table := range s.Models {
		for fieldName, field := range table.Fields {
			if field.References == nil {
				continue
			}
			target, _, err := s.ResolveModel(field.References.Model)
			if err != nil {
				return fmt.Errorf("model %q field %q reference: %w", modelName, fieldName, err)
			}
			if field.References.Field != "id" {
				if _, exists := target.Fields[field.References.Field]; !exists {
					return fmt.Errorf("%w: reference target %q.%q", ErrFieldNotFound, field.References.Model, field.References.Field)
				}
			}
		}
	}
	return nil
}

// ResolveModel accepts a canonical name, configured physical name, or plural
// physical name. Exact canonical matches take precedence over aliases.
func (s Schema) ResolveModel(candidate string) (ModelSchema, string, error) {
	if table, ok := s.Models[candidate]; ok {
		return normalizeModel(candidate, table), candidate, nil
	}

	lookup := candidate
	if s.UsePlural && strings.HasSuffix(lookup, "s") {
		lookup = strings.TrimSuffix(lookup, "s")
	}
	for canonical, table := range s.Models {
		physical := table.ModelName
		if physical == "" {
			physical = canonical
		}
		if physical == lookup {
			return normalizeModel(canonical, table), canonical, nil
		}
	}
	return ModelSchema{}, "", fmt.Errorf("%w: %q", ErrModelNotFound, candidate)
}

// ResolveField accepts a canonical or configured physical field name. The id
// field exists implicitly on every adapter model.
func (s Schema) ResolveField(modelName, candidate string) (FieldAttribute, string, error) {
	table, canonicalModel, err := s.ResolveModel(modelName)
	if err != nil {
		return FieldAttribute{}, "", err
	}
	if candidate == "id" || candidate == "_id" {
		return FieldAttribute{Type: FieldString, FieldName: "id"}, "id", nil
	}
	if field, ok := table.Fields[candidate]; ok {
		return normalizeField(candidate, field), candidate, nil
	}
	for canonical, field := range table.Fields {
		if field.FieldName == candidate {
			return normalizeField(canonical, field), canonical, nil
		}
	}
	return FieldAttribute{}, "", fmt.Errorf("%w: %s.%s", ErrFieldNotFound, canonicalModel, candidate)
}

func normalizeModel(canonical string, table ModelSchema) ModelSchema {
	if table.ModelName == "" {
		table.ModelName = canonical
	}
	return table
}

func normalizeField(canonical string, field FieldAttribute) FieldAttribute {
	if field.FieldName == "" {
		field.FieldName = canonical
	}
	return field
}

func validFieldType(field FieldAttribute) bool {
	switch field.Type {
	case FieldString, FieldNumber, FieldBoolean, FieldDate, FieldJSON, FieldStringArray, FieldNumberArray:
		return len(field.Enum) == 0
	case FieldEnum:
		return len(field.Enum) > 0
	default:
		return false
	}
}

// EncodeValue converts a canonical value into a backend representation based
// on capabilities, matching reference implementation's adapter factory conversions.
func EncodeValue(capabilities Capabilities, field FieldAttribute, value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	if field.Transform.Input != nil {
		var err error
		value, err = field.Transform.Input(value)
		if err != nil {
			return nil, err
		}
	}
	// reference implementation's adapter factory accepts client-serialized date strings on
	// endpoints without a dedicated schema parser and converts valid values
	// back to Date before invoking an adapter.
	if field.Type == FieldDate {
		if encoded, ok := value.(string); ok {
			if parsed, err := time.Parse(time.RFC3339Nano, encoded); err == nil {
				value = parsed
			}
		}
	}

	switch field.Type {
	case FieldJSON:
		if !capabilities.JSON {
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("encode JSON field: %w", err)
			}
			return string(encoded), nil
		}
	case FieldStringArray, FieldNumberArray:
		if !capabilities.Arrays {
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("encode array field: %w", err)
			}
			return string(encoded), nil
		}
	case FieldDate:
		if !capabilities.Dates {
			if date, ok := value.(time.Time); ok {
				return date.Format(time.RFC3339Nano), nil
			}
		}
	case FieldBoolean:
		if !capabilities.Booleans {
			if boolean, ok := value.(bool); ok {
				if boolean {
					return int64(1), nil
				}
				return int64(0), nil
			}
		}
	}
	return value, nil
}

// DecodeValue reverses EncodeValue and then applies the configured output transform.
func DecodeValue(capabilities Capabilities, field FieldAttribute, value any) (any, error) {
	if value != nil {
		switch field.Type {
		case FieldJSON, FieldStringArray, FieldNumberArray:
			unsupported := (field.Type == FieldJSON && !capabilities.JSON) ||
				(field.Type != FieldJSON && !capabilities.Arrays)
			if encoded, ok := value.(string); unsupported && ok {
				var decoded any
				switch field.Type {
				case FieldStringArray:
					decoded = &[]string{}
				case FieldNumberArray:
					decoded = &[]float64{}
				default:
					decoded = new(any)
				}
				if err := json.Unmarshal([]byte(encoded), decoded); err != nil {
					return nil, fmt.Errorf("decode %s field: %w", field.Type, err)
				}
				switch typed := decoded.(type) {
				case *[]string:
					value = *typed
				case *[]float64:
					value = *typed
				case *any:
					value = *typed
				}
			}
		case FieldDate:
			if encoded, ok := value.(string); !capabilities.Dates && ok {
				parsed, err := time.Parse(time.RFC3339Nano, encoded)
				if err != nil {
					return nil, fmt.Errorf("decode date field: %w", err)
				}
				value = parsed
			}
		case FieldBoolean:
			if !capabilities.Booleans {
				switch encoded := value.(type) {
				case int:
					value = encoded == 1
				case int64:
					value = encoded == 1
				case float64:
					value = encoded == 1
				}
			}
		}
	}
	if field.Transform.Output != nil {
		return field.Transform.Output(value)
	}
	return value, nil
}
