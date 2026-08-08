package apikey

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// Schema returns the canonical single-auth API-key storage extension.
func Schema(options Options) (storage.Schema, error) {
	optional := storage.Bool(false)
	notInput := storage.Bool(false)
	jsonTransform := storage.FieldTransform{
		Input: func(value any) (any, error) {
			if value == nil {
				return nil, nil
			}
			if text, ok := value.(string); ok {
				return text, nil
			}
			encoded, err := json.Marshal(value)
			return string(encoded), err
		},
		Output: func(value any) (any, error) {
			text, ok := value.(string)
			if !ok || text == "" {
				return value, nil
			}
			var decoded any
			if err := json.Unmarshal([]byte(text), &decoded); err != nil {
				return nil, err
			}
			return decoded, nil
		},
	}
	now := func(ctx storage.ValueContext) (any, error) {
		if ctx.Now != nil {
			return ctx.Now(), nil
		}
		return time.Now(), nil
	}
	extension := storage.Schema{Models: map[string]storage.ModelSchema{
		"apikey": {
			ModelName: "apikey",
			Fields: map[string]storage.FieldAttribute{
				"configId":            {Type: storage.FieldString, DefaultValue: storage.StaticValue("default"), Input: notInput, Index: true},
				"name":                {Type: storage.FieldString, Required: optional, Input: notInput},
				"start":               {Type: storage.FieldString, Required: optional, Input: notInput},
				"referenceId":         {Type: storage.FieldString, Input: notInput, Index: true},
				"prefix":              {Type: storage.FieldString, Required: optional, Input: notInput},
				"key":                 {Type: storage.FieldString, Input: notInput, Index: true, Unique: true},
				"refillInterval":      {Type: storage.FieldNumber, Required: optional, Input: notInput},
				"refillAmount":        {Type: storage.FieldNumber, Required: optional, Input: notInput},
				"lastRefillAt":        {Type: storage.FieldDate, Required: optional, Input: notInput},
				"enabled":             {Type: storage.FieldBoolean, Required: optional, Input: notInput, DefaultValue: storage.StaticValue(true)},
				"rateLimitEnabled":    {Type: storage.FieldBoolean, Required: optional, Input: notInput, DefaultValue: storage.StaticValue(true)},
				"rateLimitTimeWindow": {Type: storage.FieldNumber, Required: optional, Input: notInput, DefaultValue: storage.StaticValue(int64((24 * time.Hour) / time.Millisecond))},
				"rateLimitMax":        {Type: storage.FieldNumber, Required: optional, Input: notInput, DefaultValue: storage.StaticValue(int64(10))},
				"requestCount":        {Type: storage.FieldNumber, Required: optional, Input: notInput, DefaultValue: storage.StaticValue(int64(0))},
				"remaining":           {Type: storage.FieldNumber, Required: optional, Input: notInput},
				"lastRequest":         {Type: storage.FieldDate, Required: optional, Input: notInput},
				"expiresAt":           {Type: storage.FieldDate, Required: optional, Input: notInput},
				"createdAt":           {Type: storage.FieldDate, DefaultValue: now, Input: notInput},
				"updatedAt":           {Type: storage.FieldDate, DefaultValue: now, OnUpdate: now, Input: notInput},
				"permissions":         {Type: storage.FieldString, Required: optional, Input: notInput, Transform: jsonTransform},
				"metadata":            {Type: storage.FieldString, Required: optional, Transform: jsonTransform},
			},
		},
	}}
	if len(options.Schema.Models) != 0 || options.Schema.UsePlural {
		extension = mergeSchema(extension, options.Schema)
	}
	if _, err := storage.CoreSchema().Merge(extension); err != nil {
		return storage.Schema{}, fmt.Errorf("apikey: schema: %w", err)
	}
	return extension.Clone(), nil
}

func mergeSchema(base, additional storage.Schema) storage.Schema {
	merged := base.Clone()
	additional = additional.Clone()
	for name, extra := range additional.Models {
		current, exists := merged.Models[name]
		if !exists {
			current = storage.ModelSchema{ModelName: name, Fields: map[string]storage.FieldAttribute{}}
		}
		if extra.ModelName != "" {
			current.ModelName = extra.ModelName
		}
		if current.Fields == nil {
			current.Fields = make(map[string]storage.FieldAttribute)
		}
		for field, attribute := range extra.Fields {
			current.Fields[field] = attribute
		}
		merged.Models[name] = current
	}
	merged.UsePlural = base.UsePlural || additional.UsePlural
	return merged
}
