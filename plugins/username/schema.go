package username

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/storage"
)

func schemaFor(options Options, usernameNormalizer, displayNormalizer Normalizer) (storage.Schema, error) {
	optional := storage.Bool(false)
	returned := storage.Bool(true)
	usernameField := options.Schema.User.Username
	displayField := options.Schema.User.DisplayUsername
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {ModelName: options.Schema.User.ModelName, Fields: map[string]storage.FieldAttribute{
			"username": {
				Type:      storage.FieldString,
				Required:  optional,
				Returned:  returned,
				Sortable:  true,
				Unique:    true,
				FieldName: usernameField,
				Transform: storage.FieldTransform{Input: func(value any) (any, error) {
					text, ok := value.(string)
					if !ok {
						return value, nil
					}
					return usernameNormalizer(text), nil
				}},
			},
			"displayUsername": {
				Type:      storage.FieldString,
				Required:  optional,
				FieldName: displayField,
				Transform: storage.FieldTransform{Input: func(value any) (any, error) {
					text, ok := value.(string)
					if !ok {
						return value, nil
					}
					return displayNormalizer(text), nil
				}},
			},
		}},
	}}
	if _, err := storage.CoreSchema().Merge(schema); err != nil {
		return storage.Schema{}, fmt.Errorf("username: schema: %w", err)
	}
	return schema, nil
}

// Schema returns an independent schema extension for options.
func Schema(options Options) (storage.Schema, error) {
	compiled, err := compileDefinition(options)
	if err != nil {
		return storage.Schema{}, err
	}
	return compiled.schema.Clone(), nil
}
