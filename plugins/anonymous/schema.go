package anonymous

import "github.com/pers0na2dev/single-auth/storage"

// Schema returns an independent copy of the anonymous user-field schema.
func Schema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {
			Fields: map[string]storage.FieldAttribute{
				"isAnonymous": {
					Type:         storage.FieldBoolean,
					Required:     storage.Bool(false),
					Input:        storage.Bool(false),
					DefaultValue: storage.StaticValue(false),
				},
			},
		},
	}}
}

func resolveSchema(extension storage.Schema) (storage.Schema, error) {
	base := Schema()
	if len(extension.Models) == 0 && !extension.UsePlural {
		return base, nil
	}
	extension = extension.Clone()
	// InferOptionSchema lets upstream callers provide only the physical field
	// name (for example isAnonymous: "is_anon"). Preserve the frozen field
	// contract when the Go storage override likewise supplies only metadata.
	if user, exists := extension.Models["user"]; exists {
		if field, exists := user.Fields["isAnonymous"]; exists {
			frozen := base.Models["user"].Fields["isAnonymous"]
			if field.Type == "" {
				field.Type = frozen.Type
			}
			if field.Required == nil {
				field.Required = frozen.Required
			}
			if field.Input == nil {
				field.Input = frozen.Input
			}
			if field.DefaultValue == nil {
				field.DefaultValue = frozen.DefaultValue
			}
			if user.Fields == nil {
				user.Fields = map[string]storage.FieldAttribute{}
			}
			user.Fields["isAnonymous"] = field
			extension.Models["user"] = user
		}
	}
	return base.Merge(extension)
}
