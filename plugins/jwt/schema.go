package jwt

import "github.com/pers0na2dev/single-auth/storage"

// Schema returns an independent copy of single-auth 1.6.26's jwks model.
func Schema() storage.Schema {
	optional := storage.Bool(false)
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"jwks": {
			ModelName: "jwks",
			Fields: map[string]storage.FieldAttribute{
				"publicKey":  {Type: storage.FieldString},
				"privateKey": {Type: storage.FieldString},
				"createdAt":  {Type: storage.FieldDate},
				"expiresAt":  {Type: storage.FieldDate, Required: optional},
			},
		},
	}}
}

func resolveSchema(extension storage.Schema) (storage.Schema, error) {
	if len(extension.Models) == 0 && !extension.UsePlural {
		return Schema(), nil
	}
	return Schema().Merge(extension)
}
