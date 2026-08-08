package passkey

import "github.com/pers0na2dev/single-auth/storage"

// Schema returns an independent copy of the upstream passkey model schema.
func Schema() storage.Schema {
	optional := storage.Bool(false)
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"passkey": {
			ModelName: "passkey",
			Fields: map[string]storage.FieldAttribute{
				"name":      {Type: storage.FieldString, Required: optional},
				"publicKey": {Type: storage.FieldString},
				"userId": {
					Type:       storage.FieldString,
					Index:      true,
					References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
				},
				"credentialID": {Type: storage.FieldString, Index: true},
				"counter":      {Type: storage.FieldNumber},
				"deviceType":   {Type: storage.FieldString},
				"backedUp":     {Type: storage.FieldBoolean},
				"transports":   {Type: storage.FieldString, Required: optional},
				"createdAt":    {Type: storage.FieldDate, Required: optional},
				"aaguid":       {Type: storage.FieldString, Required: optional},
			},
		},
	}}
}

func resolveSchema(extension storage.Schema) (storage.Schema, error) {
	base := Schema()
	if len(extension.Models) == 0 && !extension.UsePlural {
		return base, nil
	}
	return base.Merge(extension)
}
