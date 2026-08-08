package deviceauthorization

import "github.com/pers0na2dev/single-auth/storage"

// Schema returns an independent copy of single-auth 1.6.26's deviceCode
// model. The model deliberately has no user relation in the frozen upstream.
func Schema() storage.Schema {
	optional := storage.Bool(false)
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"deviceCode": {
			ModelName: "deviceCode",
			Fields: map[string]storage.FieldAttribute{
				"deviceCode":      {Type: storage.FieldString},
				"userCode":        {Type: storage.FieldString},
				"userId":          {Type: storage.FieldString, Required: optional},
				"expiresAt":       {Type: storage.FieldDate},
				"status":          {Type: storage.FieldString},
				"lastPolledAt":    {Type: storage.FieldDate, Required: optional},
				"pollingInterval": {Type: storage.FieldNumber, Required: optional},
				"clientId":        {Type: storage.FieldString, Required: optional},
				"scope":           {Type: storage.FieldString, Required: optional},
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
