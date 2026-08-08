package siwe

import "github.com/pers0na2dev/single-auth/storage"

// Schema returns an independent copy of the frozen walletAddress schema.
func Schema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"walletAddress": {
			ModelName: "walletAddress",
			Fields: map[string]storage.FieldAttribute{
				"userId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "user", Field: "id"},
				},
				"address":   {Type: storage.FieldString},
				"chainId":   {Type: storage.FieldNumber},
				"isPrimary": {Type: storage.FieldBoolean, DefaultValue: storage.StaticValue(false)},
				"createdAt": {Type: storage.FieldDate},
			},
		},
	}}
}

func resolveSchema(extension storage.Schema) (storage.Schema, error) {
	base := Schema()
	if len(extension.Models) == 0 && !extension.UsePlural {
		return base, nil
	}
	// Plugin schemas may reference core models that are merged by the root only
	// after PluginFactory.Schema returns. Compose here without prematurely
	// rejecting the valid walletAddress.userId -> user reference.
	merged := base.Clone()
	extra := extension.Clone()
	for name, model := range extra.Models {
		current, exists := merged.Models[name]
		if !exists {
			current = storage.ModelSchema{ModelName: name, Fields: map[string]storage.FieldAttribute{}}
		}
		if model.ModelName != "" {
			current.ModelName = model.ModelName
		}
		if model.DisableMigrations {
			current.DisableMigrations = true
		}
		if model.Order != 0 {
			current.Order = model.Order
		}
		if current.Fields == nil {
			current.Fields = map[string]storage.FieldAttribute{}
		}
		for field, attribute := range model.Fields {
			current.Fields[field] = attribute
		}
		merged.Models[name] = current
	}
	merged.UsePlural = base.UsePlural || extra.UsePlural
	return merged, nil
}
