package ratelimit

import (
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// Schema returns the canonical reference implementation database-backed rate-limit model.
// A unique key constraint is the atomic create-race guard; count is numeric,
// and lastRequest is stored as a bigint Unix-millisecond value.
func Schema() storage.Schema {
	return SchemaWithModelName("rateLimit")
}

// SchemaWithModelName returns the canonical rateLimit schema using modelName
// as its physical table/model name. An empty name selects "rateLimit".
func SchemaWithModelName(modelName string) storage.Schema {
	if modelName == "" {
		modelName = "rateLimit"
	}
	lastRequestDefault := func(valueContext storage.ValueContext) (any, error) {
		now := time.Now()
		if valueContext.Now != nil {
			now = valueContext.Now()
		}
		return now.UnixMilli(), nil
	}
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"rateLimit": {
			ModelName: modelName,
			Fields: map[string]storage.FieldAttribute{
				"key": {
					Type:   storage.FieldString,
					Unique: true,
				},
				"count": {
					Type: storage.FieldNumber,
				},
				"lastRequest": {
					Type:         storage.FieldNumber,
					BigInt:       true,
					DefaultValue: lastRequestDefault,
				},
			},
		},
	}}
}
