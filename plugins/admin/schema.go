package admin

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/storage"
)

// Schema returns the administration schema merged with custom overrides.
func Schema(custom storage.Schema) (storage.Schema, error) {
	optional := storage.Bool(false)
	notInput := storage.Bool(false)
	base := storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"role":       {Type: storage.FieldString, Required: optional, Input: notInput},
			"banned":     {Type: storage.FieldBoolean, Required: optional, Input: notInput, DefaultValue: storage.StaticValue(false)},
			"banReason":  {Type: storage.FieldString, Required: optional, Input: notInput},
			"banExpires": {Type: storage.FieldDate, Required: optional, Input: notInput},
		}},
		"session": {Fields: map[string]storage.FieldAttribute{
			"impersonatedBy": {Type: storage.FieldString, Required: optional, Input: notInput},
		}},
	}}
	merged, err := base.Merge(custom)
	if err != nil {
		return storage.Schema{}, fmt.Errorf("admin: schema: %w", err)
	}
	if _, err := storage.CoreSchema().Merge(merged); err != nil {
		return storage.Schema{}, fmt.Errorf("admin: schema: %w", err)
	}
	return merged, nil
}
