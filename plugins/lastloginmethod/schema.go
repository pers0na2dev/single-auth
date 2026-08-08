package lastloginmethod

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/storage"
)

func schemaFor(options Options) (storage.Schema, error) {
	if !options.StoreInDatabase {
		return storage.Schema{}, nil
	}
	fieldName := options.Schema.User.LastLoginMethod
	if fieldName == "" {
		fieldName = "lastLoginMethod"
	}
	extension := storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {
			Fields: map[string]storage.FieldAttribute{
				"lastLoginMethod": {
					Type:      storage.FieldString,
					Input:     storage.Bool(false),
					Required:  storage.Bool(false),
					FieldName: fieldName,
				},
			},
		},
	}}
	if _, err := storage.CoreSchema().Merge(extension); err != nil {
		return storage.Schema{}, fmt.Errorf("lastloginmethod: schema: %w", err)
	}
	return extension, nil
}

// Schema returns an independent schema extension for options.
func Schema(options Options) (storage.Schema, error) {
	return schemaFor(snapshotOptions(options))
}
