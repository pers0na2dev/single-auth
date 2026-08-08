package phonenumber

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/storage"
)

func schemaFor(options Options) (storage.Schema, error) {
	optional := storage.Bool(false)
	returned := storage.Bool(true)
	notInput := storage.Bool(false)
	extension := storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {
			ModelName: options.Schema.User.ModelName,
			Fields: map[string]storage.FieldAttribute{
				"phoneNumber": {
					Type: storage.FieldString, Required: optional, Returned: returned,
					Unique: true, Sortable: true, FieldName: options.Schema.User.PhoneNumber,
				},
				"phoneNumberVerified": {
					Type: storage.FieldBoolean, Required: optional, Returned: returned,
					Input: notInput, FieldName: options.Schema.User.PhoneNumberVerified,
				},
			},
		},
	}}
	if _, err := storage.CoreSchema().Merge(extension); err != nil {
		return storage.Schema{}, fmt.Errorf("phonenumber: schema: %w", err)
	}
	return extension, nil
}

// Schema returns an independent storage extension for options.
func Schema(options Options) (storage.Schema, error) {
	result, err := schemaFor(options)
	if err != nil {
		return storage.Schema{}, err
	}
	return result.Clone(), nil
}
