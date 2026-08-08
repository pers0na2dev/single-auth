package twofactor

import "github.com/pers0na2dev/single-auth/storage"

func Schema(options Options) (storage.Schema, error) {
	userField := options.Schema.User.TwoFactorEnabled
	userModelName := options.Schema.User.ModelName
	if userModelName == "" {
		userModelName = "user"
	}
	modelName := options.TwoFactorTable
	if modelName == "" {
		modelName = options.Schema.TwoFactor.ModelName
	}
	if modelName == "" {
		modelName = "twoFactor"
	}
	field := func(configured, fallback string) string {
		if configured != "" {
			return configured
		}
		return fallback
	}
	optional := storage.Bool(false)
	notInput := storage.Bool(false)
	notReturned := storage.Bool(false)
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {
			ModelName: userModelName,
			Fields: map[string]storage.FieldAttribute{
				"twoFactorEnabled": {
					Type: storage.FieldBoolean, Required: optional, Input: notInput,
					DefaultValue: storage.StaticValue(false), FieldName: userField,
				},
			},
		},
		"twoFactor": {
			ModelName: modelName,
			Fields: map[string]storage.FieldAttribute{
				"secret": {
					Type: storage.FieldString, Returned: notReturned, Index: true,
					FieldName: field(options.Schema.TwoFactor.Secret, ""),
				},
				"backupCodes": {
					Type: storage.FieldString, Returned: notReturned,
					FieldName: field(options.Schema.TwoFactor.BackupCodes, ""),
				},
				"userId": {
					Type: storage.FieldString, Returned: notReturned, Index: true,
					FieldName:  field(options.Schema.TwoFactor.UserID, ""),
					References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
				},
				"verified": {
					Type: storage.FieldBoolean, Required: optional, Input: notInput,
					DefaultValue: storage.StaticValue(true),
					FieldName:    field(options.Schema.TwoFactor.Verified, ""),
				},
				"failedVerificationCount": {
					Type: storage.FieldNumber, Required: optional, Input: notInput,
					Returned: notReturned, DefaultValue: storage.StaticValue(0),
					FieldName: field(options.Schema.TwoFactor.FailedVerificationCount, ""),
				},
				"lockedUntil": {
					Type: storage.FieldDate, Required: optional, Input: notInput,
					Returned:  notReturned,
					FieldName: field(options.Schema.TwoFactor.LockedUntil, ""),
				},
			},
		},
	}}, nil
}
