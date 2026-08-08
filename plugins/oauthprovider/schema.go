package oauthprovider

import "github.com/pers0na2dev/single-auth/storage"

// OAuthProviderSchema returns the single-auth OAuth provider persistence
// models. A fresh schema is returned on every call so plugin composition may
// safely customize it.
func OAuthProviderSchema() storage.Schema {
	optional := storage.Bool(false)
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"oauthClient": {
			ModelName: "oauthClient",
			Fields: map[string]storage.FieldAttribute{
				"clientId":                {Type: storage.FieldString, Unique: true},
				"clientSecret":            {Type: storage.FieldString, Required: optional},
				"disabled":                {Type: storage.FieldBoolean, Required: optional, DefaultValue: storage.StaticValue(false)},
				"skipConsent":             {Type: storage.FieldBoolean, Required: optional},
				"enableEndSession":        {Type: storage.FieldBoolean, Required: optional},
				"subjectType":             {Type: storage.FieldString, Required: optional},
				"scopes":                  {Type: storage.FieldStringArray, Required: optional},
				"userId":                  indexedOAuthReference(storage.FieldString, false, "user", "id", ""),
				"createdAt":               {Type: storage.FieldDate, Required: optional},
				"updatedAt":               {Type: storage.FieldDate, Required: optional},
				"name":                    {Type: storage.FieldString, Required: optional},
				"uri":                     {Type: storage.FieldString, Required: optional},
				"icon":                    {Type: storage.FieldString, Required: optional},
				"contacts":                {Type: storage.FieldStringArray, Required: optional},
				"tos":                     {Type: storage.FieldString, Required: optional},
				"policy":                  {Type: storage.FieldString, Required: optional},
				"softwareId":              {Type: storage.FieldString, Required: optional},
				"softwareVersion":         {Type: storage.FieldString, Required: optional},
				"softwareStatement":       {Type: storage.FieldString, Required: optional},
				"redirectUris":            {Type: storage.FieldStringArray},
				"postLogoutRedirectUris":  {Type: storage.FieldStringArray, Required: optional},
				"tokenEndpointAuthMethod": {Type: storage.FieldString, Required: optional},
				"grantTypes":              {Type: storage.FieldStringArray, Required: optional},
				"responseTypes":           {Type: storage.FieldStringArray, Required: optional},
				"public":                  {Type: storage.FieldBoolean, Required: optional},
				"type":                    {Type: storage.FieldString, Required: optional},
				"requirePKCE":             {Type: storage.FieldBoolean, Required: optional},
				"referenceId":             {Type: storage.FieldString, Required: optional},
				"metadata":                {Type: storage.FieldJSON, Required: optional},
			},
		},
		"oauthRefreshToken": {
			ModelName: "oauthRefreshToken",
			Fields: map[string]storage.FieldAttribute{
				"token":       {Type: storage.FieldString, Unique: true},
				"clientId":    indexedOAuthReference(storage.FieldString, true, "oauthClient", "clientId", ""),
				"sessionId":   indexedOAuthReference(storage.FieldString, false, "session", "id", storage.SetNull),
				"userId":      indexedOAuthReference(storage.FieldString, true, "user", "id", ""),
				"referenceId": {Type: storage.FieldString, Required: optional},
				"expiresAt":   {Type: storage.FieldDate},
				"createdAt":   {Type: storage.FieldDate},
				"revoked":     {Type: storage.FieldDate, Required: optional},
				"authTime":    {Type: storage.FieldDate, Required: optional},
				"scopes":      {Type: storage.FieldStringArray},
			},
		},
		"oauthAccessToken": {
			ModelName: "oauthAccessToken",
			Fields: map[string]storage.FieldAttribute{
				"token":       {Type: storage.FieldString, Unique: true},
				"clientId":    indexedOAuthReference(storage.FieldString, true, "oauthClient", "clientId", ""),
				"sessionId":   indexedOAuthReference(storage.FieldString, false, "session", "id", storage.SetNull),
				"userId":      indexedOAuthReference(storage.FieldString, false, "user", "id", ""),
				"referenceId": {Type: storage.FieldString, Required: optional},
				"refreshId":   indexedOAuthReference(storage.FieldString, false, "oauthRefreshToken", "id", ""),
				"expiresAt":   {Type: storage.FieldDate},
				"createdAt":   {Type: storage.FieldDate},
				"scopes":      {Type: storage.FieldStringArray},
			},
		},
		"oauthConsent": {
			ModelName: "oauthConsent",
			Fields: map[string]storage.FieldAttribute{
				"clientId":    indexedOAuthReference(storage.FieldString, true, "oauthClient", "clientId", ""),
				"userId":      indexedOAuthReference(storage.FieldString, false, "user", "id", ""),
				"referenceId": {Type: storage.FieldString, Required: optional},
				"scopes":      {Type: storage.FieldStringArray},
				"createdAt":   {Type: storage.FieldDate},
				"updatedAt":   {Type: storage.FieldDate},
			},
		},
	}}
}

func indexedOAuthReference(fieldType storage.FieldType, required bool, model, field string, onDelete storage.DeleteAction) storage.FieldAttribute {
	attribute := storage.FieldAttribute{
		Type:       fieldType,
		Index:      true,
		References: &storage.Reference{Model: model, Field: field, OnDelete: onDelete},
	}
	if !required {
		attribute.Required = storage.Bool(false)
	}
	return attribute
}
