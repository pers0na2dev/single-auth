package mcp

import "github.com/pers0na2dev/single-auth/storage"

// Schema returns a fresh copy of the three models inherited by MCP from the
// frozen single-auth OIDC provider.
func Schema() storage.Schema {
	optional := storage.Bool(false)
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"oauthApplication": {
			ModelName: "oauthApplication",
			Fields: map[string]storage.FieldAttribute{
				"name":         {Type: storage.FieldString},
				"icon":         {Type: storage.FieldString, Required: optional},
				"metadata":     {Type: storage.FieldString, Required: optional},
				"clientId":     {Type: storage.FieldString, Unique: true},
				"clientSecret": {Type: storage.FieldString, Required: optional},
				"redirectUrls": {Type: storage.FieldString},
				"type":         {Type: storage.FieldString},
				"disabled": {
					Type: storage.FieldBoolean, Required: optional,
					DefaultValue: storage.StaticValue(false),
				},
				"userId": {
					Type: storage.FieldString, Required: optional, Index: true,
					References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
				},
				"createdAt": {Type: storage.FieldDate},
				"updatedAt": {Type: storage.FieldDate},
			},
		},
		"oauthAccessToken": {
			ModelName: "oauthAccessToken",
			Fields: map[string]storage.FieldAttribute{
				"accessToken":           {Type: storage.FieldString, Unique: true},
				"refreshToken":          {Type: storage.FieldString, Unique: true},
				"accessTokenExpiresAt":  {Type: storage.FieldDate},
				"refreshTokenExpiresAt": {Type: storage.FieldDate},
				"clientId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "oauthApplication", Field: "clientId", OnDelete: storage.Cascade},
				},
				"userId": {
					Type: storage.FieldString, Required: optional, Index: true,
					References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
				},
				"scopes":    {Type: storage.FieldString},
				"createdAt": {Type: storage.FieldDate},
				"updatedAt": {Type: storage.FieldDate},
			},
		},
		"oauthConsent": {
			ModelName: "oauthConsent",
			Fields: map[string]storage.FieldAttribute{
				"clientId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "oauthApplication", Field: "clientId", OnDelete: storage.Cascade},
				},
				"userId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
				},
				"scopes":       {Type: storage.FieldString},
				"createdAt":    {Type: storage.FieldDate},
				"updatedAt":    {Type: storage.FieldDate},
				"consentGiven": {Type: storage.FieldBoolean},
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
