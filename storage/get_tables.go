package storage

import "time"

// AuthModelOptions configure one of reference implementation's four core models.
// Fields maps canonical field names to their physical database names, while
// AdditionalFields are merged last and may replace core or plugin metadata.
type AuthModelOptions struct {
	ModelName        string
	Fields           map[string]string
	AdditionalFields map[string]FieldAttribute
}

// AuthSessionTableOptions configure the session table and its persistence
// when a secondary store is present.
type AuthSessionTableOptions struct {
	AuthModelOptions
	StoreSessionInDatabase bool
}

// AuthVerificationTableOptions configure the verification table and its
// persistence when a secondary store is present.
type AuthVerificationTableOptions struct {
	AuthModelOptions
	StoreInDatabase bool
}

// AuthRateLimitTableOptions configure reference implementation's optional database-backed
// rate-limit table. Storage accepts the same values as reference implementation; only
// "database" materializes the built-in table.
type AuthRateLimitTableOptions struct {
	Storage   string
	ModelName string
	Fields    map[string]string
}

// AuthPluginTable is the schema shape exposed by a reference implementation plugin.
// DisableMigration is a pointer because an omitted value preserves the value
// contributed by an earlier plugin, while an explicit false clears it.
type AuthPluginTable struct {
	Fields           map[string]FieldAttribute
	ModelName        string
	DisableMigration *bool
}

// AuthTablesPlugin contributes tables in plugin order. Later plugins replace
// fields with the same canonical name and otherwise accumulate metadata.
type AuthTablesPlugin struct {
	ID     string
	Schema map[string]AuthPluginTable
}

// AuthTablesOptions are the storage-relevant subset of CompatibilityOptions.
// SecondaryStorage records presence rather than a concrete implementation;
// getAuthTables only branches on whether the option was configured.
type AuthTablesOptions struct {
	User             AuthModelOptions
	Session          AuthSessionTableOptions
	Account          AuthModelOptions
	Verification     AuthVerificationTableOptions
	RateLimit        AuthRateLimitTableOptions
	SecondaryStorage bool
	Plugins          []AuthTablesPlugin
}

// GetAuthTables returns reference implementation's effective database table metadata.
// It mirrors @single-auth/core's getAuthTables merge order and always returns
// an independent schema that callers may safely mutate.
func GetAuthTables(options AuthTablesOptions) Schema {
	pluginSchema := mergeAuthPluginTables(options.Plugins)
	userPlugin := takeAuthPluginTable(pluginSchema, "user")
	sessionPlugin := takeAuthPluginTable(pluginSchema, "session")
	accountPlugin := takeAuthPluginTable(pluginSchema, "account")
	verificationPlugin := takeAuthPluginTable(pluginSchema, "verification")

	now := func(ctx ValueContext) (any, error) {
		if ctx.Now != nil {
			return ctx.Now(), nil
		}
		return time.Now(), nil
	}
	unixMillis := func(ctx ValueContext) (any, error) {
		value := time.Now()
		if ctx.Now != nil {
			value = ctx.Now()
		}
		return value.UnixMilli(), nil
	}

	models := map[string]ModelSchema{
		"user": {
			ModelName: modelName(options.User.ModelName, "user"),
			Order:     1,
			Fields: mergeAuthFields(
				map[string]FieldAttribute{
					"name":          {Type: FieldString, Required: Bool(true), FieldName: authFieldName(options.User.Fields, "name"), Sortable: true},
					"email":         {Type: FieldString, Required: Bool(true), FieldName: authFieldName(options.User.Fields, "email"), Unique: true, Sortable: true},
					"emailVerified": {Type: FieldBoolean, Required: Bool(true), FieldName: authFieldName(options.User.Fields, "emailVerified"), DefaultValue: StaticValue(false), Input: Bool(false)},
					"image":         {Type: FieldString, Required: Bool(false), FieldName: authFieldName(options.User.Fields, "image")},
					"createdAt":     {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.User.Fields, "createdAt"), DefaultValue: now},
					"updatedAt":     {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.User.Fields, "updatedAt"), DefaultValue: now, OnUpdate: now},
				},
				userPlugin.Fields,
				options.User.AdditionalFields,
			),
		},
		"account": {
			ModelName: modelName(options.Account.ModelName, "account"),
			Order:     3,
			Fields: mergeAuthFields(
				map[string]FieldAttribute{
					"accountId":  {Type: FieldString, Required: Bool(true), FieldName: authFieldName(options.Account.Fields, "accountId")},
					"providerId": {Type: FieldString, Required: Bool(true), FieldName: authFieldName(options.Account.Fields, "providerId")},
					"userId": {
						Type: FieldString, Required: Bool(true), FieldName: authFieldName(options.Account.Fields, "userId"), Index: true,
						References: &Reference{Model: "user", Field: "id", OnDelete: Cascade},
					},
					"accessToken":           {Type: FieldString, Required: Bool(false), Returned: Bool(false), FieldName: authFieldName(options.Account.Fields, "accessToken")},
					"refreshToken":          {Type: FieldString, Required: Bool(false), Returned: Bool(false), FieldName: authFieldName(options.Account.Fields, "refreshToken")},
					"idToken":               {Type: FieldString, Required: Bool(false), Returned: Bool(false), FieldName: authFieldName(options.Account.Fields, "idToken")},
					"accessTokenExpiresAt":  {Type: FieldDate, Required: Bool(false), Returned: Bool(false), FieldName: authFieldName(options.Account.Fields, "accessTokenExpiresAt")},
					"refreshTokenExpiresAt": {Type: FieldDate, Required: Bool(false), Returned: Bool(false), FieldName: authFieldName(options.Account.Fields, "refreshTokenExpiresAt")},
					"scope":                 {Type: FieldString, Required: Bool(false), FieldName: authFieldName(options.Account.Fields, "scope")},
					"password":              {Type: FieldString, Required: Bool(false), Returned: Bool(false), FieldName: authFieldName(options.Account.Fields, "password")},
					"createdAt":             {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.Account.Fields, "createdAt"), DefaultValue: now},
					"updatedAt":             {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.Account.Fields, "updatedAt"), OnUpdate: now},
				},
				accountPlugin.Fields,
				options.Account.AdditionalFields,
			),
		},
	}

	if !options.SecondaryStorage || options.Session.StoreSessionInDatabase {
		models["session"] = ModelSchema{
			ModelName: modelName(options.Session.ModelName, "session"),
			Order:     2,
			Fields: mergeAuthFields(
				map[string]FieldAttribute{
					"expiresAt": {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.Session.Fields, "expiresAt")},
					"token":     {Type: FieldString, Required: Bool(true), FieldName: authFieldName(options.Session.Fields, "token"), Unique: true},
					"createdAt": {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.Session.Fields, "createdAt"), DefaultValue: now},
					"updatedAt": {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.Session.Fields, "updatedAt"), OnUpdate: now},
					"ipAddress": {Type: FieldString, Required: Bool(false), FieldName: authFieldName(options.Session.Fields, "ipAddress")},
					"userAgent": {Type: FieldString, Required: Bool(false), FieldName: authFieldName(options.Session.Fields, "userAgent")},
					"userId": {
						Type: FieldString, Required: Bool(true), FieldName: authFieldName(options.Session.Fields, "userId"), Index: true,
						References: &Reference{Model: "user", Field: "id", OnDelete: Cascade},
					},
				},
				sessionPlugin.Fields,
				options.Session.AdditionalFields,
			),
		}
	}

	if !options.SecondaryStorage || options.Verification.StoreInDatabase {
		models["verification"] = ModelSchema{
			ModelName: modelName(options.Verification.ModelName, "verification"),
			Order:     4,
			Fields: mergeAuthFields(
				map[string]FieldAttribute{
					"identifier": {Type: FieldString, Required: Bool(true), FieldName: authFieldName(options.Verification.Fields, "identifier"), Index: true},
					"value":      {Type: FieldString, Required: Bool(true), FieldName: authFieldName(options.Verification.Fields, "value")},
					"expiresAt":  {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.Verification.Fields, "expiresAt")},
					"createdAt":  {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.Verification.Fields, "createdAt"), DefaultValue: now},
					"updatedAt":  {Type: FieldDate, Required: Bool(true), FieldName: authFieldName(options.Verification.Fields, "updatedAt"), DefaultValue: now, OnUpdate: now},
				},
				verificationPlugin.Fields,
				options.Verification.AdditionalFields,
			),
		}
	}

	for key, table := range pluginSchema {
		models[key] = ModelSchema{
			ModelName:         table.ModelName,
			Fields:            cloneAuthFields(table.Fields),
			DisableMigrations: table.DisableMigrations,
		}
	}

	if options.RateLimit.Storage == "database" {
		models["rateLimit"] = ModelSchema{
			ModelName: modelName(options.RateLimit.ModelName, "rateLimit"),
			Fields: map[string]FieldAttribute{
				"key":         {Type: FieldString, Required: Bool(true), Unique: true, FieldName: authFieldName(options.RateLimit.Fields, "key")},
				"count":       {Type: FieldNumber, Required: Bool(true), FieldName: authFieldName(options.RateLimit.Fields, "count")},
				"lastRequest": {Type: FieldNumber, Required: Bool(true), BigInt: true, FieldName: authFieldName(options.RateLimit.Fields, "lastRequest"), DefaultValue: unixMillis},
			},
		}
	}

	return Schema{Models: models}
}

type mergedAuthPluginTable struct {
	Fields            map[string]FieldAttribute
	ModelName         string
	DisableMigrations bool
}

func mergeAuthPluginTables(plugins []AuthTablesPlugin) map[string]mergedAuthPluginTable {
	merged := make(map[string]mergedAuthPluginTable)
	for _, plugin := range plugins {
		for key, contribution := range plugin.Schema {
			current := merged[key]
			current.Fields = mergeAuthFields(current.Fields, contribution.Fields)
			current.ModelName = modelName(contribution.ModelName, key)
			if contribution.DisableMigration != nil {
				current.DisableMigrations = *contribution.DisableMigration
			}
			merged[key] = current
		}
	}
	return merged
}

func takeAuthPluginTable(tables map[string]mergedAuthPluginTable, key string) mergedAuthPluginTable {
	table := tables[key]
	delete(tables, key)
	return table
}

func modelName(configured, fallback string) string {
	if configured != "" {
		return configured
	}
	return fallback
}

func authFieldName(configured map[string]string, canonical string) string {
	if value := configured[canonical]; value != "" {
		return value
	}
	return canonical
}

func mergeAuthFields(sources ...map[string]FieldAttribute) map[string]FieldAttribute {
	merged := make(map[string]FieldAttribute)
	for _, source := range sources {
		for name, field := range source {
			merged[name] = cloneAuthField(field)
		}
	}
	return merged
}

func cloneAuthFields(source map[string]FieldAttribute) map[string]FieldAttribute {
	return mergeAuthFields(source)
}

func cloneAuthField(field FieldAttribute) FieldAttribute {
	field.Enum = append([]string(nil), field.Enum...)
	if field.Required != nil {
		field.Required = Bool(*field.Required)
	}
	if field.Returned != nil {
		field.Returned = Bool(*field.Returned)
	}
	if field.Input != nil {
		field.Input = Bool(*field.Input)
	}
	if field.References != nil {
		reference := *field.References
		field.References = &reference
	}
	return field
}
