package main

import (
	"fmt"
	"os"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

var fixedTime = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func main() {
	if len(os.Args) != 2 {
		panic("expected one db-types fixture name")
	}
	mode := os.Args[1]
	switch mode {
	case "account-additional-fields":
		accountAdditionalFields()
	case "account-plugin-fields":
		accountPluginFields()
	case "schema-without-additional-fields":
		defaultSchema()
	case "session-additional-fields":
		sessionAdditionalFields()
	case "session-plugin-fields":
		sessionPluginFields()
	case "user-additional-fields":
		userAdditionalFields()
	case "user-both-additional-plugin-fields":
		userBothAdditionalAndPluginFields()
	case "user-different-field-types":
		userDifferentFieldTypes()
	case "user-plugin-fields":
		userPluginFields()
	case "verification-additional-fields":
		verificationAdditionalFields()
	default:
		panic("unknown db-types fixture: " + mode)
	}
	fmt.Print("ok:db-types-" + mode)
}

func accountAdditionalFields() {
	type additional struct {
		LastLoginAt model.Value[time.Time]
		IsVerified  bool
	}
	schema := storage.GetAuthTables(storage.AuthTablesOptions{
		Account: storage.AuthModelOptions{AdditionalFields: map[string]storage.FieldAttribute{
			"lastLoginAt": {Type: storage.FieldDate, Required: storage.Bool(false)},
			"isVerified":  {Type: storage.FieldBoolean, Required: storage.Bool(true)},
		}},
	})
	assertField(schema, "account", "lastLoginAt", storage.FieldDate, false)
	assertField(schema, "account", "isVerified", storage.FieldBoolean, true)
	decoded, err := singleauth.DecodeAccount(model.Account{
		Core:       model.Core{ID: "account-1", CreatedAt: fixedTime, UpdatedAt: fixedTime},
		ProviderID: "credential", AccountID: "account@example.com", UserID: "user-1",
		AdditionalFields: model.Fields{
			"lastLoginAt": model.Null[any](), "isVerified": model.Present[any](true),
		},
	}, func(fields model.Fields) (additional, error) {
		lastLoginAt, err := singleauth.DecodeDBField[time.Time](fields, "lastLoginAt")
		if err != nil {
			return additional{}, err
		}
		isVerified, err := singleauth.RequireDBField[bool](fields, "isVerified")
		return additional{LastLoginAt: lastLoginAt, IsVerified: isVerified}, err
	})
	if err != nil {
		panic(err)
	}
	var lastLoginAt model.Value[time.Time] = decoded.Additional.LastLoginAt
	var isVerified bool = decoded.Additional.IsVerified
	var providerID string = decoded.ProviderID
	var accountID string = decoded.AccountID
	if !lastLoginAt.IsNull() || !isVerified || providerID != "credential" || accountID == "" {
		panic("account additional-field type contract failed")
	}
}

func accountPluginFields() {
	type additional struct{ CustomAccountField bool }
	schema := pluginSchema("account-plugin", "account", map[string]storage.FieldAttribute{
		"customAccountField": {Type: storage.FieldBoolean, Required: storage.Bool(true)},
	})
	assertField(schema, "account", "customAccountField", storage.FieldBoolean, true)
	decoded, err := singleauth.DecodeAccount(model.Account{
		ProviderID: "github", AccountID: "123",
		AdditionalFields: model.Fields{"customAccountField": model.Present[any](true)},
	}, func(fields model.Fields) (additional, error) {
		value, err := singleauth.RequireDBField[bool](fields, "customAccountField")
		return additional{CustomAccountField: value}, err
	})
	if err != nil {
		panic(err)
	}
	var custom bool = decoded.Additional.CustomAccountField
	var providerID string = decoded.ProviderID
	if !custom || providerID != "github" {
		panic("account plugin-field type contract failed")
	}
}

func defaultSchema() {
	var user singleauth.User
	var session singleauth.Session
	var account singleauth.Account
	var verification singleauth.Verification
	var email string = user.Email
	var token string = session.Token
	var providerID string = account.ProviderID
	var value string = verification.Value
	_, _, _, _ = email, token, providerID, value

	// The explicit empty generic is the Go form of an omitted TypeScript DB
	// options generic and proves the static wrappers also have a zero-field form.
	var typedUser singleauth.TypedUser[struct{}]
	var typedSession singleauth.TypedSession[struct{}]
	var typedAccount singleauth.TypedAccount[struct{}]
	var typedVerification singleauth.TypedVerification[struct{}]
	_, _, _, _ = typedUser.Email, typedSession.Token, typedAccount.ProviderID, typedVerification.Value
}

func sessionAdditionalFields() {
	type additional struct {
		DeviceID     string
		RefreshCount model.Value[float64]
	}
	schema := storage.GetAuthTables(storage.AuthTablesOptions{
		Session: storage.AuthSessionTableOptions{AuthModelOptions: storage.AuthModelOptions{
			AdditionalFields: map[string]storage.FieldAttribute{
				"deviceId":     {Type: storage.FieldString, Required: storage.Bool(true)},
				"refreshCount": {Type: storage.FieldNumber, Required: storage.Bool(false)},
			},
		}},
	})
	assertField(schema, "session", "deviceId", storage.FieldString, true)
	assertField(schema, "session", "refreshCount", storage.FieldNumber, false)
	decoded, err := singleauth.DecodeSession(model.Session{
		UserID: "user-1", Token: "session-token", ExpiresAt: fixedTime.Add(time.Hour),
		AdditionalFields: model.Fields{
			"deviceId":     model.Present[any]("device-1"),
			"refreshCount": model.Present[any](float64(3)),
		},
	}, func(fields model.Fields) (additional, error) {
		deviceID, err := singleauth.RequireDBField[string](fields, "deviceId")
		if err != nil {
			return additional{}, err
		}
		refreshCount, err := singleauth.DecodeDBField[float64](fields, "refreshCount")
		return additional{DeviceID: deviceID, RefreshCount: refreshCount}, err
	})
	if err != nil {
		panic(err)
	}
	var deviceID string = decoded.Additional.DeviceID
	var refreshCount model.Value[float64] = decoded.Additional.RefreshCount
	var token string = decoded.Token
	var userID string = decoded.UserID
	count, present := refreshCount.Get()
	if deviceID != "device-1" || !present || count != 3 || token == "" || userID == "" {
		panic("session additional-field type contract failed")
	}
}

func sessionPluginFields() {
	type additional struct {
		PluginSessionID string
		Metadata        model.Value[map[string]any]
	}
	schema := pluginSchema("session-plugin", "session", map[string]storage.FieldAttribute{
		"pluginSessionId": {Type: storage.FieldString, Required: storage.Bool(true)},
		"metadata":        {Type: storage.FieldJSON, Required: storage.Bool(false)},
	})
	assertField(schema, "session", "pluginSessionId", storage.FieldString, true)
	assertField(schema, "session", "metadata", storage.FieldJSON, false)
	decoded, err := singleauth.DecodeSession(model.Session{
		Token: "session-token",
		AdditionalFields: model.Fields{
			"pluginSessionId": model.Present[any]("plugin-session-1"),
			"metadata":        model.Present[any](map[string]any{"role": "admin"}),
		},
	}, func(fields model.Fields) (additional, error) {
		pluginSessionID, err := singleauth.RequireDBField[string](fields, "pluginSessionId")
		if err != nil {
			return additional{}, err
		}
		metadata, err := singleauth.DecodeDBField[map[string]any](fields, "metadata")
		return additional{PluginSessionID: pluginSessionID, Metadata: metadata}, err
	})
	if err != nil {
		panic(err)
	}
	var pluginSessionID string = decoded.Additional.PluginSessionID
	var metadata model.Value[map[string]any] = decoded.Additional.Metadata
	var token string = decoded.Token
	data, present := metadata.Get()
	if pluginSessionID == "" || !present || data["role"] != "admin" || token == "" {
		panic("session plugin-field type contract failed")
	}
}

func userAdditionalFields() {
	type additional struct {
		CustomField string
		Code        model.Value[string]
		Name        string
	}
	schema := storage.GetAuthTables(storage.AuthTablesOptions{
		User: storage.AuthModelOptions{AdditionalFields: map[string]storage.FieldAttribute{
			"code": {Type: storage.FieldString, Required: storage.Bool(false)},
			"name": {Type: storage.FieldString, Required: storage.Bool(true)},
		}},
		Plugins: []storage.AuthTablesPlugin{{ID: "demo", Schema: map[string]storage.AuthPluginTable{
			"user": {Fields: map[string]storage.FieldAttribute{
				"customField": {Type: storage.FieldString, Required: storage.Bool(true)},
			}},
		}}},
	})
	assertField(schema, "user", "customField", storage.FieldString, true)
	assertField(schema, "user", "code", storage.FieldString, false)
	assertField(schema, "user", "name", storage.FieldString, true)
	decoded, err := singleauth.DecodeUser(model.User{
		Core:  model.Core{ID: "user-1", CreatedAt: fixedTime, UpdatedAt: fixedTime},
		Email: "user@example.com", Name: "Core Name",
		AdditionalFields: model.Fields{
			"customField": model.Present[any]("plugin"),
			"code":        model.Null[any](), "name": model.Present[any]("Configured Name"),
		},
	}, func(fields model.Fields) (additional, error) {
		customField, err := singleauth.RequireDBField[string](fields, "customField")
		if err != nil {
			return additional{}, err
		}
		code, err := singleauth.DecodeDBField[string](fields, "code")
		if err != nil {
			return additional{}, err
		}
		name, err := singleauth.RequireDBField[string](fields, "name")
		return additional{CustomField: customField, Code: code, Name: name}, err
	})
	if err != nil {
		panic(err)
	}
	var customField string = decoded.Additional.CustomField
	var code model.Value[string] = decoded.Additional.Code
	var name string = decoded.Additional.Name
	var email string = decoded.Email
	var id string = decoded.ID
	var createdAt time.Time = decoded.CreatedAt
	var updatedAt time.Time = decoded.UpdatedAt
	if customField != "plugin" || !code.IsNull() || name != "Configured Name" ||
		email == "" || id == "" || createdAt.IsZero() || updatedAt.IsZero() {
		panic("user additional-field type contract failed")
	}
}

func userBothAdditionalAndPluginFields() {
	type additional struct {
		CustomField string
		PluginField float64
	}
	schema := storage.GetAuthTables(storage.AuthTablesOptions{
		User: storage.AuthModelOptions{AdditionalFields: map[string]storage.FieldAttribute{
			"customField": {Type: storage.FieldString, Required: storage.Bool(true)},
		}},
		Plugins: []storage.AuthTablesPlugin{{ID: "test-plugin", Schema: map[string]storage.AuthPluginTable{
			"user": {Fields: map[string]storage.FieldAttribute{
				"pluginField": {Type: storage.FieldNumber, Required: storage.Bool(true)},
			}},
		}}},
	})
	assertField(schema, "user", "customField", storage.FieldString, true)
	assertField(schema, "user", "pluginField", storage.FieldNumber, true)
	decoded, err := singleauth.DecodeUser(model.User{
		Email: "user@example.com",
		AdditionalFields: model.Fields{
			"customField": model.Present[any]("configured"),
			"pluginField": model.Present[any](float64(42)),
		},
	}, func(fields model.Fields) (additional, error) {
		customField, err := singleauth.RequireDBField[string](fields, "customField")
		if err != nil {
			return additional{}, err
		}
		pluginField, err := singleauth.RequireDBField[float64](fields, "pluginField")
		return additional{CustomField: customField, PluginField: pluginField}, err
	})
	if err != nil {
		panic(err)
	}
	var customField string = decoded.Additional.CustomField
	var pluginField float64 = decoded.Additional.PluginField
	var email string = decoded.Email
	if customField != "configured" || pluginField != 42 || email == "" {
		panic("combined user field type contract failed")
	}
}

func userDifferentFieldTypes() {
	type additional struct {
		Age      float64
		IsActive model.Value[bool]
		JoinedAt time.Time
		Metadata model.Value[map[string]any]
	}
	schema := storage.GetAuthTables(storage.AuthTablesOptions{
		User: storage.AuthModelOptions{AdditionalFields: map[string]storage.FieldAttribute{
			"age":      {Type: storage.FieldNumber, Required: storage.Bool(true)},
			"isActive": {Type: storage.FieldBoolean, Required: storage.Bool(false)},
			"joinedAt": {Type: storage.FieldDate, Required: storage.Bool(true)},
			"metadata": {Type: storage.FieldJSON, Required: storage.Bool(false)},
		}},
	})
	assertField(schema, "user", "age", storage.FieldNumber, true)
	assertField(schema, "user", "isActive", storage.FieldBoolean, false)
	assertField(schema, "user", "joinedAt", storage.FieldDate, true)
	assertField(schema, "user", "metadata", storage.FieldJSON, false)
	decoded, err := singleauth.DecodeUser(model.User{
		AdditionalFields: model.Fields{
			"age":      model.Present[any](float64(31)),
			"joinedAt": model.Present[any](fixedTime),
			"metadata": model.Present[any](map[string]any{"source": "test"}),
		},
	}, func(fields model.Fields) (additional, error) {
		age, err := singleauth.RequireDBField[float64](fields, "age")
		if err != nil {
			return additional{}, err
		}
		isActive, err := singleauth.DecodeDBField[bool](fields, "isActive")
		if err != nil {
			return additional{}, err
		}
		joinedAt, err := singleauth.RequireDBField[time.Time](fields, "joinedAt")
		if err != nil {
			return additional{}, err
		}
		metadata, err := singleauth.DecodeDBField[map[string]any](fields, "metadata")
		return additional{Age: age, IsActive: isActive, JoinedAt: joinedAt, Metadata: metadata}, err
	})
	if err != nil {
		panic(err)
	}
	var age float64 = decoded.Additional.Age
	var isActive model.Value[bool] = decoded.Additional.IsActive
	var joinedAt time.Time = decoded.Additional.JoinedAt
	var metadata model.Value[map[string]any] = decoded.Additional.Metadata
	data, present := metadata.Get()
	if age != 31 || isActive.IsSet() || joinedAt != fixedTime || !present || data["source"] != "test" {
		panic("user field-kind type contract failed")
	}
}

func userPluginFields() {
	type additional struct {
		PluginField         string
		OptionalPluginField model.Value[float64]
	}
	schema := pluginSchema("test-plugin", "user", map[string]storage.FieldAttribute{
		"pluginField":         {Type: storage.FieldString, Required: storage.Bool(true)},
		"optionalPluginField": {Type: storage.FieldNumber, Required: storage.Bool(false)},
	})
	assertField(schema, "user", "pluginField", storage.FieldString, true)
	assertField(schema, "user", "optionalPluginField", storage.FieldNumber, false)
	decoded, err := singleauth.DecodeUser(model.User{
		Email: "user@example.com",
		AdditionalFields: model.Fields{
			"pluginField":         model.Present[any]("plugin"),
			"optionalPluginField": model.Null[any](),
		},
	}, func(fields model.Fields) (additional, error) {
		pluginField, err := singleauth.RequireDBField[string](fields, "pluginField")
		if err != nil {
			return additional{}, err
		}
		optional, err := singleauth.DecodeDBField[float64](fields, "optionalPluginField")
		return additional{PluginField: pluginField, OptionalPluginField: optional}, err
	})
	if err != nil {
		panic(err)
	}
	var pluginField string = decoded.Additional.PluginField
	var optionalPluginField model.Value[float64] = decoded.Additional.OptionalPluginField
	var email string = decoded.Email
	if pluginField != "plugin" || !optionalPluginField.IsNull() || email == "" {
		panic("user plugin-field type contract failed")
	}
}

func verificationAdditionalFields() {
	type additional struct {
		Attempts    float64
		LockedUntil model.Value[time.Time]
	}
	schema := storage.GetAuthTables(storage.AuthTablesOptions{
		Verification: storage.AuthVerificationTableOptions{AuthModelOptions: storage.AuthModelOptions{
			AdditionalFields: map[string]storage.FieldAttribute{
				"attempts":    {Type: storage.FieldNumber, Required: storage.Bool(true)},
				"lockedUntil": {Type: storage.FieldDate, Required: storage.Bool(false)},
			},
		}},
	})
	assertField(schema, "verification", "attempts", storage.FieldNumber, true)
	assertField(schema, "verification", "lockedUntil", storage.FieldDate, false)
	decoded, err := singleauth.DecodeVerification(model.Verification{
		Identifier: "identifier", Value: "value",
		AdditionalFields: model.Fields{
			"attempts":    model.Present[any](float64(2)),
			"lockedUntil": model.Null[any](),
		},
	}, func(fields model.Fields) (additional, error) {
		attempts, err := singleauth.RequireDBField[float64](fields, "attempts")
		if err != nil {
			return additional{}, err
		}
		lockedUntil, err := singleauth.DecodeDBField[time.Time](fields, "lockedUntil")
		return additional{Attempts: attempts, LockedUntil: lockedUntil}, err
	})
	if err != nil {
		panic(err)
	}
	var attempts float64 = decoded.Additional.Attempts
	var lockedUntil model.Value[time.Time] = decoded.Additional.LockedUntil
	var value string = decoded.Value
	var identifier string = decoded.Identifier
	if attempts != 2 || !lockedUntil.IsNull() || value == "" || identifier == "" {
		panic("verification additional-field type contract failed")
	}
}

func pluginSchema(id, modelName string, fields map[string]storage.FieldAttribute) storage.Schema {
	return storage.GetAuthTables(storage.AuthTablesOptions{
		Plugins: []storage.AuthTablesPlugin{{ID: id, Schema: map[string]storage.AuthPluginTable{
			modelName: {Fields: fields},
		}}},
	})
}

func assertField(
	schema storage.Schema,
	modelName string,
	fieldName string,
	fieldType storage.FieldType,
	required bool,
) {
	modelSchema, ok := schema.Models[modelName]
	if !ok {
		panic("missing model schema: " + modelName)
	}
	field, ok := modelSchema.Fields[fieldName]
	if !ok || field.Type != fieldType || field.IsRequired() != required {
		panic(fmt.Sprintf("invalid schema field %s.%s: %#v", modelName, fieldName, field))
	}
}
