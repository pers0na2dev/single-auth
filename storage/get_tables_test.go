package storage

import (
	"sort"
	"testing"
)

func TestGetAuthTablesBehavior(t *testing.T) {
	runners := map[string]func(*testing.T){
		"getAuthTables::should use correct field name for refreshTokenExpiresAt": func(t *testing.T) {
			tables := GetAuthTables(AuthTablesOptions{Account: AuthModelOptions{Fields: map[string]string{
				"refreshTokenExpiresAt": "custom_refresh_token_expires_at",
			}}})
			if got := tables.Models["account"].Fields["refreshTokenExpiresAt"].FieldName; got != "custom_refresh_token_expires_at" {
				t.Fatalf("account.refreshTokenExpiresAt.fieldName=%q", got)
			}
		},
		"getAuthTables::should not use accessTokenExpiresAt field name for refreshTokenExpiresAt": func(t *testing.T) {
			tables := GetAuthTables(AuthTablesOptions{Account: AuthModelOptions{Fields: map[string]string{
				"accessTokenExpiresAt":  "custom_access_token_expires_at",
				"refreshTokenExpiresAt": "custom_refresh_token_expires_at",
			}}})
			account := tables.Models["account"]
			refresh := account.Fields["refreshTokenExpiresAt"].FieldName
			access := account.Fields["accessTokenExpiresAt"].FieldName
			if refresh != "custom_refresh_token_expires_at" || access != "custom_access_token_expires_at" || refresh == access {
				t.Fatalf("refreshTokenExpiresAt=%q accessTokenExpiresAt=%q", refresh, access)
			}
		},
		"getAuthTables::should use default field names when no custom names provided": func(t *testing.T) {
			account := GetAuthTables(AuthTablesOptions{}).Models["account"]
			if refresh := account.Fields["refreshTokenExpiresAt"].FieldName; refresh != "refreshTokenExpiresAt" {
				t.Fatalf("refreshTokenExpiresAt.fieldName=%q", refresh)
			}
			if access := account.Fields["accessTokenExpiresAt"].FieldName; access != "accessTokenExpiresAt" {
				t.Fatalf("accessTokenExpiresAt.fieldName=%q", access)
			}
		},
		"getAuthTables::should merge additionalFields into verification table metadata": func(t *testing.T) {
			tables := GetAuthTables(AuthTablesOptions{Verification: AuthVerificationTableOptions{
				AuthModelOptions: AuthModelOptions{AdditionalFields: map[string]FieldAttribute{
					"newField": {FieldName: "new_field", Type: FieldString},
				}},
			}})
			field, exists := tables.Models["verification"].Fields["newField"]
			if !exists || field.FieldName != "new_field" || field.Type != FieldString {
				t.Fatalf("verification.newField=%#v exists=%t", field, exists)
			}
		},
		"getAuthTables::should exclude verification table when secondaryStorage is configured": func(t *testing.T) {
			if _, exists := GetAuthTables(AuthTablesOptions{SecondaryStorage: true}).Models["verification"]; exists {
				t.Fatal("verification table was included")
			}
		},
		"getAuthTables::should include verification table when storeInDatabase is true": func(t *testing.T) {
			options := AuthTablesOptions{SecondaryStorage: true}
			options.Verification.StoreInDatabase = true
			if _, exists := GetAuthTables(options).Models["verification"]; !exists {
				t.Fatal("verification table was omitted")
			}
		},
		"getAuthTables::should include verification table when no secondaryStorage": func(t *testing.T) {
			if _, exists := GetAuthTables(AuthTablesOptions{}).Models["verification"]; !exists {
				t.Fatal("verification table was omitted")
			}
		},
		"getAuthTables::should propagate disableMigration from a plugin schema onto the table": func(t *testing.T) {
			tables := GetAuthTables(AuthTablesOptions{Plugins: []AuthTablesPlugin{{
				ID: "test",
				Schema: map[string]AuthPluginTable{
					"skipped": {Fields: map[string]FieldAttribute{"name": {Type: FieldString}}, DisableMigration: Bool(true)},
					"kept":    {Fields: map[string]FieldAttribute{"name": {Type: FieldString}}},
				},
			}}})
			if !tables.Models["skipped"].DisableMigrations {
				t.Fatal("skipped.disableMigrations=false")
			}
			if tables.Models["kept"].DisableMigrations {
				t.Fatal("kept.disableMigrations=true")
			}
		},
		"getAuthTables::should keep disableMigration when plugins accumulate the same table key": func(t *testing.T) {
			tables := GetAuthTables(AuthTablesOptions{Plugins: []AuthTablesPlugin{
				{ID: "a", Schema: map[string]AuthPluginTable{
					"shared": {Fields: map[string]FieldAttribute{"a": {Type: FieldString}}, DisableMigration: Bool(true)},
				}},
				{ID: "b", Schema: map[string]AuthPluginTable{
					"shared": {Fields: map[string]FieldAttribute{"b": {Type: FieldString}}},
				}},
			}})
			shared := tables.Models["shared"]
			if !shared.DisableMigrations {
				t.Fatal("shared.disableMigrations=false")
			}
			if _, exists := shared.Fields["a"]; !exists {
				t.Fatal("shared.a was discarded")
			}
			if _, exists := shared.Fields["b"]; !exists {
				t.Fatal("shared.b was discarded")
			}
		},
		"getAuthTables > user.modelName collision with account schema key::should point session.userId at the user table when user.modelName='account' and account.modelName='identity'": func(t *testing.T) {
			tables := GetAuthTables(AuthTablesOptions{
				User:    AuthModelOptions{ModelName: "account"},
				Account: AuthModelOptions{ModelName: "identity"},
			})
			assertUserReference(t, tables, "session")
		},
		"getAuthTables > user.modelName collision with account schema key::should point account.userId at the user table when user.modelName='account' and account.modelName='identity'": func(t *testing.T) {
			tables := GetAuthTables(AuthTablesOptions{
				User:    AuthModelOptions{ModelName: "account"},
				Account: AuthModelOptions{ModelName: "identity"},
			})
			assertUserReference(t, tables, "account")
		},
	}

	names := make([]string, 0, len(runners))
	for name := range runners {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		run := runners[name]
		t.Run(name, func(t *testing.T) {
			run(t)
		})
	}
}

func assertUserReference(t *testing.T, tables Schema, sourceModel string) {
	t.Helper()
	reference := tables.Models[sourceModel].Fields["userId"].References
	if reference == nil {
		t.Fatalf("%s.userId.references=nil", sourceModel)
	}
	user, exists := tables.Models[reference.Model]
	if !exists || user.ModelName != "account" {
		t.Fatalf("reference=%#v target=%#v exists=%t", reference, user, exists)
	}
	if _, exists := user.Fields["email"]; !exists {
		t.Fatalf("reference target %q has no email field", reference.Model)
	}
}
