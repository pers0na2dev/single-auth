package lastloginmethod

import (
	"strings"
	"testing"
)

func TestStoreInDatabaseStandaloneRuntimeRequirements(t *testing.T) {
	if _, err := New(Options{StoreInDatabase: true}); err == nil ||
		!strings.Contains(err.Error(), "database adapter is required") {
		t.Fatalf("missing adapter error = %v", err)
	}
}

func TestDisabledDatabaseSchemaRemainsUndefinedEquivalent(t *testing.T) {
	plugin, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if plugin.Schema.Models != nil || plugin.Schema.UsePlural {
		t.Fatalf("disabled schema = %#v, want zero value", plugin.Schema)
	}
}

func TestSchemaRejectsPhysicalAliasCollision(t *testing.T) {
	_, err := Schema(Options{
		StoreInDatabase: true,
		Schema: SchemaOptions{User: UserSchemaOptions{
			LastLoginMethod: "email",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "resolve to \"email\"") {
		t.Fatalf("alias collision error = %v", err)
	}
}

func TestFactorySnapshotsPointerOptions(t *testing.T) {
	maxAge := 17
	factory := NewFactory(Options{MaxAge: &maxAge})
	maxAge = 99
	if factory.PluginID() != "last-login-method" {
		t.Fatalf("plugin ID = %q", factory.PluginID())
	}
	snapshot, ok := factory.(*rootFactory)
	if !ok || snapshot.options.MaxAge == nil || *snapshot.options.MaxAge != 17 {
		t.Fatalf("factory snapshot = %#v", factory)
	}
}
