package additionalfields

import (
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestPluginDescriptorAndSchemaComposition(t *testing.T) {
	optional := storage.Bool(false)
	returned := storage.Bool(false)
	fields := Fields{
		{Name: "role", Attribute: storage.FieldAttribute{Type: storage.FieldString, DefaultValue: storage.StaticValue("user"), Index: true, FieldName: "user_role"}},
		{Name: "private", Attribute: storage.FieldAttribute{Type: storage.FieldJSON, Required: optional, Returned: returned}},
	}
	processor, err := Compile(Options{
		User: fields,
		Session: Fields{{Name: "theme", Attribute: storage.FieldAttribute{
			Type: storage.FieldString, Required: optional,
		}}},
		Account: Fields{{Name: "tenant", Attribute: storage.FieldAttribute{
			Type: storage.FieldString, Required: optional,
		}}},
		Verification: Fields{{Name: "purpose", Attribute: storage.FieldAttribute{
			Type: storage.FieldString, Required: optional,
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plugin := processor.Plugin()
	if plugin.ID != "additional-fields" || plugin.Version != Version || len(plugin.Hooks.Before) != 1 || len(plugin.ErrorCodes) != 4 {
		t.Fatalf("plugin descriptor = %#v", plugin)
	}
	for _, model := range []string{"user", "session", "account", "verification"} {
		if len(plugin.Schema.Models[model].Fields) == 0 {
			t.Fatalf("missing %s fields: %#v", model, plugin.Schema)
		}
	}
	role := plugin.Schema.Models["user"].Fields["role"]
	if role.Type != storage.FieldString || role.FieldName != "user_role" || !role.Index || role.DefaultValue == nil {
		t.Fatalf("role metadata = %#v", role)
	}

	// Caller and returned-descriptor mutations must not alter the processor.
	fields[0].Attribute.FieldName = "mutated_input"
	plugin.Schema.Models["user"].Fields["role"] = storage.FieldAttribute{Type: storage.FieldNumber}
	stable := processor.Schema().Models["user"].Fields["role"]
	if stable.Type != storage.FieldString || stable.FieldName != "user_role" {
		t.Fatalf("processor schema mutated: %#v", stable)
	}

	merged, err := storage.CoreSchema().Merge(processor.Schema())
	if err != nil {
		t.Fatal(err)
	}
	if merged.Models["user"].Fields["role"].FieldName != "user_role" || merged.Models["user"].Fields["email"].Type != storage.FieldString {
		t.Fatalf("merged schema = %#v", merged.Models["user"])
	}
}

func TestCompileRejectsInvalidFields(t *testing.T) {
	for _, test := range []struct {
		name    string
		options Options
		want    string
	}{
		{name: "empty name", options: Options{User: Fields{{Attribute: storage.FieldAttribute{Type: storage.FieldString}}}}, want: "empty name"},
		{name: "duplicate", options: Options{User: Fields{
			{Name: "role", Attribute: storage.FieldAttribute{Type: storage.FieldString}},
			{Name: "role", Attribute: storage.FieldAttribute{Type: storage.FieldString}},
		}}, want: "duplicated"},
		{name: "invalid type", options: Options{User: Fields{{Name: "role", Attribute: storage.FieldAttribute{Type: "invalid"}}}}, want: "invalid type"},
		{name: "alias collision", options: Options{User: Fields{
			{Name: "first", Attribute: storage.FieldAttribute{Type: storage.FieldString, FieldName: "same"}},
			{Name: "second", Attribute: storage.FieldAttribute{Type: storage.FieldString, FieldName: "same"}},
		}}, want: "resolve to"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(test.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestFactorySnapshotsSchemaOptions(t *testing.T) {
	fields := Fields{{
		Name: "role", Attribute: storage.FieldAttribute{
			Type: storage.FieldEnum, Enum: []string{"user", "admin"},
		},
	}}
	factory := NewFactory(Options{User: fields})
	fields[0].Attribute.Type = storage.FieldNumber
	fields[0].Attribute.Enum[0] = "mutated"
	schema, err := factory.Schema()
	if err != nil {
		t.Fatal(err)
	}
	role := schema.Models["user"].Fields["role"]
	if role.Type != storage.FieldEnum || role.Enum[0] != "user" {
		t.Fatalf("factory schema mutated: %#v", role)
	}
}
