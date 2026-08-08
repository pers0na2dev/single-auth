package username

import (
	"reflect"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestDefaultValidationAndJavaScriptLength(t *testing.T) {
	compiled, err := compileDefinition(Options{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		value string
		code  string
	}{
		{value: "ab", code: CodeUsernameTooShort},
		{value: "abc", code: ""},
		{value: "A_z.9", code: ""},
		{value: "bad-name", code: CodeInvalidUsername},
		{value: strings.Repeat("a", 31), code: CodeUsernameTooLong},
	}
	for _, test := range tests {
		code, validateErr := compiled.validateUsernameValue(test.value)
		if validateErr != nil || code != test.code {
			t.Fatalf("validateUsernameValue(%q)=(%q,%v), want %q", test.value, code, validateErr, test.code)
		}
	}
	if got := javascriptStringLength("a😀b"); got != 4 {
		t.Fatalf("JavaScript length=%d, want 4", got)
	}
}

func TestNormalizationAndIndependentValidationOrder(t *testing.T) {
	var usernameObserved, displayObserved string
	compiled, err := compileDefinition(Options{
		UsernameNormalization:        func(value string) string { return strings.TrimPrefix(value, "@") },
		DisplayUsernameNormalization: strings.TrimSpace,
		UsernameValidator: func(value string) (bool, error) {
			usernameObserved = value
			return true, nil
		},
		DisplayUsernameValidator: func(value string) (bool, error) {
			displayObserved = value
			return true, nil
		},
		ValidationOrder: ValidationOrders{
			Username: PostNormalization, DisplayUsername: PostNormalization,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, err := compiled.validateUsernameValue("@Alice"); err != nil || code != "" || usernameObserved != "Alice" {
		t.Fatalf("username code=%q err=%v observed=%q", code, err, usernameObserved)
	}
	valid, err := compiled.options.DisplayUsernameValidator(compiled.displayForValidation("  @Alice  "))
	if err != nil || !valid || displayObserved != "@Alice" {
		t.Fatalf("display valid=%v err=%v observed=%q", valid, err, displayObserved)
	}

	disabled, err := compileDefinition(Options{DisableUsernameNormalization: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := disabled.usernameNormal("Mixed.Case"); got != "Mixed.Case" {
		t.Fatalf("disabled normalization=%q", got)
	}
}

func TestFactorySchemaRequiresNoRuntimeAndSnapshotsAliases(t *testing.T) {
	factory := NewFactory(Options{Schema: SchemaOptions{User: UserSchemaOptions{
		Username: "login_name", DisplayUsername: "display_name",
	}}})
	if factory.PluginID() != "username" {
		t.Fatalf("plugin ID=%q", factory.PluginID())
	}
	schema, err := factory.Schema()
	if err != nil {
		t.Fatal(err)
	}
	username := schema.Models["user"].Fields["username"]
	display := schema.Models["user"].Fields["displayUsername"]
	if username.Type != storage.FieldString || username.Required == nil || *username.Required ||
		username.Returned == nil || !*username.Returned || !username.Sortable || !username.Unique ||
		username.FieldName != "login_name" || display.FieldName != "display_name" {
		t.Fatalf("schema username=%#v display=%#v", username, display)
	}
	transformed, err := username.Transform.Input("Mixed.Case")
	if err != nil || transformed != "mixed.case" {
		t.Fatalf("username transform=%#v err=%v", transformed, err)
	}
	untouched, err := username.Transform.Input(42)
	if err != nil || !reflect.DeepEqual(untouched, 42) {
		t.Fatalf("non-string transform=%#v err=%v", untouched, err)
	}
}

func TestDescriptorIsFrozenToUpstreamSurface(t *testing.T) {
	auth := newTestAuth(t, Options{}, singleauth.EmailVerificationOptions{}, false)
	plugins := auth.Options().Plugins
	if len(plugins) != 1 {
		t.Fatalf("plugins=%d", len(plugins))
	}
	descriptor := plugins[0]
	if descriptor.ID != "username" || descriptor.Version != Version || len(descriptor.Endpoints) != 2 || len(descriptor.Hooks.Before) != 3 {
		t.Fatalf("descriptor=%#v", descriptor)
	}
	if descriptor.Endpoints[0].Name != "signInUsername" || descriptor.Endpoints[0].Path != "/sign-in/username" ||
		descriptor.Endpoints[1].Name != "isUsernameAvailable" || descriptor.Endpoints[1].Path != "/is-username-available" {
		t.Fatalf("endpoints=%#v", descriptor.Endpoints)
	}
	for code, message := range errorMessages {
		if got := descriptor.ErrorCodes[code].Message; got != message {
			t.Fatalf("error %s=%q, want %q", code, got, message)
		}
	}
}
