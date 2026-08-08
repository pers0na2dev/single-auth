package passkey

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestPluginDescriptorAndSchemaMatchReference1626(t *testing.T) {
	harness := newHarness(t, nil)
	_ = harness

	schema := Schema()
	model, ok := schema.Models["passkey"]
	if !ok || model.ModelName != "passkey" {
		t.Fatalf("passkey model = %#v", model)
	}
	wantFields := map[string]storage.FieldType{
		"name": storage.FieldString, "publicKey": storage.FieldString,
		"userId": storage.FieldString, "credentialID": storage.FieldString,
		"counter": storage.FieldNumber, "deviceType": storage.FieldString,
		"backedUp": storage.FieldBoolean, "transports": storage.FieldString,
		"createdAt": storage.FieldDate, "aaguid": storage.FieldString,
	}
	if len(model.Fields) != len(wantFields) {
		t.Fatalf("schema fields = %#v", model.Fields)
	}
	for name, kind := range wantFields {
		field, exists := model.Fields[name]
		if !exists || field.Type != kind {
			t.Fatalf("field %s = %#v, want %s", name, field, kind)
		}
	}
	if !model.Fields["userId"].Index || model.Fields["userId"].References == nil ||
		model.Fields["userId"].References.OnDelete != storage.Cascade {
		t.Fatalf("userId field = %#v", model.Fields["userId"])
	}
	if !model.Fields["credentialID"].Index || model.Fields["credentialID"].Unique {
		t.Fatalf("credentialID field = %#v", model.Fields["credentialID"])
	}
	for _, optional := range []string{"name", "transports", "createdAt", "aaguid"} {
		if model.Fields[optional].IsRequired() {
			t.Fatalf("field %s should be optional", optional)
		}
	}

	plugin, err := New(Options{Runtime: Runtime{
		Adapter: harness.adapter,
		ResolveSession: func(*engine.Context, SessionResolution) (*SessionState, error) {
			return nil, nil
		},
		IssueSession: func(*engine.Context, string) (*SessionState, error) {
			return nil, nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if plugin.ID != "passkey" || plugin.Version != Version {
		t.Fatalf("plugin identity = %s@%s", plugin.ID, plugin.Version)
	}
	wantEndpoints := []struct {
		name, path, method string
	}{
		{"generatePasskeyRegistrationOptions", "/passkey/generate-register-options", "GET"},
		{"generatePasskeyAuthenticationOptions", "/passkey/generate-authenticate-options", "GET"},
		{"verifyPasskeyRegistration", "/passkey/verify-registration", "POST"},
		{"verifyPasskeyAuthentication", "/passkey/verify-authentication", "POST"},
		{"listPasskeys", "/passkey/list-user-passkeys", "GET"},
		{"deletePasskey", "/passkey/delete-passkey", "POST"},
		{"updatePasskey", "/passkey/update-passkey", "POST"},
	}
	if len(plugin.Endpoints) != len(wantEndpoints) {
		t.Fatalf("endpoint count = %d", len(plugin.Endpoints))
	}
	for index, want := range wantEndpoints {
		got := plugin.Endpoints[index]
		if got.Name != want.name || got.Path != want.path || !reflect.DeepEqual(got.Methods, []string{want.method}) {
			t.Fatalf("endpoint[%d] = %#v, want %#v", index, got, want)
		}
	}
	if len(plugin.ErrorCodes) != len(errorMessages) {
		t.Fatalf("error code count = %d, want %d", len(plugin.ErrorCodes), len(errorMessages))
	}
}

func TestAuthenticatorMetadata(t *testing.T) {
	for input, want := range map[string]string{
		"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4":     "Google Password Manager",
		"  DD4EC289-E01D-41C9-BB89-70FA845D4BF2  ": "iCloud Keychain (Managed)",
		"08987058-cadc-4b81-b6e1-30de50dcbe96":     "Windows Hello",
		"9ddd1817-af5a-4672-a2b9-3e3dd95000a9":     "Windows Hello",
		"6028b017-b1d4-4c02-b4b3-afcdafc96bb2":     "Windows Hello",
	} {
		if got, ok := GetAuthenticatorName(input); !ok || got != want {
			t.Fatalf("GetAuthenticatorName(%q) = %q, %v", input, got, ok)
		}
	}
	for _, input := range []string{"", "   ", anonymousAAGUID, "__proto__", "constructor", "unknown"} {
		if got, ok := GetAuthenticatorName(input); ok || got != "" {
			t.Fatalf("GetAuthenticatorName(%q) = %q, %v", input, got, ok)
		}
	}

	const extensionAAGUID = "11111111-2222-3333-4444-555555555555"
	CommonAuthenticatorNames[extensionAAGUID] = "Custom Authenticator"
	defer delete(CommonAuthenticatorNames, extensionAAGUID)
	if got, ok := GetAuthenticatorName("  " + strings.ToUpper(extensionAAGUID) + "  "); !ok || got != "Custom Authenticator" {
		t.Fatalf("extended authenticator name = %q, %v", got, ok)
	}

	originalAnonymous, hadAnonymous := CommonAuthenticatorNames[anonymousAAGUID]
	CommonAuthenticatorNames[anonymousAAGUID] = "Must remain hidden"
	defer func() {
		if hadAnonymous {
			CommonAuthenticatorNames[anonymousAAGUID] = originalAnonymous
		} else {
			delete(CommonAuthenticatorNames, anonymousAAGUID)
		}
	}()
	if got, ok := GetAuthenticatorName(anonymousAAGUID); ok || got != "" {
		t.Fatalf("anonymous AAGUID leaked mutable map value = %q, %v", got, ok)
	}
}
