package deviceauthorization

import (
	"reflect"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestDescriptorSchemaEndpointsAndErrorCodes(t *testing.T) {
	descriptor, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.ID != PluginID || descriptor.Version != Version {
		t.Fatalf("identity = %q %q", descriptor.ID, descriptor.Version)
	}
	wantEndpoints := []struct{ name, path, method string }{
		{"deviceCode", DeviceCodePath, "POST"},
		{"deviceToken", DeviceTokenPath, "POST"},
		{"deviceVerify", DeviceVerifyPath, "GET"},
		{"deviceApprove", DeviceApprovePath, "POST"},
		{"deviceDeny", DeviceDenyPath, "POST"},
	}
	if len(descriptor.Endpoints) != len(wantEndpoints) {
		t.Fatalf("endpoints = %#v", descriptor.Endpoints)
	}
	for index, expected := range wantEndpoints {
		endpoint := descriptor.Endpoints[index]
		if endpoint.Name != expected.name || endpoint.Path != expected.path ||
			!reflect.DeepEqual(endpoint.Methods, []string{expected.method}) || endpoint.Handler == nil {
			t.Fatalf("endpoint %d = %#v", index, endpoint)
		}
	}
	model := descriptor.Schema.Models["deviceCode"]
	if model.ModelName != "deviceCode" || len(model.Fields) != 9 {
		t.Fatalf("schema = %#v", descriptor.Schema)
	}
	for name, fieldType := range map[string]storage.FieldType{
		"deviceCode": storage.FieldString, "userCode": storage.FieldString,
		"userId": storage.FieldString, "expiresAt": storage.FieldDate,
		"status": storage.FieldString, "lastPolledAt": storage.FieldDate,
		"pollingInterval": storage.FieldNumber, "clientId": storage.FieldString,
		"scope": storage.FieldString,
	} {
		if model.Fields[name].Type != fieldType {
			t.Fatalf("field %s = %#v", name, model.Fields[name])
		}
	}
	if len(descriptor.ErrorCodes) != 13 || descriptor.ErrorCodes["DEVICE_CODE_NOT_CLAIMED"].Message != MessageDeviceCodeNotClaimed {
		t.Fatalf("errors = %#v", descriptor.ErrorCodes)
	}
}

func TestNormalizeOptionsDefaultsAndCustomValues(t *testing.T) {
	defaults, err := NormalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if defaults.ExpiresIn != 30*time.Minute || defaults.Interval != 5*time.Second ||
		defaults.DeviceCodeLength != 40 || defaults.UserCodeLength != 8 {
		t.Fatalf("defaults = %#v", defaults)
	}
	custom, err := NormalizeOptions(Options{
		ExpiresIn: time.Minute, Interval: 2 * time.Second,
		DeviceCodeLength: 50, UserCodeLength: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if custom.ExpiresIn != time.Minute || custom.Interval != 2*time.Second ||
		custom.DeviceCodeLength != 50 || custom.UserCodeLength != 10 {
		t.Fatalf("custom = %#v", custom)
	}
	if _, err := NormalizeOptions(Options{DeviceCodeLength: -1}); err == nil {
		t.Fatal("negative DeviceCodeLength accepted")
	}
	if _, err := NormalizeOptions(Options{UserCodeLength: -1}); err == nil {
		t.Fatal("negative UserCodeLength accepted")
	}
	if configured, err := NormalizeOptions(Options{VerificationURI: "/device"}); err != nil || configured.VerificationURI != "/device" {
		t.Fatalf("string VerificationURI = %#v, %v", configured, err)
	}
}

func TestCustomSchemaIsMergedAndSnapshotted(t *testing.T) {
	extension := storage.Schema{Models: map[string]storage.ModelSchema{
		"deviceCode": {ModelName: "device_codes", Fields: map[string]storage.FieldAttribute{
			"clientId": {Type: storage.FieldString, FieldName: "client_id"},
		}},
	}}
	descriptor, err := New(Options{Schema: extension})
	if err != nil {
		t.Fatal(err)
	}
	if model := descriptor.Schema.Models["deviceCode"]; model.ModelName != "device_codes" || model.Fields["clientId"].FieldName != "client_id" {
		t.Fatalf("merged schema = %#v", descriptor.Schema)
	}
	model := extension.Models["deviceCode"]
	model.Fields["clientId"] = storage.FieldAttribute{Type: storage.FieldBoolean}
	extension.Models["deviceCode"] = model
	if descriptor.Schema.Models["deviceCode"].Fields["clientId"].Type != storage.FieldString {
		t.Fatal("descriptor schema aliases caller input")
	}
}

func TestDurationSecondsUsesJavaScriptMathFloorSemantics(t *testing.T) {
	for _, test := range []struct {
		input time.Duration
		want  int64
	}{
		{input: 1500 * time.Millisecond, want: 1},
		{input: -1500 * time.Millisecond, want: -2},
		{input: -time.Second, want: -1},
		{input: 0, want: 0},
	} {
		if got := floorDurationSeconds(test.input); got != test.want {
			t.Fatalf("floorDurationSeconds(%s) = %d, want %d", test.input, got, test.want)
		}
	}
}
