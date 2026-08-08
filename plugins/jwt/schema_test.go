package jwt

import (
	"reflect"
	"slices"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestSchemaMatchesFrozenPlugin(t *testing.T) {
	schema := Schema()
	model, ok := schema.Models["jwks"]
	if !ok || model.ModelName != "jwks" {
		t.Fatalf("jwks model = %#v", model)
	}
	if got, want := sortedFieldNames(model.Fields), []string{"createdAt", "expiresAt", "privateKey", "publicKey"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fields = %#v, want %#v", got, want)
	}
	if model.Fields["publicKey"].Type != storage.FieldString || !model.Fields["publicKey"].IsRequired() ||
		model.Fields["privateKey"].Type != storage.FieldString || !model.Fields["privateKey"].IsRequired() ||
		model.Fields["createdAt"].Type != storage.FieldDate || !model.Fields["createdAt"].IsRequired() ||
		model.Fields["expiresAt"].Type != storage.FieldDate || model.Fields["expiresAt"].IsRequired() {
		t.Fatalf("schema fields = %#v", model.Fields)
	}
	first := Schema()
	first.Models["jwks"] = storage.ModelSchema{}
	if Schema().Models["jwks"].ModelName != "jwks" {
		t.Fatal("Schema returned shared state")
	}
}

func sortedFieldNames(fields map[string]storage.FieldAttribute) []string {
	result := make([]string, 0, len(fields))
	for name := range fields {
		result = append(result, name)
	}
	slices.Sort(result)
	return result
}
