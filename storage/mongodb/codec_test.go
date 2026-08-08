package mongodb

import (
	"reflect"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestObjectIDAndUUIDCodec(t *testing.T) {
	const objectText = "507f1f77bcf86cd799439011"
	objectConfiguration := testConfig(t, Options{IDType: ObjectID})
	object, err := encodeID(&objectConfiguration, objectText, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := object.(bson.ObjectID); !ok {
		t.Fatalf("object ID encoded as %T", object)
	}
	decoded, err := decodeID(&objectConfiguration, object)
	if err != nil || decoded != objectText {
		t.Fatalf("decoded ObjectID = %v, %v", decoded, err)
	}

	const uuidText = "550e8400-e29b-41d4-a716-446655440000"
	uuidConfiguration := testConfig(t, Options{IDType: UUIDID})
	uuid, err := encodeID(&uuidConfiguration, uuidText, true)
	if err != nil {
		t.Fatal(err)
	}
	binary, ok := uuid.(bson.Binary)
	if !ok || binary.Subtype != 4 || len(binary.Data) != 16 {
		t.Fatalf("UUID encoded as %#v", uuid)
	}
	decoded, err = decodeID(&uuidConfiguration, uuid)
	if err != nil || decoded != uuidText {
		t.Fatalf("decoded UUID = %v, %v", decoded, err)
	}
}

func TestCreateCodecAppliesDefaultsAndDeepCopiesJSON(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	configuration := testConfig(t, Options{
		IDType:      TextID,
		IDGenerator: func(string) (any, error) { return "generated", nil },
		Clock:       func() time.Time { return now },
	})
	model, _ := resolveModel(&configuration, "user")
	metadata := map[string]any{"roles": []any{"admin"}}
	mutation, err := encodeCreate(&configuration, model, storage.Record{
		"name": "Alice", "email": "alice@example.com", "metadata": metadata,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if mutation.values["_id"] != "generated" || mutation.values["createdAt"] != now || mutation.values["updatedAt"] != now {
		t.Fatalf("defaults = %#v", mutation.values)
	}
	metadata["roles"].([]any)[0] = "mutated"
	storedMetadata := mutation.values["metadata"].(bson.M)
	if got := storedMetadata["roles"].(bson.A)[0]; got != "admin" {
		t.Fatalf("stored nested value = %v", got)
	}
}

func TestDecodeDocumentPreservesMissingAndExplicitNull(t *testing.T) {
	configuration := testConfig(t, Options{IDType: TextID, IDGenerator: func(string) (any, error) { return "generated", nil }})
	model, _ := resolveModel(&configuration, "user")
	raw := bson.M{"_id": "u1", "name": "Alice", "image": nil, "unknown": bson.M{"n": int32(1)}}
	decoded, err := decodeDocument(&configuration, model, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value, exists := decoded["image"]; !exists || value != nil {
		t.Fatalf("explicit null lost: %#v", decoded)
	}
	if _, exists := decoded["email"]; exists {
		t.Fatalf("missing field was materialized: %#v", decoded)
	}
	if !reflect.DeepEqual(decoded["unknown"], map[string]any{"n": 1}) {
		t.Fatalf("unknown field = %#v", decoded["unknown"])
	}
	selected, err := decodeDocument(&configuration, model, raw, []string{"name"})
	if err != nil || !reflect.DeepEqual(selected, storage.Record{"name": "Alice"}) {
		t.Fatalf("selected = %#v, %v", selected, err)
	}
}

func testConfig(t *testing.T, options Options) config {
	t.Helper()
	if len(options.Schema.Models) == 0 {
		schema, err := storage.CoreSchema().Merge(storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{
				"metadata": {Type: storage.FieldJSON, Required: storage.Bool(false)},
			}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		options.Schema = schema
	}
	configuration, err := normalizeOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}
