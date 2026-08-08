package mongodb

import (
	"errors"
	"reflect"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestBuildWhereGroupsANDAndORConnectors(t *testing.T) {
	configuration := testConfig(t, Options{IDType: TextID, IDGenerator: func(string) (any, error) { return "generated", nil }})
	model, err := resolveModel(&configuration, "user")
	if err != nil {
		t.Fatal(err)
	}
	filter, err := buildWhere(&configuration, model, []storage.Where{
		{Field: "name", Value: "Alice", Mode: storage.Insensitive},
		{Field: "email", Value: "example.com", Operator: storage.OpEndsWith},
		{Field: "emailVerified", Value: true, Connector: storage.Or},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := bson.D{
		{Key: "$and", Value: bson.A{
			bson.D{{Key: "name", Value: bson.Regex{Pattern: "^Alice$", Options: "i"}}},
			bson.D{{Key: "email", Value: bson.Regex{Pattern: "example\\.com$"}}},
		}},
		{Key: "$or", Value: bson.A{
			bson.D{{Key: "emailVerified", Value: true}},
		}},
	}
	if !reflect.DeepEqual(filter, want) {
		t.Fatalf("filter = %#v\nwant   = %#v", filter, want)
	}
}

func TestBuildWhereEscapesRegexAndEncodesObjectIDs(t *testing.T) {
	configuration := testConfig(t, Options{IDType: ObjectID})
	model, err := resolveModel(&configuration, "user")
	if err != nil {
		t.Fatal(err)
	}
	const identifier = "507f1f77bcf86cd799439011"
	filter, err := buildWhere(&configuration, model, []storage.Where{
		{Field: "id", Value: identifier},
		{Field: "name", Value: "a.*(b)", Operator: storage.OpContains},
	})
	if err != nil {
		t.Fatal(err)
	}
	objectID, _ := bson.ObjectIDFromHex(identifier)
	want := bson.D{{Key: "$and", Value: bson.A{
		bson.D{{Key: "_id", Value: objectID}},
		bson.D{{Key: "name", Value: bson.Regex{Pattern: `a\.\*\(b\)`}}},
	}}}
	if !reflect.DeepEqual(filter, want) {
		t.Fatalf("filter = %#v\nwant   = %#v", filter, want)
	}
}

func TestBuildWhereNotInNullExcludesMissing(t *testing.T) {
	configuration := testConfig(t, Options{IDType: TextID, IDGenerator: func(string) (any, error) { return "generated", nil }})
	model, _ := resolveModel(&configuration, "user")
	filter, err := buildWhere(&configuration, model, []storage.Where{{
		Field: "image", Operator: storage.OpNotIn, Value: []any{nil, "blocked"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := bson.D{{Key: "$and", Value: bson.A{
		bson.D{{Key: "image", Value: bson.D{{Key: "$exists", Value: true}}}},
		bson.D{{Key: "image", Value: bson.D{{Key: "$ne", Value: nil}}}},
		bson.D{{Key: "image", Value: bson.D{{Key: "$nin", Value: bson.A{"blocked"}}}}},
	}}}
	if !reflect.DeepEqual(filter, want) {
		t.Fatalf("filter = %#v\nwant   = %#v", filter, want)
	}
}

func TestBuildWhereValidation(t *testing.T) {
	configuration := testConfig(t, Options{})
	model, _ := resolveModel(&configuration, "user")
	_, err := buildWhere(&configuration, model, []storage.Where{{
		Field: "email", Operator: storage.OpIn, Value: "not-an-array",
	}})
	if !errors.Is(err, storage.ErrInvalidQuery) {
		t.Fatalf("error = %v", err)
	}
	_, err = buildSort(&configuration, model, &storage.Sort{Field: "email", Direction: "sideways"})
	if !errors.Is(err, storage.ErrInvalidQuery) {
		t.Fatalf("sort error = %v", err)
	}
}
