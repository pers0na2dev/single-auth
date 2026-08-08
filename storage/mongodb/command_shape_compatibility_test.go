package mongodb

import (
	"reflect"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/pers0na2dev/single-auth/storage"
)

// TestMongoDBAdapterCommandShapeBehavior complements the real MongoDB
// E2E suite with the exact command-shape assertions made by the upstream mock
// tests. In particular, it prevents empty $inc/$set operators from reaching
// older MongoDB servers even though current servers accept some empty updates.
func TestMongoDBAdapterCommandShapeBehavior(t *testing.T) {
	t.Run("consumeOne returns the deleted document from Mongo metadata", func(t *testing.T) {
		adapter, database := newMongoCommandShapeAdapter(t)
		collection := database.collection("verification")
		collection.findOneAndDeleteResult = bson.M{
			"_id": "verification-id", "identifier": "magic-link-token",
		}
		result, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{
			Model: "verification",
			Where: []storage.Where{{Field: "identifier", Value: "magic-link-token"}},
		})
		if err != nil || result["id"] != "verification-id" || result["identifier"] != "magic-link-token" {
			t.Fatalf("consumeOne=%#v, %v", result, err)
		}
		wantFilter := bson.D{{Key: "identifier", Value: "magic-link-token"}}
		if !reflect.DeepEqual(collection.lastFilter, wantFilter) {
			t.Fatalf("consumeOne filter=%#v, want %#v", collection.lastFilter, wantFilter)
		}
	})

	t.Run("incrementOne applies $inc and $set atomically against the guard filter", func(t *testing.T) {
		adapter, database := newMongoCommandShapeAdapter(t)
		collection := database.collection("rateLimit")
		collection.findOneAndUpdateResult = bson.M{
			"_id": "counter-id", "count": int64(4), "lastRequest": int64(1700000000000),
		}
		result, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
			Model:     "rateLimit",
			Where:     []storage.Where{{Field: "count", Value: 5, Operator: storage.OpLt}},
			Increment: map[string]float64{"count": 1},
			Set:       storage.Record{"lastRequest": int64(1700000000000)},
		})
		if err != nil || result["id"] != "counter-id" || result["count"] != 4 {
			t.Fatalf("combined increment=%#v, %v", result, err)
		}
		wantFilter := bson.D{{Key: "count", Value: bson.D{{Key: "$lt", Value: int64(5)}}}}
		wantUpdate := bson.D{
			{Key: "$inc", Value: bson.M{"count": int64(1)}},
			{Key: "$set", Value: bson.M{"lastRequest": int64(1700000000000)}},
		}
		if !reflect.DeepEqual(collection.lastFilter, wantFilter) || !reflect.DeepEqual(collection.lastUpdate, wantUpdate) {
			t.Fatalf("combined command filter=%#v update=%#v, want %#v %#v", collection.lastFilter, collection.lastUpdate, wantFilter, wantUpdate)
		}
	})

	t.Run("incrementOne omits $set when no absolute assignments are provided", func(t *testing.T) {
		adapter, database := newMongoCommandShapeAdapter(t)
		collection := database.collection("rateLimit")
		collection.findOneAndUpdateResult = bson.M{"_id": "counter-id", "count": int64(11)}
		_, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
			Model:     "rateLimit",
			Where:     []storage.Where{{Field: "key", Value: "a"}},
			Increment: map[string]float64{"count": 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		want := bson.D{{Key: "$inc", Value: bson.M{"count": int64(1)}}}
		if !reflect.DeepEqual(collection.lastUpdate, want) {
			t.Fatalf("increment-only update=%#v, want %#v", collection.lastUpdate, want)
		}
	})

	t.Run("incrementOne omits $inc for a set-only guarded transition", func(t *testing.T) {
		adapter, database := newMongoCommandShapeAdapter(t)
		collection := database.collection("rateLimit")
		collection.findOneAndUpdateResult = bson.M{
			"_id": "counter-id", "lastRequest": int64(1700000000000),
		}
		_, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
			Model:     "rateLimit",
			Where:     []storage.Where{{Field: "key", Value: "a"}},
			Increment: map[string]float64{},
			Set:       storage.Record{"lastRequest": int64(1700000000000)},
		})
		if err != nil {
			t.Fatal(err)
		}
		want := bson.D{{Key: "$set", Value: bson.M{"lastRequest": int64(1700000000000)}}}
		if !reflect.DeepEqual(collection.lastUpdate, want) {
			t.Fatalf("set-only update=%#v, want %#v", collection.lastUpdate, want)
		}
	})

	t.Run("incrementOne returns null when the guard matches no document", func(t *testing.T) {
		adapter, database := newMongoCommandShapeAdapter(t)
		result, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
			Model:     "rateLimit",
			Where:     []storage.Where{{Field: "count", Value: 5, Operator: storage.OpLt}},
			Increment: map[string]float64{"count": 1},
		})
		if err != nil || result != nil {
			t.Fatalf("guard miss=%#v, %v; want nil", result, err)
		}
		wantFilter := bson.D{{Key: "count", Value: bson.D{{Key: "$lt", Value: int64(5)}}}}
		if actual := database.collection("rateLimit").lastFilter; !reflect.DeepEqual(actual, wantFilter) {
			t.Fatalf("guard filter=%#v, want %#v", actual, wantFilter)
		}
	})
}

func newMongoCommandShapeAdapter(t *testing.T) (*Adapter, *fakeDatabase) {
	t.Helper()
	configuration := testConfig(t, Options{
		IDType: TextID,
		IDGenerator: func(string) (any, error) {
			return "generated", nil
		},
	})
	database := newFakeDatabase()
	return newAdapter(database, &fakeTransactions{}, configuration), database
}
