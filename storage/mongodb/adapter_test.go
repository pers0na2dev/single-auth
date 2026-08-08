package mongodb

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestAdapterCreateFindSelectAndJoin(t *testing.T) {
	now := time.Date(2026, 8, 8, 15, 0, 0, 0, time.UTC)
	configuration := testConfig(t, Options{
		IDType:      TextID,
		IDGenerator: func(string) (any, error) { return "generated", nil },
		Clock:       func() time.Time { return now },
	})
	database := newFakeDatabase()
	users := database.collection("user")
	sessions := database.collection("session")
	adapter := newAdapter(database, &fakeTransactions{}, configuration)

	input := storage.Record{
		"name": "Alice", "email": "alice@example.com", "metadata": map[string]any{"role": "admin"},
	}
	created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "user", Data: input})
	if err != nil {
		t.Fatal(err)
	}
	if created["id"] != "generated" || created["createdAt"] != now || created["emailVerified"] != false {
		t.Fatalf("created = %#v", created)
	}
	if users.insertCalls != 1 || users.lastInserted["_id"] != "generated" {
		t.Fatalf("insert = %#v", users.lastInserted)
	}
	input["metadata"].(map[string]any)["role"] = "mutated"
	if got := users.lastInserted["metadata"].(bson.M)["role"]; got != "admin" {
		t.Fatalf("insert retained caller map: %v", got)
	}

	users.findFn = func(_ context.Context, filter bson.D, options findOptions) ([]bson.M, error) {
		if !reflect.DeepEqual(filter, bson.D{{Key: "_id", Value: "generated"}}) {
			t.Fatalf("user filter = %#v", filter)
		}
		if !options.hasLimit || options.limit != 1 {
			t.Fatalf("find options = %#v", options)
		}
		return []bson.M{{"_id": "generated", "name": "Alice"}}, nil
	}
	selected, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "generated"}}, Select: []string{"name"},
	})
	if err != nil || !reflect.DeepEqual(selected, storage.Record{"name": "Alice"}) {
		t.Fatalf("selected = %#v, %v", selected, err)
	}
	if want := (bson.D{{Key: "name", Value: 1}, {Key: "_id", Value: 0}}); !reflect.DeepEqual(users.lastFind.projection, want) {
		t.Fatalf("projection = %#v, want %#v", users.lastFind.projection, want)
	}

	users.findFn = func(_ context.Context, _ bson.D, _ findOptions) ([]bson.M, error) {
		return []bson.M{{"_id": "generated", "name": "Alice"}}, nil
	}
	sessions.findFn = func(_ context.Context, filter bson.D, options findOptions) ([]bson.M, error) {
		if !reflect.DeepEqual(filter, bson.D{{Key: "userId", Value: "generated"}}) || options.limit != 100 {
			t.Fatalf("join query = %#v, %#v", filter, options)
		}
		return []bson.M{{"_id": "s1", "userId": "generated", "token": "token"}}, nil
	}
	joined, err := adapter.FindOne(t.Context(), storage.FindOneParams{Model: "user", Join: map[string]storage.JoinOption{"session": {}}})
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := joined["session"].([]storage.Record)
	if !ok || len(rows) != 1 || rows[0]["id"] != "s1" {
		t.Fatalf("join = %#v", joined["session"])
	}
}

func TestAdapterAtomicMutationShapes(t *testing.T) {
	configuration := testConfig(t, Options{IDType: TextID, IDGenerator: func(string) (any, error) { return "generated", nil }})
	database := newFakeDatabase()
	verification := database.collection("verification")
	rateLimit := database.collection("rateLimit")
	adapter := newAdapter(database, &fakeTransactions{}, configuration)

	verification.findOneAndDeleteResult = bson.M{"_id": "v1", "identifier": "once", "value": "secret"}
	consumed, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "once"}},
	})
	if err != nil || consumed["id"] != "v1" {
		t.Fatalf("consume = %#v, %v", consumed, err)
	}
	if verification.findOneAndDeleteCalls != 1 || !reflect.DeepEqual(verification.lastFilter, bson.D{{Key: "identifier", Value: "once"}}) {
		t.Fatalf("consume filter = %#v", verification.lastFilter)
	}

	rateLimit.findOneAndUpdateResult = bson.M{"_id": "r1", "key": "ip", "count": int32(4), "lastRequest": int64(100)}
	updated, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model:     "rateLimit",
		Where:     []storage.Where{{Field: "key", Value: "ip"}, {Field: "count", Operator: storage.OpLt, Value: 5}},
		Increment: map[string]float64{"count": 1},
		Set:       storage.Record{"lastRequest": 100},
	})
	if err != nil || updated["count"] != 4 {
		t.Fatalf("increment = %#v, %v", updated, err)
	}
	wantUpdate := bson.D{
		{Key: "$inc", Value: bson.M{"count": int64(1)}},
		{Key: "$set", Value: bson.M{"lastRequest": int64(100)}},
	}
	if rateLimit.findOneAndUpdateCalls != 1 || !reflect.DeepEqual(rateLimit.lastUpdate, wantUpdate) {
		t.Fatalf("atomic update = %#v, want %#v", rateLimit.lastUpdate, wantUpdate)
	}

	_, err = adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model: "rateLimit", Increment: map[string]float64{"key": 1},
	})
	if !errors.Is(err, storage.ErrInvalidIncrement) {
		t.Fatalf("non-numeric increment error = %v", err)
	}
	_, err = adapter.IncrementOne(t.Context(), storage.IncrementOneParams{Model: "rateLimit"})
	if !errors.Is(err, storage.ErrInvalidIncrement) {
		t.Fatalf("empty increment error = %v", err)
	}
}

func TestAdapterUpdateDeleteAndDuplicateError(t *testing.T) {
	configuration := testConfig(t, Options{IDType: TextID, IDGenerator: func(string) (any, error) { return "generated", nil }})
	database := newFakeDatabase()
	users := database.collection("user")
	adapter := newAdapter(database, &fakeTransactions{}, configuration)

	users.findOneAndUpdateResult = bson.M{"_id": "u1", "name": "Updated"}
	updated, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "u1"}}, Update: storage.Record{"name": "Updated"},
	})
	if err != nil || updated["name"] != "Updated" {
		t.Fatalf("update = %#v, %v", updated, err)
	}
	users.updateManyCounts = updateCounts{matched: 3, modified: 1}
	count, err := adapter.UpdateMany(t.Context(), storage.UpdateManyParams{Model: "user", Update: storage.Record{"name": "same"}})
	if err != nil || count != 3 {
		t.Fatalf("update many = %d, %v", count, err)
	}
	users.deleteManyCount = 2
	count, err = adapter.DeleteMany(t.Context(), storage.DeleteManyParams{Model: "user"})
	if err != nil || count != 2 {
		t.Fatalf("delete many = %d, %v", count, err)
	}
	if err := adapter.Delete(t.Context(), storage.DeleteParams{Model: "user"}); err != nil || users.deleteOneCalls != 0 {
		t.Fatalf("empty singular delete = %v, calls %d", err, users.deleteOneCalls)
	}

	users.insertErr = mongo.WriteException{WriteErrors: mongo.WriteErrors{{Code: 11000, Message: "duplicate key"}}}
	_, err = adapter.Create(t.Context(), storage.CreateParams{Model: "user", Data: storage.Record{"name": "A", "email": "a@example.com"}})
	if !errors.Is(err, storage.ErrUniqueConstraint) {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestAdapterTransactionBindsSessionContext(t *testing.T) {
	configuration := testConfig(t, Options{IDType: TextID, IDGenerator: func(string) (any, error) { return "generated", nil }})
	database := newFakeDatabase()
	transactions := &fakeTransactions{}
	adapter := newAdapter(database, transactions, configuration)
	users := database.collection("user")
	users.insertFn = func(ctx context.Context, document bson.M) (any, error) {
		if ctx.Value(transactionMarker{}) != true {
			t.Fatal("transaction session was not bound to operation context")
		}
		return document["_id"], nil
	}
	if err := adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
		_, err := transaction.Create(context.Background(), storage.CreateParams{
			Model: "user", Data: storage.Record{"name": "A", "email": "a@example.com"},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if transactions.calls != 1 {
		t.Fatalf("transaction calls = %d", transactions.calls)
	}

	disabledConfiguration := testConfig(t, Options{
		IDType: TextID, IDGenerator: func(string) (any, error) { return "generated", nil }, DisableTransactions: true,
	})
	disabled := newAdapter(database, nil, disabledConfiguration)
	err := disabled.Transaction(t.Context(), func(storage.TransactionAdapter) error { return nil })
	if !errors.Is(err, storage.ErrTransactionsUnsupported) || disabled.Capabilities().Transactions {
		t.Fatalf("disabled transaction = %v, capabilities %#v", err, disabled.Capabilities())
	}
}

func TestEnsureSchemaUsesDeterministicPlan(t *testing.T) {
	configuration := testConfig(t, Options{})
	database := newFakeDatabase()
	database.collectionNames = []string{"user"}
	adapter := newAdapter(database, &fakeTransactions{}, configuration)
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	wantCreated := []string{"rateLimit", "session", "account", "verification"}
	if !reflect.DeepEqual(database.createdCollections, wantCreated) {
		t.Fatalf("created collections = %v, want %v", database.createdCollections, wantCreated)
	}
	if got := database.collection("user").createdIndexes; !reflect.DeepEqual(got, []indexSpec{{
		name: "single_user_email_idx", field: "email", unique: true,
	}}) {
		t.Fatalf("user indexes = %#v", got)
	}
	if got := database.collection("session").createdIndexes; len(got) != 2 || got[0].field != "token" || got[1].field != "userId" {
		t.Fatalf("session indexes = %#v", got)
	}
}

type fakeDatabase struct {
	collections        map[string]*fakeCollection
	collectionNames    []string
	createdCollections []string
	listErr            error
	createErr          error
}

func newFakeDatabase() *fakeDatabase {
	return &fakeDatabase{collections: map[string]*fakeCollection{}}
}

func (database *fakeDatabase) collection(name string) *fakeCollection {
	if collection, exists := database.collections[name]; exists {
		return collection
	}
	collection := &fakeCollection{}
	database.collections[name] = collection
	return collection
}

func (database *fakeDatabase) Collection(name string) collectionStore {
	return database.collection(name)
}

func (database *fakeDatabase) ListCollectionNames(context.Context) ([]string, error) {
	return append([]string(nil), database.collectionNames...), database.listErr
}

func (database *fakeDatabase) CreateCollection(_ context.Context, name string) error {
	database.createdCollections = append(database.createdCollections, name)
	return database.createErr
}

type fakeCollection struct {
	insertCalls            int
	lastInserted           bson.M
	insertErr              error
	insertFn               func(context.Context, bson.M) (any, error)
	findCalls              int
	lastFilter             bson.D
	lastFind               findOptions
	findFn                 func(context.Context, bson.D, findOptions) ([]bson.M, error)
	count                  int64
	countErr               error
	findOneAndUpdateCalls  int
	findOneAndUpdateResult bson.M
	findOneAndUpdateErr    error
	lastUpdate             bson.D
	updateManyCounts       updateCounts
	updateManyErr          error
	deleteOneCalls         int
	deleteOneErr           error
	deleteManyCount        int64
	deleteManyErr          error
	findOneAndDeleteCalls  int
	findOneAndDeleteResult bson.M
	findOneAndDeleteErr    error
	createdIndexes         []indexSpec
	createIndexesErr       error
}

func (collection *fakeCollection) InsertOne(ctx context.Context, document bson.M) (any, error) {
	collection.insertCalls++
	collection.lastInserted = document
	if collection.insertFn != nil {
		return collection.insertFn(ctx, document)
	}
	return document["_id"], collection.insertErr
}

func (collection *fakeCollection) Find(ctx context.Context, filter bson.D, options findOptions) ([]bson.M, error) {
	collection.findCalls++
	collection.lastFilter = filter
	collection.lastFind = options
	if collection.findFn != nil {
		return collection.findFn(ctx, filter, options)
	}
	return []bson.M{}, nil
}

func (collection *fakeCollection) CountDocuments(context.Context, bson.D) (int64, error) {
	return collection.count, collection.countErr
}

func (collection *fakeCollection) FindOneAndUpdate(_ context.Context, filter bson.D, update bson.D) (bson.M, error) {
	collection.findOneAndUpdateCalls++
	collection.lastFilter = filter
	collection.lastUpdate = update
	if collection.findOneAndUpdateErr != nil {
		return nil, collection.findOneAndUpdateErr
	}
	if collection.findOneAndUpdateResult == nil {
		return nil, mongo.ErrNoDocuments
	}
	return collection.findOneAndUpdateResult, nil
}

func (collection *fakeCollection) UpdateMany(_ context.Context, filter bson.D, update bson.D) (updateCounts, error) {
	collection.lastFilter = filter
	collection.lastUpdate = update
	return collection.updateManyCounts, collection.updateManyErr
}

func (collection *fakeCollection) DeleteOne(_ context.Context, filter bson.D) (int64, error) {
	collection.deleteOneCalls++
	collection.lastFilter = filter
	return 1, collection.deleteOneErr
}

func (collection *fakeCollection) DeleteMany(_ context.Context, filter bson.D) (int64, error) {
	collection.lastFilter = filter
	return collection.deleteManyCount, collection.deleteManyErr
}

func (collection *fakeCollection) FindOneAndDelete(_ context.Context, filter bson.D) (bson.M, error) {
	collection.findOneAndDeleteCalls++
	collection.lastFilter = filter
	if collection.findOneAndDeleteErr != nil {
		return nil, collection.findOneAndDeleteErr
	}
	if collection.findOneAndDeleteResult == nil {
		return nil, mongo.ErrNoDocuments
	}
	return collection.findOneAndDeleteResult, nil
}

func (collection *fakeCollection) CreateIndexes(_ context.Context, specs []indexSpec) error {
	collection.createdIndexes = append(collection.createdIndexes, specs...)
	return collection.createIndexesErr
}

type transactionMarker struct{}

type fakeTransactions struct{ calls int }

func (transactions *fakeTransactions) Run(ctx context.Context, callback func(contextBinder) error) error {
	transactions.calls++
	return callback(func(operationContext context.Context) context.Context {
		return context.WithValue(operationContext, transactionMarker{}, true)
	})
}
