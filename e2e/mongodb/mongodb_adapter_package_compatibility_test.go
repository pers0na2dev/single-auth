package mongodb_e2e_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcmongodb "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/pers0na2dev/single-auth/storage"
	mongostore "github.com/pers0na2dev/single-auth/storage/mongodb"
)

const mongoPackageFixedUUID = "550e8400-e29b-41d4-a716-446655440000"

type mongoPackageOracle struct {
	Tests []mongoPackageOracleTest
}

type mongoPackageOracleTest struct {
	Suite       string
	Title       string
	Observation mongoPackageOracleObservation
}

type mongoPackageOracleObservation struct {
	AdapterFactoryDefined bool                      `json:"adapterFactoryDefined"`
	Result                *mongoPackageOracleResult `json:"result"`
	Filter                mongoPackageOracleFilter  `json:"filter"`
	Update                mongoPackageOracleUpdate  `json:"update"`
	ReturnDocument        string                    `json:"returnDocument"`
	IncludeResultMetadata bool                      `json:"includeResultMetadata"`
	HasInc                bool                      `json:"hasInc"`
	HasSet                bool                      `json:"hasSet"`
	ResultIsNull          bool                      `json:"resultIsNull"`
	Found                 bool                      `json:"found"`
	ID                    string                    `json:"id"`
	InsertedCount         int                       `json:"insertedCount"`
	IDIsBSONUUID          bool                      `json:"idIsBSONUUID"`
	IDMatchesUUID         bool                      `json:"idMatchesUUID"`
	ForeignKeyIsBSONUUID  bool                      `json:"foreignKeyIsBSONUUID"`
	ForeignKey            string                    `json:"foreignKey"`
	IDIsObjectID          bool                      `json:"idIsObjectID"`
}

type mongoPackageOracleResult struct {
	ID          string `json:"id"`
	Identifier  string `json:"identifier"`
	Count       int    `json:"count"`
	LastRequest int64  `json:"lastRequest"`
}

type mongoPackageOracleFilter struct {
	Identifier string                        `json:"identifier"`
	Key        string                        `json:"key"`
	Count      *mongoPackageOracleComparison `json:"count"`
}

type mongoPackageOracleComparison struct {
	LT int `json:"$lt"`
}

type mongoPackageOracleUpdate struct {
	Increment map[string]int64 `json:"$inc"`
	Set       map[string]int64 `json:"$set"`
}

func TestMongoDBAdapterPackageRuntimeBehavior(t *testing.T) {
	oracle := loadMongoPackageOracle(t)
	client := startMongoPackageBehaviorClient(t)
	runners := map[string]func(*testing.T, *mongo.Database, mongoPackageOracleObservation){
		"mongodb-adapter::consumeOne returns the deleted document from Mongo metadata":            runMongoConsumeOneBehavior,
		"mongodb-adapter::incrementOne applies $inc and $set atomically against the guard filter": runMongoIncrementAndSetBehavior,
		"mongodb-adapter::incrementOne omits $inc for a set-only guarded transition":              runMongoSetOnlyBehavior,
		"mongodb-adapter::incrementOne omits $set when no absolute assignments are provided":      runMongoIncrementOnlyBehavior,
		"mongodb-adapter::incrementOne returns null when the guard matches no document":           runMongoGuardMissBehavior,
		"mongodb-adapter::should create mongodb adapter":                                          runMongoAdapterCreationBehavior,
		"uuid support::should convert BSON UUID to string in output":                              runMongoUUIDOutputBehavior,
		"uuid support::should store FK fields as BSON UUID when generateId is 'uuid'":             runMongoUUIDForeignKeyBehavior,
		"uuid support::should store _id as BSON UUID when generateId is 'uuid'":                   runMongoUUIDPrimaryKeyBehavior,
		"uuid support::should store _id as ObjectId when generateId is not set":                   runMongoObjectIDPrimaryKeyBehavior,
	}
	if len(runners) != len(oracle.Tests) {
		t.Fatalf("exact MongoDB Go runners=%d, upstream tests=%d", len(runners), len(oracle.Tests))
	}

	for index, vector := range oracle.Tests {
		vector := vector
		name := vector.Suite + "::" + vector.Title
		run, exists := runners[name]
		if !exists {
			t.Fatalf("no MongoDB Go runner for %q", name)
		}
		t.Run(name, func(t *testing.T) {
			database := client.Database(fmt.Sprintf("package_behavior_%02d", index+1))
			run(t, database, vector.Observation)
		})
	}
}

func runMongoAdapterCreationBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	adapter, err := mongostore.New(database, mongostore.Options{DisableTransactions: true})
	if err != nil {
		t.Fatal(err)
	}
	if actual := adapter != nil; actual != expected.AdapterFactoryDefined {
		t.Fatalf("adapter defined=%v, want %v", actual, expected.AdapterFactoryDefined)
	}
}

func runMongoConsumeOneBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	if expected.Result == nil || !expected.IncludeResultMetadata {
		t.Fatalf("invalid consumeOne oracle: %#v", expected)
	}
	adapter := newMongoTextBehaviorAdapter(t, database)
	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "verification",
		Data: storage.Record{
			"id": expected.Result.ID, "identifier": expected.Filter.Identifier,
			"value": "one-shot", "expiresAt": time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
		},
		ForceAllowID: true,
	})
	if err != nil || created["id"] != expected.Result.ID {
		t.Fatalf("seed verification=%#v, %v", created, err)
	}
	consumed, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{
		Model: "verification",
		Where: []storage.Where{{Field: "identifier", Value: expected.Filter.Identifier}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if recordString(consumed, "id") != expected.Result.ID ||
		recordString(consumed, "identifier") != expected.Result.Identifier {
		t.Fatalf("consumeOne=%#v, want %#v", consumed, expected.Result)
	}
	remaining, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "verification",
		Where: []storage.Where{{Field: "identifier", Value: expected.Filter.Identifier}},
	})
	if err != nil || remaining != nil {
		t.Fatalf("consumed verification remains=%#v, %v", remaining, err)
	}
}

func runMongoIncrementAndSetBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	if expected.Result == nil || expected.Filter.Count == nil ||
		expected.ReturnDocument != "after" || !expected.IncludeResultMetadata {
		t.Fatalf("invalid increment-and-set oracle: %#v", expected)
	}
	increment := expected.Update.Increment["count"]
	lastRequest := expected.Update.Set["lastRequest"]
	adapter := newMongoTextBehaviorAdapter(t, database)
	seedMongoRateLimit(t, adapter, expected.Result.ID, "combined", expected.Result.Count-int(increment), 1)
	updated, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model:     "rateLimit",
		Where:     []storage.Where{{Field: "count", Operator: storage.OpLt, Value: expected.Filter.Count.LT}},
		Increment: map[string]float64{"count": float64(increment)},
		Set:       storage.Record{"lastRequest": lastRequest},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMongoRateLimitResult(t, updated, expected.Result.ID, expected.Result.Count, expected.Result.LastRequest)
	persisted := findMongoRateLimit(t, adapter, expected.Result.ID)
	assertMongoRateLimitResult(t, persisted, expected.Result.ID, expected.Result.Count, expected.Result.LastRequest)
}

func runMongoSetOnlyBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	if expected.Result == nil || expected.HasInc || !expected.HasSet || len(expected.Update.Increment) != 0 {
		t.Fatalf("invalid set-only oracle: %#v", expected)
	}
	adapter := newMongoTextBehaviorAdapter(t, database)
	seedMongoRateLimit(t, adapter, expected.Result.ID, expected.Filter.Key, 7, 1)
	updated, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model:     "rateLimit",
		Where:     []storage.Where{{Field: "key", Value: expected.Filter.Key}},
		Increment: map[string]float64{},
		Set:       storage.Record{"lastRequest": expected.Update.Set["lastRequest"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if recordString(updated, "id") != expected.Result.ID ||
		recordInt64(updated, "lastRequest") != expected.Result.LastRequest || recordInt(updated, "count") != 7 {
		t.Fatalf("set-only result=%#v, want %#v with count unchanged", updated, expected.Result)
	}
}

func runMongoIncrementOnlyBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	if expected.Result == nil || !expected.HasInc || expected.HasSet || len(expected.Update.Set) != 0 {
		t.Fatalf("invalid increment-only oracle: %#v", expected)
	}
	increment := expected.Update.Increment["count"]
	adapter := newMongoTextBehaviorAdapter(t, database)
	seedMongoRateLimit(t, adapter, expected.Result.ID, expected.Filter.Key, expected.Result.Count-int(increment), 9)
	updated, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model:     "rateLimit",
		Where:     []storage.Where{{Field: "key", Value: expected.Filter.Key}},
		Increment: map[string]float64{"count": float64(increment)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if recordString(updated, "id") != expected.Result.ID || recordInt(updated, "count") != expected.Result.Count ||
		recordInt64(updated, "lastRequest") != 9 {
		t.Fatalf("increment-only result=%#v, want %#v with lastRequest unchanged", updated, expected.Result)
	}
}

func runMongoGuardMissBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	if !expected.ResultIsNull || expected.Filter.Count == nil {
		t.Fatalf("invalid guard-miss oracle: %#v", expected)
	}
	adapter := newMongoTextBehaviorAdapter(t, database)
	seedMongoRateLimit(t, adapter, "guard-miss", "guard-miss", expected.Filter.Count.LT, 3)
	updated, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model:     "rateLimit",
		Where:     []storage.Where{{Field: "count", Operator: storage.OpLt, Value: expected.Filter.Count.LT}},
		Increment: map[string]float64{"count": 1},
	})
	if err != nil || updated != nil {
		t.Fatalf("guard miss=%#v, %v; want nil", updated, err)
	}
	persisted := findMongoRateLimit(t, adapter, "guard-miss")
	if recordInt(persisted, "count") != expected.Filter.Count.LT {
		t.Fatalf("guard-miss row mutated: %#v", persisted)
	}
}

func runMongoUUIDPrimaryKeyBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	adapter := newMongoUUIDBehaviorAdapter(t, database)
	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "user",
		Data:  storage.Record{"name": "Test", "email": "test@test.com", "emailVerified": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := findRawMongoDocument(t, database.Collection("user"), bson.D{})
	binary, isUUID := raw["_id"].(bson.Binary)
	actualMatches := isUUID && binary.Subtype == 4 && uuidTextPattern.MatchString(recordString(created, "id"))
	if expected.InsertedCount != 1 || isUUID != expected.IDIsBSONUUID || actualMatches != expected.IDMatchesUUID {
		t.Fatalf("UUID primary key=%#v, created=%#v, want %#v", raw["_id"], created, expected)
	}
}

func runMongoUUIDForeignKeyBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	adapter := newMongoUUIDBehaviorAdapter(t, database)
	_, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "session",
		Data: storage.Record{
			"userId": expected.ForeignKey, "token": "test-token",
			"expiresAt": time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := findRawMongoDocument(t, database.Collection("session"), bson.D{})
	primary, primaryOK := raw["_id"].(bson.Binary)
	foreign, foreignOK := raw["userId"].(bson.Binary)
	actualForeign := ""
	if foreignOK && foreign.Subtype == 4 {
		actualForeign = formatMongoUUID(foreign.Data)
	}
	if expected.InsertedCount != 1 ||
		(primaryOK && primary.Subtype == 4) != expected.IDIsBSONUUID ||
		(foreignOK && foreign.Subtype == 4) != expected.ForeignKeyIsBSONUUID ||
		actualForeign != expected.ForeignKey {
		t.Fatalf("UUID FK raw=%#v, want %#v", raw, expected)
	}
}

func runMongoObjectIDPrimaryKeyBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	adapter, err := mongostore.New(database, mongostore.Options{DisableTransactions: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Create(t.Context(), storage.CreateParams{
		Model: "user",
		Data:  storage.Record{"name": "Test", "email": "test@test.com", "emailVerified": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := findRawMongoDocument(t, database.Collection("user"), bson.D{})
	_, isObjectID := raw["_id"].(bson.ObjectID)
	if expected.InsertedCount != 1 || isObjectID != expected.IDIsObjectID {
		t.Fatalf("ObjectID primary key=%#v, want %#v", raw["_id"], expected)
	}
}

func runMongoUUIDOutputBehavior(t *testing.T, database *mongo.Database, expected mongoPackageOracleObservation) {
	t.Helper()
	data, err := hex.DecodeString(strings.ReplaceAll(expected.ID, "-", ""))
	if err != nil || len(data) != 16 {
		t.Fatalf("invalid frozen UUID %q: %v", expected.ID, err)
	}
	_, err = database.Collection("user").InsertOne(t.Context(), bson.M{
		"_id": bson.Binary{Subtype: 4, Data: data}, "name": "Test", "email": "test@test.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := newMongoUUIDBehaviorAdapter(t, database)
	result, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: expected.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	actualFound := result != nil
	if actualFound != expected.Found || recordString(result, "id") != expected.ID {
		t.Fatalf("decoded UUID=%#v, want found=%v id=%q", result, expected.Found, expected.ID)
	}
}

func newMongoTextBehaviorAdapter(t *testing.T, database *mongo.Database) *mongostore.Adapter {
	t.Helper()
	adapter, err := mongostore.New(database, mongostore.Options{
		IDType: mongostore.TextID,
		IDGenerator: func(model string) (any, error) {
			return model + "-generated", nil
		},
		DisableTransactions: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func newMongoUUIDBehaviorAdapter(t *testing.T, database *mongo.Database) *mongostore.Adapter {
	t.Helper()
	adapter, err := mongostore.New(database, mongostore.Options{
		IDType: mongostore.UUIDID, DisableTransactions: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func seedMongoRateLimit(t *testing.T, adapter *mongostore.Adapter, id, key string, count int, lastRequest int64) {
	t.Helper()
	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "rateLimit",
		Data: storage.Record{
			"id": id, "key": key, "count": count, "lastRequest": lastRequest,
		},
		ForceAllowID: true,
	})
	if err != nil || recordString(created, "id") != id {
		t.Fatalf("seed rate limit=%#v, %v", created, err)
	}
}

func findMongoRateLimit(t *testing.T, adapter *mongostore.Adapter, id string) storage.Record {
	t.Helper()
	record, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "rateLimit", Where: []storage.Where{{Field: "id", Value: id}},
	})
	if err != nil || record == nil {
		t.Fatalf("find rate limit %q=%#v, %v", id, record, err)
	}
	return record
}

func assertMongoRateLimitResult(t *testing.T, record storage.Record, id string, count int, lastRequest int64) {
	t.Helper()
	if recordString(record, "id") != id || recordInt(record, "count") != count ||
		recordInt64(record, "lastRequest") != lastRequest {
		t.Fatalf("rate-limit result=%#v, want id=%q count=%d lastRequest=%d", record, id, count, lastRequest)
	}
}

func findRawMongoDocument(t *testing.T, collection *mongo.Collection, filter bson.D) bson.M {
	t.Helper()
	var document bson.M
	if err := collection.FindOne(t.Context(), filter).Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document
}

func recordString(record storage.Record, field string) string {
	if record == nil {
		return ""
	}
	value, _ := record[field].(string)
	return value
}

func recordInt(record storage.Record, field string) int {
	if record == nil {
		return 0
	}
	switch value := record[field].(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func recordInt64(record storage.Record, field string) int64 {
	if record == nil {
		return 0
	}
	switch value := record[field].(type) {
	case int:
		return int64(value)
	case int32:
		return int64(value)
	case int64:
		return value
	case float64:
		return int64(value)
	default:
		return 0
	}
}

var uuidTextPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func formatMongoUUID(data []byte) string {
	if len(data) != 16 {
		return ""
	}
	encoded := hex.EncodeToString(data)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func startMongoPackageBehaviorClient(t *testing.T) *mongo.Client {
	t.Helper()
	container, err := tcmongodb.Run(
		t.Context(),
		mongoImage,
		tcmongodb.WithReplicaSet("single-package-behavior-rs"),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required MongoDB package-behavior replica set: %v", err)
		}
		t.Skipf("Docker is unavailable for local MongoDB package behavior: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("MongoDB package-behavior container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate MongoDB package-behavior container: %v", terminateErr)
		}
	})

	connectionString, err := container.ConnectionString(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	client, err := mongo.Connect(options.Client().ApplyURI(connectionString).SetServerSelectionTimeout(15 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if disconnectErr := client.Disconnect(context.Background()); disconnectErr != nil {
			t.Errorf("disconnect MongoDB package-behavior client: %v", disconnectErr)
		}
	})
	if err := client.Ping(t.Context(), nil); err != nil {
		t.Fatalf("ping MongoDB package-behavior replica set: %v", err)
	}
	return client
}

func loadMongoPackageOracle(t *testing.T) mongoPackageOracle {
	t.Helper()
	oracle := mongoPackageOracle{Tests: mongoPackageScenarios}
	if len(oracle.Tests) != 10 {
		t.Fatalf("MongoDB package scenarios=%d, want 10", len(oracle.Tests))
	}
	seen := make(map[string]struct{}, len(oracle.Tests))
	for _, vector := range oracle.Tests {
		if vector.Suite == "" || vector.Title == "" {
			t.Fatalf("invalid MongoDB package scenario: %#v", vector)
		}
		key := vector.Suite + "::" + vector.Title
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate MongoDB package scenario %q", key)
		}
		seen[key] = struct{}{}
	}
	return oracle
}
