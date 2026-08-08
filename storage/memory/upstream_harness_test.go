package memory_test

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type memoryBehaviorHarness struct {
	adapter *memory.Adapter
	profile string
	now     time.Time
}

func newMemoryBehaviorHarness(t *testing.T, vector memoryAdapterVector) *memoryBehaviorHarness {
	t.Helper()
	schema := memoryBehaviorSchema()
	if strings.Contains(vector.Scenario, "modified field name") {
		user := schema.Models["user"]
		email := user.Fields["email"]
		email.FieldName = "email_address"
		user.Fields["email"] = email
		schema.Models["user"] = user
	}
	if strings.Contains(vector.Scenario, "modified model name") ||
		strings.Contains(vector.Scenario, "users-table join") {
		user := schema.Models["user"]
		user.ModelName = "user_table"
		schema.Models["user"] = user
	}
	if strings.Contains(vector.Scenario, "join a model with modified field name") {
		session := schema.Models["session"]
		userID := session.Fields["userId"]
		userID.FieldName = "user_id"
		session.Fields["userId"] = userID
		schema.Models["session"] = session
	}

	serial := 0
	generator := func(string) (any, error) {
		serial++
		switch vector.Profile {
		case "number-id":
			return serial, nil
		case "uuid":
			return fmt.Sprintf("00000000-0000-4000-8000-%012x", serial), nil
		default:
			return fmt.Sprintf("generated-%s-%03d", vector.Profile, serial), nil
		}
	}
	now := time.Date(2026, 8, 9, 9, 30, 0, 0, time.UTC)
	adapter, err := memory.New(
		memory.WithSchema(schema),
		memory.WithClock(func() time.Time { return now }),
		memory.WithIDGenerator(generator),
		memory.WithDefaultFindManyLimit(100),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &memoryBehaviorHarness{adapter: adapter, profile: vector.Profile, now: now}
}

func memoryBehaviorSchema() storage.Schema {
	optional := storage.Bool(false)
	schema, err := storage.CoreSchema().Merge(storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"rank":           {Type: storage.FieldNumber, Required: optional, Sortable: true},
			"numericField":   {Type: storage.FieldNumber, Required: optional, Sortable: true},
			"active":         {Type: storage.FieldBoolean, Required: optional},
			"city":           {Type: storage.FieldString, Required: optional},
			"tag":            {Type: storage.FieldString, Required: optional},
			"metadata":       {Type: storage.FieldJSON, Required: optional},
			"stringArray":    {Type: storage.FieldStringArray, Required: optional},
			"numberArray":    {Type: storage.FieldNumberArray, Required: optional},
			"dateField":      {Type: storage.FieldDate, Required: optional},
			"customField":    {Type: storage.FieldString, Required: optional, DefaultValue: storage.StaticValue("default-value")},
			"testField":      {Type: storage.FieldString, Required: optional, DefaultValue: storage.StaticValue("test-value")},
			"cbDefaultValue": {Type: storage.FieldString, Required: optional, DefaultValue: storage.StaticValue("advanced-test-value")},
		}},
		"testModel": {
			ModelName: "testModel",
			Fields: map[string]storage.FieldAttribute{
				"nullableReference": {Type: storage.FieldString, Required: optional, References: &storage.Reference{Model: "user", Field: "id"}},
				"testField":         {Type: storage.FieldString, Required: optional, DefaultValue: storage.StaticValue("test-value")},
				"cbDefaultValue":    {Type: storage.FieldString, Required: optional, DefaultValue: storage.StaticValue("advanced-test-value")},
				"stringArray":       {Type: storage.FieldStringArray, Required: optional},
				"numberArray":       {Type: storage.FieldNumberArray, Required: optional},
				"json":              {Type: storage.FieldJSON, Required: optional},
			},
		},
		"oneToOneTable": {
			ModelName: "oneToOneTable",
			Fields: map[string]storage.FieldAttribute{
				"oneToOne": {Type: storage.FieldString, Unique: true, References: &storage.Reference{Model: "user", Field: "id"}},
				"label":    {Type: storage.FieldString, Required: optional},
			},
		},
	}})
	if err != nil {
		panic(err)
	}
	return schema
}

func (h *memoryBehaviorHarness) id(index int) string {
	switch h.profile {
	case "number-id":
		return fmt.Sprintf("%d", index)
	case "uuid":
		return fmt.Sprintf("10000000-0000-4000-8000-%012x", index)
	default:
		return fmt.Sprintf("id-%03d", index)
	}
}

func (h *memoryBehaviorHarness) user(t *testing.T, index int, values storage.Record) storage.Record {
	t.Helper()
	createdAt := h.now.Add(time.Duration(index) * time.Minute)
	record := storage.Record{
		"id": h.id(index), "name": fmt.Sprintf("user-%02d", index),
		"email": fmt.Sprintf("user-%02d@email.com", index), "emailVerified": index%2 == 0,
		"rank": index, "numericField": index, "active": index%2 == 0,
		"createdAt": createdAt, "updatedAt": createdAt,
	}
	for key, value := range values {
		record[key] = value
	}
	return mustMemoryCreate(t, h.adapter, "user", record, true)
}

func (h *memoryBehaviorHarness) session(t *testing.T, index int, userID string) storage.Record {
	t.Helper()
	return mustMemoryCreate(t, h.adapter, "session", storage.Record{
		"id": h.id(1000 + index), "userId": userID,
		"token": fmt.Sprintf("token-%03d", index), "expiresAt": h.now.Add(time.Hour),
	}, true)
}

func (h *memoryBehaviorHarness) account(t *testing.T, index int, userID string) storage.Record {
	t.Helper()
	return mustMemoryCreate(t, h.adapter, "account", storage.Record{
		"id": h.id(2000 + index), "userId": userID,
		"accountId": fmt.Sprintf("account-%03d", index), "providerId": "test",
	}, true)
}

func (h *memoryBehaviorHarness) oneToOne(t *testing.T, index int, userID string) storage.Record {
	t.Helper()
	return mustMemoryCreate(t, h.adapter, "oneToOneTable", storage.Record{
		"id": h.id(3000 + index), "oneToOne": userID, "label": fmt.Sprintf("profile-%03d", index),
	}, true)
}

func mustMemoryCreate(t *testing.T, adapter storage.TransactionAdapter, model string, data storage.Record, forceID bool) storage.Record {
	t.Helper()
	record, err := adapter.Create(t.Context(), storage.CreateParams{Model: model, Data: data, ForceAllowID: forceID})
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatalf("create %s returned nil", model)
	}
	return record
}

func mustMemoryFindOne(t *testing.T, adapter storage.TransactionAdapter, params storage.FindOneParams) storage.Record {
	t.Helper()
	record, err := adapter.FindOne(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func mustMemoryFindMany(t *testing.T, adapter storage.TransactionAdapter, params storage.FindManyParams) []storage.Record {
	t.Helper()
	records, err := adapter.FindMany(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func memoryRecordIDs(records []storage.Record) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, fmt.Sprint(record["id"]))
	}
	return ids
}

func sortedMemoryRecordIDs(records []storage.Record) []string {
	ids := memoryRecordIDs(records)
	sort.Strings(ids)
	return ids
}

func requireMemoryIDs(t *testing.T, records []storage.Record, want ...string) {
	t.Helper()
	got := sortedMemoryRecordIDs(records)
	wanted := append([]string(nil), want...)
	sort.Strings(wanted)
	if !reflect.DeepEqual(got, wanted) {
		t.Fatalf("record IDs = %v, want %v; records=%#v", got, wanted, records)
	}
}

func requireMemoryField(t *testing.T, record storage.Record, field string, want any) {
	t.Helper()
	if record == nil {
		t.Fatalf("record is nil; want %s=%#v", field, want)
	}
	if got := record[field]; !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %#v (%T), want %#v (%T); record=%#v", field, got, got, want, want, record)
	}
}
