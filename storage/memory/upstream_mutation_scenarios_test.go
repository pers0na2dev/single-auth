package memory_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func runMemoryInitScenario(t *testing.T, harness *memoryBehaviorHarness, vector memoryAdapterVector, description string) {
	t.Helper()
	if description != "tests" {
		t.Fatalf("unsupported init scenario %q", description)
	}
	created, err := harness.adapter.Create(t.Context(), storage.CreateParams{
		Model: "testModel", Data: storage.Record{},
	})
	if err != nil {
		t.Fatal(err)
	}
	id, ok := created["id"].(string)
	if !ok || id == "" {
		t.Fatalf("generated ID = %#v", created["id"])
	}
	switch vector.Profile {
	case "number-id":
		if id != "1" {
			t.Fatalf("serial ID = %q, want 1", id)
		}
	case "uuid":
		if !uuidPattern.MatchString(id) {
			t.Fatalf("UUID ID = %q", id)
		}
	case "joins":
		if !harness.adapter.Capabilities().Joins {
			t.Fatal("join profile does not advertise joins")
		}
	default:
		if id == "1" || uuidPattern.MatchString(id) {
			t.Fatalf("normal profile unexpectedly used serial/UUID ID %q", id)
		}
	}
}

func supportsMemoryCreateScenario(description string) bool {
	switch description {
	case "should create a model", "should always return an id", "should use generateId if provided",
		"should return null for nullable foreign keys", "should apply default values to fields",
		"should support arrays", "should support json", "should return a number id", "should return a uuid":
		return true
	default:
		return false
	}
}

func runMemoryCreateScenario(t *testing.T, harness *memoryBehaviorHarness, _ memoryAdapterVector, description string) {
	t.Helper()
	switch description {
	case "should create a model":
		created := harness.user(t, 1, storage.Record{"image": "avatar.png"})
		requireMemoryField(t, created, "id", harness.id(1))
		requireMemoryField(t, created, "email", "user-01@email.com")
		requireMemoryField(t, created, "image", "avatar.png")
	case "should always return an id", "should use generateId if provided":
		created, err := harness.adapter.Create(t.Context(), storage.CreateParams{Model: "testModel", Data: storage.Record{}})
		if err != nil {
			t.Fatal(err)
		}
		id, ok := created["id"].(string)
		if !ok || id == "" {
			t.Fatalf("generated ID = %#v", created["id"])
		}
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "testModel", Where: []storage.Where{{Field: "id", Value: id}}})
		requireMemoryField(t, found, "id", id)
	case "should return null for nullable foreign keys":
		created := mustMemoryCreate(t, harness.adapter, "testModel", storage.Record{"nullableReference": nil}, false)
		value, exists := created["nullableReference"]
		if !exists || value != nil {
			t.Fatalf("nullableReference = %#v, exists=%v", value, exists)
		}
	case "should apply default values to fields":
		model := mustMemoryCreate(t, harness.adapter, "testModel", storage.Record{}, false)
		requireMemoryField(t, model, "testField", "test-value")
		requireMemoryField(t, model, "cbDefaultValue", "advanced-test-value")
		user := harness.user(t, 1, nil)
		requireMemoryField(t, user, "testField", "test-value")
		requireMemoryField(t, user, "cbDefaultValue", "advanced-test-value")
	case "should support arrays":
		stringsValue := []string{"1", "2", "3"}
		numbersValue := []int{1, 2, 3}
		created := mustMemoryCreate(t, harness.adapter, "testModel", storage.Record{
			"stringArray": stringsValue, "numberArray": numbersValue,
		}, false)
		if !reflect.DeepEqual(created["stringArray"], stringsValue) || !reflect.DeepEqual(created["numberArray"], numbersValue) {
			t.Fatalf("array round-trip = %#v", created)
		}
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "testModel", Where: []storage.Where{{Field: "id", Value: created["id"]}}})
		if !reflect.DeepEqual(found, created) {
			t.Fatalf("array persisted = %#v, want %#v", found, created)
		}
	case "should support json":
		jsonValue := map[string]any{"foo": "bar", "nested": map[string]any{"enabled": true}}
		created := mustMemoryCreate(t, harness.adapter, "testModel", storage.Record{"json": jsonValue}, false)
		if !reflect.DeepEqual(created["json"], jsonValue) {
			t.Fatalf("JSON round-trip = %#v", created["json"])
		}
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "testModel", Where: []storage.Where{{Field: "id", Value: created["id"]}}})
		if !reflect.DeepEqual(found, created) {
			t.Fatalf("JSON persisted = %#v, want %#v", found, created)
		}
	case "should return a number id":
		created := mustMemoryCreate(t, harness.adapter, "testModel", storage.Record{}, false)
		id, ok := created["id"].(string)
		if !ok || id != "1" {
			t.Fatalf("serial output ID = %#v", created["id"])
		}
	case "should return a uuid":
		created := mustMemoryCreate(t, harness.adapter, "testModel", storage.Record{}, false)
		id, ok := created["id"].(string)
		if !ok || !uuidPattern.MatchString(id) {
			t.Fatalf("UUID output ID = %#v", created["id"])
		}
	default:
		t.Fatalf("unsupported create scenario %q", description)
	}
}

func supportsMemoryCountScenario(description string) bool {
	switch description {
	case "should count many models", "should count with where clause", "should return 0 with no rows to count", "with mode insensitive":
		return true
	default:
		return false
	}
}

func runMemoryCountScenario(t *testing.T, harness *memoryBehaviorHarness, description string) {
	t.Helper()
	var where []storage.Where
	want := int64(0)
	switch description {
	case "should return 0 with no rows to count":
	case "should count many models":
		for index := 1; index <= 15; index++ {
			harness.user(t, index, nil)
		}
		want = 15
	case "should count with where clause":
		for index := 1; index <= 15; index++ {
			harness.user(t, index, nil)
		}
		where = []storage.Where{
			{Field: "id", Value: harness.id(3), Connector: storage.Or},
			{Field: "id", Value: harness.id(4), Connector: storage.Or},
		}
		want = 2
	case "with mode insensitive":
		harness.user(t, 1, storage.Record{"email": "CountTest@Case.INSENSITIVE"})
		where = []storage.Where{{Field: "email", Value: "counttest@case.insensitive", Mode: storage.Insensitive}}
		want = 1
	default:
		t.Fatalf("unsupported count scenario %q", description)
	}
	count, err := harness.adapter.Count(t.Context(), storage.CountParams{Model: "user", Where: where})
	if err != nil || count != want {
		t.Fatalf("count = %d, want %d, err=%v", count, want, err)
	}
}

func supportsMemoryUpdateScenario(description string) bool {
	switch description {
	case "should update a model", "should return null when where is empty",
		"should correctly return record when updating a field used in where clause",
		"should handle updating multiple fields including where clause field",
		"should work when updated field is not in where clause",
		"should support multiple where conditions under AND connector with unique field",
		"should return updated record when where condition uses null value",
		"should return null when a multi-predicate where matches no row", "where with mode insensitive":
		return true
	default:
		return false
	}
}

func runMemoryUpdateScenario(t *testing.T, harness *memoryBehaviorHarness, description string) {
	t.Helper()
	user := harness.user(t, 1, nil)
	params := storage.UpdateParams{Model: "user"}
	switch description {
	case "should update a model":
		params.Where = []storage.Where{{Field: "id", Value: user["id"]}}
		params.Update = storage.Record{"name": "test-name"}
	case "should return null when where is empty":
		params.Update = storage.Record{"name": "test-name"}
	case "should correctly return record when updating a field used in where clause":
		params.Where = []storage.Where{{Field: "email", Value: user["email"]}}
		params.Update = storage.Record{"email": "newemail@example.com"}
	case "should handle updating multiple fields including where clause field":
		params.Where = []storage.Where{{Field: "email", Value: user["email"]}}
		params.Update = storage.Record{"email": "updated@example.com", "name": "Updated Name", "emailVerified": true}
	case "should work when updated field is not in where clause":
		params.Where = []storage.Where{{Field: "email", Value: user["email"]}}
		params.Update = storage.Record{"name": "Updated Name Only"}
	case "should support multiple where conditions under AND connector with unique field":
		params.Where = []storage.Where{{Field: "email", Value: user["email"]}, {Field: "id", Value: user["id"]}}
		params.Update = storage.Record{"name": "Updated Name"}
	case "should return updated record when where condition uses null value":
		if _, err := harness.adapter.Update(t.Context(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}}, Update: storage.Record{"image": nil},
		}); err != nil {
			t.Fatal(err)
		}
		params.Where = []storage.Where{{Field: "id", Value: user["id"]}, {Field: "image", Value: nil}}
		params.Update = storage.Record{"name": "null-where-updated"}
	case "should return null when a multi-predicate where matches no row":
		winner, err := harness.adapter.Update(t.Context(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}, {Field: "emailVerified", Value: user["emailVerified"]}},
			Update: storage.Record{"emailVerified": !user["emailVerified"].(bool)},
		})
		if err != nil || winner == nil {
			t.Fatalf("guard winner = %#v, err=%v", winner, err)
		}
		loser, err := harness.adapter.Update(t.Context(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}, {Field: "emailVerified", Value: user["emailVerified"]}},
			Update: storage.Record{"emailVerified": user["emailVerified"]},
		})
		if err != nil || loser != nil {
			t.Fatalf("guard loser = %#v, err=%v", loser, err)
		}
		return
	case "where with mode insensitive":
		params.Where = []storage.Where{{Field: "email", Value: strings.ToUpper(user["email"].(string)), Mode: storage.Insensitive}}
		params.Update = storage.Record{"name": "AfterUpdate"}
	default:
		t.Fatalf("unsupported update scenario %q", description)
	}
	updated, err := harness.adapter.Update(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	if description == "should return null when where is empty" {
		if updated != nil {
			t.Fatalf("empty where update = %#v", updated)
		}
		return
	}
	if updated == nil {
		t.Fatal("update returned nil")
	}
	for field, value := range params.Update {
		requireMemoryField(t, updated, field, value)
	}
	found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}}})
	for field, value := range params.Update {
		requireMemoryField(t, found, field, value)
	}
}

func supportsMemoryUpdateManyScenario(description string) bool {
	switch description {
	case "should update all models when where is empty", "should update many models with a multiple where", "should update many models with a specific where":
		return true
	default:
		return false
	}
}

func runMemoryUpdateManyScenario(t *testing.T, harness *memoryBehaviorHarness, description string) {
	t.Helper()
	for index := 1; index <= 3; index++ {
		harness.user(t, index, nil)
	}
	params := storage.UpdateManyParams{Model: "user", Update: storage.Record{"name": "test-name"}}
	want := int64(0)
	switch description {
	case "should update all models when where is empty":
		want = 3
	case "should update many models with a multiple where":
		params.Where = []storage.Where{{Field: "id", Value: harness.id(1), Connector: storage.Or}, {Field: "id", Value: harness.id(2), Connector: storage.Or}}
		want = 2
	case "should update many models with a specific where":
		params.Where = []storage.Where{{Field: "id", Value: harness.id(1)}}
		want = 1
	default:
		t.Fatalf("unsupported updateMany scenario %q", description)
	}
	count, err := harness.adapter.UpdateMany(t.Context(), params)
	if err != nil || count != want {
		t.Fatalf("updateMany count = %d, want %d, err=%v", count, want, err)
	}
	rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: params.Where, Limit: storage.Int(100)})
	if int64(len(rows)) != want {
		t.Fatalf("updated rows=%d, want %d", len(rows), want)
	}
	for _, row := range rows {
		requireMemoryField(t, row, "name", "test-name")
	}
}

func runMemoryIncrementOneScenario(t *testing.T, harness *memoryBehaviorHarness, description string) {
	t.Helper()
	if description != "guarded set transition returns the row on a matching guard and null on a guard miss" {
		t.Fatalf("unsupported incrementOne scenario %q", description)
	}
	user := harness.user(t, 1, nil)
	won, err := harness.adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}, {Field: "name", Value: user["name"]}},
		Set: storage.Record{"image": "https://example.com/avatar.png"},
	})
	if err != nil || won == nil || won["image"] != "https://example.com/avatar.png" {
		t.Fatalf("won transition = %#v, err=%v", won, err)
	}
	lost, err := harness.adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}, {Field: "name", Value: "wrong"}},
		Set: storage.Record{"image": "should-not-apply"},
	})
	if err != nil || lost != nil {
		t.Fatalf("lost transition = %#v, err=%v", lost, err)
	}
	found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}}})
	requireMemoryField(t, found, "image", "https://example.com/avatar.png")
}

func supportsMemoryDeleteScenario(description string) bool {
	switch description {
	case "should delete a model", "should delete by non-unique field", "should not throw on record not found":
		return true
	default:
		return false
	}
}

func runMemoryDeleteScenario(t *testing.T, harness *memoryBehaviorHarness, description string) {
	t.Helper()
	switch description {
	case "should delete a model":
		user := harness.user(t, 1, nil)
		if err := harness.adapter.Delete(t.Context(), storage.DeleteParams{Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}}}); err != nil {
			t.Fatal(err)
		}
		if found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}}}); found != nil {
			t.Fatalf("deleted row = %#v", found)
		}
	case "should delete by non-unique field":
		verification := mustMemoryCreate(t, harness.adapter, "verification", storage.Record{
			"id": harness.id(1), "identifier": "shared-identifier", "value": "secret", "expiresAt": harness.now.Add(time.Hour),
		}, true)
		if err := harness.adapter.Delete(t.Context(), storage.DeleteParams{Model: "verification", Where: []storage.Where{{Field: "identifier", Value: verification["identifier"]}}}); err != nil {
			t.Fatal(err)
		}
		if found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "verification", Where: []storage.Where{{Field: "identifier", Value: verification["identifier"]}}}); found != nil {
			t.Fatalf("verification still exists: %#v", found)
		}
	case "should not throw on record not found":
		if err := harness.adapter.Delete(t.Context(), storage.DeleteParams{Model: "user", Where: []storage.Where{{Field: "id", Value: harness.id(999)}}}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported delete scenario %q", description)
	}
}

func supportsMemoryDeleteManyScenario(description string) bool {
	switch description {
	case "should delete many models", "starts_with should not interpret regex patterns", "ends_with should not interpret regex patterns",
		"contains should not interpret regex patterns", "should delete many models with numeric values",
		"should delete many models with boolean values", "where with mode insensitive":
		return true
	default:
		return false
	}
}

func runMemoryDeleteManyScenario(t *testing.T, harness *memoryBehaviorHarness, description string) {
	t.Helper()
	var where []storage.Where
	wantRemaining := []string{}
	switch description {
	case "should delete many models":
		for index := 1; index <= 3; index++ {
			harness.user(t, index, nil)
		}
		where = []storage.Where{{Field: "id", Value: harness.id(1), Connector: storage.Or}, {Field: "id", Value: harness.id(2), Connector: storage.Or}}
		wantRemaining = []string{harness.id(3)}
	case "starts_with should not interpret regex patterns":
		harness.user(t, 1, storage.Record{"name": ".*danger"})
		harness.user(t, 2, storage.Record{"name": "normal"})
		where = []storage.Where{{Field: "name", Value: ".*", Operator: storage.OpStartsWith}}
		wantRemaining = []string{harness.id(2)}
	case "ends_with should not interpret regex patterns":
		harness.user(t, 1, storage.Record{"name": "danger.*"})
		harness.user(t, 2, storage.Record{"name": "normal"})
		where = []storage.Where{{Field: "name", Value: ".*", Operator: storage.OpEndsWith}}
		wantRemaining = []string{harness.id(2)}
	case "contains should not interpret regex patterns":
		harness.user(t, 1, storage.Record{"name": "prefix-.*-suffix"})
		harness.user(t, 2, storage.Record{"name": "normal"})
		where = []storage.Where{{Field: "name", Value: ".*", Operator: storage.OpContains}}
		wantRemaining = []string{harness.id(2)}
	case "should delete many models with numeric values":
		for index := 1; index <= 3; index++ {
			harness.user(t, index, storage.Record{"numericField": index - 1})
		}
		where = []storage.Where{{Field: "numericField", Value: 0, Operator: storage.OpGt}}
		wantRemaining = []string{harness.id(1)}
	case "should delete many models with boolean values":
		harness.user(t, 1, storage.Record{"emailVerified": true})
		harness.user(t, 2, storage.Record{"emailVerified": false})
		harness.user(t, 3, storage.Record{"emailVerified": true})
		where = []storage.Where{{Field: "emailVerified", Value: true}}
		wantRemaining = []string{harness.id(2)}
	case "where with mode insensitive":
		harness.user(t, 1, storage.Record{"email": "DeleteMany@Case.INSENSITIVE"})
		harness.user(t, 2, nil)
		where = []storage.Where{{Field: "email", Value: "deletemany@case.insensitive", Mode: storage.Insensitive}}
		wantRemaining = []string{harness.id(2)}
	default:
		t.Fatalf("unsupported deleteMany scenario %q", description)
	}
	if _, err := harness.adapter.DeleteMany(t.Context(), storage.DeleteManyParams{Model: "user", Where: where}); err != nil {
		t.Fatal(err)
	}
	remaining := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Limit: storage.Int(100)})
	requireMemoryIDs(t, remaining, wantRemaining...)
}
