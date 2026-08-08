package memory_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func supportsMemoryFindOneScenario(description string) bool {
	switch description {
	case "should find a model", "should find a model using a reference field", "should find a model using a uuid",
		"should find a model with additional fields", "should find a model with join",
		"should find a model with modified field name", "should find a model with modified model name",
		"should find a model without id", "should find model with date field",
		"should join a model with modified field name", "should not apply defaultValue if value not found",
		"should not throw on record not found", "should perform backwards joins",
		"should return an array for one-to-many joins", "should return an object for one-to-one joins",
		"should return null for failed base model lookup that has joins",
		"should return null for one-to-one join when joined record doesn't exist",
		"should select fields", "should select fields with multiple joins",
		"should select fields with one-to-many join", "should select fields with one-to-one join",
		"should work with both one-to-one and one-to-many joins",
		"backwards join should only return single record not array",
		"backwards join with modified field name (session base, users-table join)",
		"multiple joins should return result even when some joined tables have no matching rows",
		"should be able to perform a complex limited join", "should be able to perform a limited join",
		"eq with mode insensitive should match regardless of case",
		"eq with mode sensitive (default) should not match different case":
		return true
	default:
		return false
	}
}

func runMemoryFindOneScenario(t *testing.T, harness *memoryBehaviorHarness, _ memoryAdapterVector, description string) {
	t.Helper()
	switch description {
	case "should find a model":
		user := harness.user(t, 1, nil)
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}}})
		if !reflect.DeepEqual(found, user) {
			t.Fatalf("found = %#v, want %#v", found, user)
		}
	case "should find a model using a reference field":
		user := harness.user(t, 1, nil)
		session := harness.session(t, 1, user["id"].(string))
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "session", Where: []storage.Where{{Field: "userId", Value: user["id"]}}})
		if !reflect.DeepEqual(found, session) {
			t.Fatalf("found by reference = %#v, want %#v", found, session)
		}
	case "should find a model using a uuid":
		created, err := harness.adapter.Create(t.Context(), storage.CreateParams{Model: "user", Data: storage.Record{
			"name": "UUID", "email": "uuid@email.com", "emailVerified": false,
		}})
		if err != nil {
			t.Fatal(err)
		}
		id, _ := created["id"].(string)
		if !uuidPattern.MatchString(id) {
			t.Fatalf("created UUID = %q", id)
		}
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: id}}})
		if !reflect.DeepEqual(found, created) {
			t.Fatalf("UUID lookup = %#v, want %#v", found, created)
		}
	case "should find a model with additional fields":
		user := harness.user(t, 1, nil)
		requireMemoryField(t, user, "customField", "default-value")
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "customField", Value: "default-value"}}})
		requireMemoryField(t, found, "id", user["id"])
		requireMemoryField(t, found, "customField", "default-value")
	case "should find a model with modified field name", "should find a model with modified model name":
		user := harness.user(t, 1, nil)
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "email", Value: user["email"]}}})
		if !reflect.DeepEqual(found, user) {
			t.Fatalf("aliased lookup = %#v, want %#v", found, user)
		}
		if _, leaked := found["email_address"]; leaked {
			t.Fatalf("physical field leaked: %#v", found)
		}
	case "should find a model without id":
		user := harness.user(t, 1, nil)
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "email", Value: user["email"]}}})
		requireMemoryField(t, found, "id", user["id"])
	case "should find model with date field":
		user := harness.user(t, 1, nil)
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "createdAt", Value: user["createdAt"]}}})
		if !reflect.DeepEqual(found["createdAt"], user["createdAt"]) {
			t.Fatalf("date lookup = %#v, want %#v", found["createdAt"], user["createdAt"])
		}
	case "should not apply defaultValue if value not found":
		model := mustMemoryCreate(t, harness.adapter, "testModel", storage.Record{"testField": nil, "cbDefaultValue": nil}, false)
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "testModel", Where: []storage.Where{{Field: "id", Value: model["id"]}}})
		if value, exists := found["testField"]; !exists || value != nil {
			t.Fatalf("explicit null default field = %#v, exists=%v", value, exists)
		}
		if value, exists := found["cbDefaultValue"]; !exists || value != nil {
			t.Fatalf("explicit null callback default = %#v, exists=%v", value, exists)
		}
	case "should not throw on record not found":
		if found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: harness.id(999)}}}); found != nil {
			t.Fatalf("missing lookup = %#v", found)
		}
	case "should select fields":
		user := harness.user(t, 1, nil)
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}}, Select: []string{"email", "name"},
		})
		want := storage.Record{"email": user["email"], "name": user["name"]}
		if !reflect.DeepEqual(found, want) {
			t.Fatalf("selected fields = %#v, want %#v", found, want)
		}
	case "eq with mode insensitive should match regardless of case":
		user := harness.user(t, 1, storage.Record{"email": "TestUser@Example.COM"})
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "email", Value: "testuser@example.com", Mode: storage.Insensitive}}})
		requireMemoryField(t, found, "id", user["id"])
	case "eq with mode sensitive (default) should not match different case":
		harness.user(t, 1, storage.Record{"email": "ExactCase@Test.com"})
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "email", Value: "exactcase@test.com", Mode: storage.Sensitive}}})
		if found != nil {
			t.Fatalf("case-sensitive lookup = %#v", found)
		}
	case "should return null for failed base model lookup that has joins":
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: harness.id(999)}},
			Join: map[string]storage.JoinOption{"session": {}, "account": {}, "oneToOneTable": {}},
		})
		if found != nil {
			t.Fatalf("missing joined base = %#v", found)
		}
	case "should return null for one-to-one join when joined record doesn't exist":
		user := harness.user(t, 1, nil)
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}}, Join: map[string]storage.JoinOption{"oneToOneTable": {}},
		})
		if value, exists := found["oneToOneTable"]; !exists || value != nil {
			t.Fatalf("missing one-to-one = %#v, exists=%v", value, exists)
		}
	default:
		runMemoryFindOneJoinScenario(t, harness, description)
	}
}

func runMemoryFindOneJoinScenario(t *testing.T, harness *memoryBehaviorHarness, description string) {
	t.Helper()
	user := harness.user(t, 1, nil)
	session := harness.session(t, 1, user["id"].(string))
	account := harness.account(t, 1, user["id"].(string))
	one := harness.oneToOne(t, 1, user["id"].(string))

	backward := description == "should perform backwards joins" ||
		description == "backwards join should only return single record not array" ||
		description == "backwards join with modified field name (session base, users-table join)"
	if backward {
		found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{
			Model: "session", Where: []storage.Where{{Field: "id", Value: session["id"]}}, Join: map[string]storage.JoinOption{"user": {}},
		})
		joined, ok := found["user"].(storage.Record)
		if !ok || joined["id"] != user["id"] {
			t.Fatalf("backwards join = %#v", found["user"])
		}
		return
	}

	joins := map[string]storage.JoinOption{}
	selectFields := []string(nil)
	switch description {
	case "should find a model with join":
		joins = map[string]storage.JoinOption{"session": {}, "account": {}}
	case "should join a model with modified field name", "should return an array for one-to-many joins":
		joins = map[string]storage.JoinOption{"session": {}}
	case "should return an object for one-to-one joins":
		joins = map[string]storage.JoinOption{"oneToOneTable": {}}
	case "should work with both one-to-one and one-to-many joins":
		joins = map[string]storage.JoinOption{"oneToOneTable": {}, "session": {}}
	case "multiple joins should return result even when some joined tables have no matching rows":
		// A second user has no joined rows; the selected user has two populated
		// joins and one deliberately empty join.
		joins = map[string]storage.JoinOption{"session": {}, "account": {}, "oneToOneTable": {}}
	case "should be able to perform a limited join":
		for index := 2; index <= 5; index++ {
			harness.session(t, index, user["id"].(string))
		}
		joins = map[string]storage.JoinOption{"session": {Limit: storage.Int(2)}}
	case "should be able to perform a complex limited join":
		for index := 2; index <= 5; index++ {
			harness.session(t, index, user["id"].(string))
			harness.account(t, index, user["id"].(string))
		}
		joins = map[string]storage.JoinOption{"session": {Limit: storage.Int(2)}, "account": {Limit: storage.Int(3)}}
	case "should select fields with one-to-many join":
		selectFields = []string{"email", "name"}
		joins = map[string]storage.JoinOption{"session": {}}
	case "should select fields with one-to-one join":
		selectFields = []string{"email", "name"}
		joins = map[string]storage.JoinOption{"oneToOneTable": {}}
	case "should select fields with multiple joins":
		selectFields = []string{"email", "name"}
		joins = map[string]storage.JoinOption{"session": {}, "account": {}}
	default:
		t.Fatalf("unsupported findOne join scenario %q", description)
	}

	found := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}}, Select: selectFields, Join: joins,
	})
	if found == nil {
		t.Fatal("joined findOne returned nil")
	}
	if len(selectFields) > 0 {
		if found["email"] != user["email"] || found["name"] != user["name"] {
			t.Fatalf("selected joined base = %#v", found)
		}
		if _, leaked := found["rank"]; leaked {
			t.Fatalf("unselected base field leaked: %#v", found)
		}
	}
	if option, exists := joins["session"]; exists {
		records, ok := found["session"].([]storage.Record)
		if !ok {
			t.Fatalf("session join = %T %#v", found["session"], found["session"])
		}
		want := 1
		if option.Limit != nil {
			want = *option.Limit
		}
		if len(records) != want || records[0]["id"] != session["id"] {
			t.Fatalf("session join = %#v, want len=%d first=%s", records, want, session["id"])
		}
	}
	if option, exists := joins["account"]; exists {
		records, ok := found["account"].([]storage.Record)
		if !ok {
			t.Fatalf("account join = %T %#v", found["account"], found["account"])
		}
		want := 1
		if option.Limit != nil {
			want = *option.Limit
		}
		if len(records) != want || records[0]["id"] != account["id"] {
			t.Fatalf("account join = %#v, want len=%d first=%s", records, want, account["id"])
		}
	}
	if _, exists := joins["oneToOneTable"]; exists {
		record, ok := found["oneToOneTable"].(storage.Record)
		if !ok || record["id"] != one["id"] {
			t.Fatalf("one-to-one join = %T %#v", found["oneToOneTable"], found["oneToOneTable"])
		}
	}
	if strings.Contains(description, "some joined tables have no matching rows") {
		other := harness.user(t, 2, nil)
		missing := mustMemoryFindOne(t, harness.adapter, storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: other["id"]}}, Join: joins,
		})
		if len(missing["session"].([]storage.Record)) != 0 || len(missing["account"].([]storage.Record)) != 0 || missing["oneToOneTable"] != nil {
			t.Fatalf("missing mixed joins = %#v", missing)
		}
	}
}
