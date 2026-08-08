package memory_test

import (
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func runMemoryFindManyJoinScenario(t *testing.T, harness *memoryBehaviorHarness, description string) {
	t.Helper()
	if description == "should return empty array when base records don't exist with joins" {
		rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: harness.id(999)}},
			Join: map[string]storage.JoinOption{"session": {}, "account": {}, "oneToOneTable": {}},
		})
		if rows == nil || len(rows) != 0 {
			t.Fatalf("missing joined base = %#v", rows)
		}
		return
	}
	if description == "backwards join should only return single record not array" {
		for index := 1; index <= 2; index++ {
			user := harness.user(t, index, nil)
			harness.session(t, index, user["id"].(string))
		}
		rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "session", Join: map[string]storage.JoinOption{"user": {}}})
		if len(rows) != 2 {
			t.Fatalf("backwards joined rows=%d", len(rows))
		}
		for _, row := range rows {
			if _, ok := row["user"].(storage.Record); !ok {
				t.Fatalf("backwards user join = %T %#v", row["user"], row["user"])
			}
		}
		return
	}

	switch description {
	case "should return empty array for one-to-many join when joined records don't exist":
		withSessions := harness.user(t, 1, nil)
		withoutSessions := harness.user(t, 2, nil)
		harness.session(t, 1, withSessions["id"].(string))
		harness.session(t, 2, withSessions["id"].(string))
		rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Join: map[string]storage.JoinOption{"session": {}}})
		assertMemoryJoinedManyState(t, rows, withSessions["id"].(string), 2, true)
		assertMemoryJoinedManyState(t, rows, withoutSessions["id"].(string), 0, true)
		return
	case "should return null for one-to-one join when joined records don't exist":
		withProfile := harness.user(t, 1, nil)
		withoutProfile := harness.user(t, 2, nil)
		profile := harness.oneToOne(t, 1, withProfile["id"].(string))
		rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Join: map[string]storage.JoinOption{"oneToOneTable": {}}})
		with := memoryRowByID(t, rows, withProfile["id"].(string))
		joined, ok := with["oneToOneTable"].(storage.Record)
		if !ok || joined["id"] != profile["id"] {
			t.Fatalf("present one-to-one = %#v", with["oneToOneTable"])
		}
		without := memoryRowByID(t, rows, withoutProfile["id"].(string))
		if value, exists := without["oneToOneTable"]; !exists || value != nil {
			t.Fatalf("missing one-to-one = %#v, exists=%v", value, exists)
		}
		return
	case "should handle mixed joins correctly when some are missing":
		runMemoryMixedJoinScenario(t, harness)
		return
	}

	baseCount := 5
	if description == "should find many models with join" {
		baseCount = 3
	}
	users := make([]storage.Record, 0, baseCount)
	for index := 1; index <= baseCount; index++ {
		name := "other-user"
		if index <= 3 {
			name = "target-user"
		}
		user := harness.user(t, index, storage.Record{"name": name})
		users = append(users, user)
		sessionCount := 2
		accountCount := 1
		if description == "should find many models with join" || description == "should find many with join and limit" {
			sessionCount = 3
			accountCount = 3
		}
		if description == "should be able to perform a limited join" || description == "should be able to perform a complex limited join" {
			sessionCount = 5
			accountCount = 5
		}
		for joinedIndex := 1; joinedIndex <= sessionCount; joinedIndex++ {
			harness.session(t, index*10+joinedIndex, user["id"].(string))
		}
		for joinedIndex := 1; joinedIndex <= accountCount; joinedIndex++ {
			harness.account(t, index*10+joinedIndex, user["id"].(string))
		}
		if description == "should find many with one-to-one join" ||
			description == "should find many with both one-to-one and one-to-many joins" ||
			description == "should select fields with one-to-one join" {
			harness.oneToOne(t, index, user["id"].(string))
		}
	}

	params := storage.FindManyParams{Model: "user", Limit: storage.Int(100)}
	switch description {
	case "should find many models with join":
		params.Where = []storage.Where{{Field: "name", Value: "target", Operator: storage.OpStartsWith}}
		params.Join = map[string]storage.JoinOption{"session": {}, "account": {}}
	case "should find many with join and limit":
		params.Limit = storage.Int(2)
		params.Join = map[string]storage.JoinOption{"session": {}}
	case "should find many with join and offset":
		params.Offset = storage.Int(2)
		params.Join = map[string]storage.JoinOption{"session": {}}
	case "should find many with join and sortBy":
		params.SortBy = &storage.Sort{Field: "numericField", Direction: storage.Descending}
		params.Join = map[string]storage.JoinOption{"session": {}}
	case "should find many with join and where clause":
		params.Where = []storage.Where{{Field: "name", Value: "target", Operator: storage.OpStartsWith}}
		params.Join = map[string]storage.JoinOption{"session": {}}
	case "should find many with join, where, limit, and offset":
		params.Where = []storage.Where{{Field: "name", Value: "target", Operator: storage.OpStartsWith}}
		params.Limit, params.Offset = storage.Int(1), storage.Int(1)
		params.Join = map[string]storage.JoinOption{"session": {}}
	case "should find many with one-to-one join":
		params.Join = map[string]storage.JoinOption{"oneToOneTable": {}}
	case "should find many with both one-to-one and one-to-many joins":
		params.Join = map[string]storage.JoinOption{"oneToOneTable": {}, "session": {}}
	case "should be able to perform a limited join":
		params.Join = map[string]storage.JoinOption{"session": {Limit: storage.Int(2)}}
	case "should be able to perform a complex limited join":
		params.Limit, params.Offset = storage.Int(2), storage.Int(2)
		params.Join = map[string]storage.JoinOption{"session": {Limit: storage.Int(2)}, "account": {Limit: storage.Int(3)}}
	case "should select fields with one-to-many join":
		params.Where = []storage.Where{{Field: "id", Value: users[0]["id"]}}
		params.Select = []string{"email", "name"}
		params.Join = map[string]storage.JoinOption{"session": {}}
	case "should select fields with one-to-one join":
		params.Where = []storage.Where{{Field: "id", Value: users[0]["id"]}}
		params.Select = []string{"email", "name"}
		params.Join = map[string]storage.JoinOption{"oneToOneTable": {}}
	case "should select fields with multiple joins":
		params.Where = []storage.Where{{Field: "id", Value: users[0]["id"]}}
		params.Select = []string{"email", "name"}
		params.Join = map[string]storage.JoinOption{"session": {}, "account": {}}
	default:
		t.Fatalf("unsupported findMany join scenario %q", description)
	}

	rows := mustMemoryFindMany(t, harness.adapter, params)
	switch description {
	case "should find many models with join", "should find many with join and where clause":
		if len(rows) != 3 {
			t.Fatalf("filtered joined rows=%d, want 3", len(rows))
		}
	case "should find many with join and limit", "should be able to perform a complex limited join":
		if len(rows) != 2 {
			t.Fatalf("limited joined rows=%d, want 2", len(rows))
		}
	case "should find many with join and offset":
		if len(rows) != 3 {
			t.Fatalf("offset joined rows=%d, want 3", len(rows))
		}
	case "should find many with join, where, limit, and offset":
		if len(rows) != 1 || rows[0]["id"] != users[1]["id"] {
			t.Fatalf("where/limit/offset joined rows=%#v", rows)
		}
	case "should find many with join and sortBy":
		if len(rows) != 5 || rows[0]["numericField"] != 5 || rows[4]["numericField"] != 1 {
			t.Fatalf("sorted joined rows=%#v", rows)
		}
	case "should select fields with one-to-many join", "should select fields with one-to-one join", "should select fields with multiple joins":
		if len(rows) != 1 || rows[0]["email"] != users[0]["email"] || rows[0]["name"] != users[0]["name"] {
			t.Fatalf("selected joined rows=%#v", rows)
		}
		if _, leaked := rows[0]["rank"]; leaked {
			t.Fatalf("unselected field leaked: %#v", rows[0])
		}
	}

	for _, row := range rows {
		if option, exists := params.Join["session"]; exists {
			sessions, ok := row["session"].([]storage.Record)
			if !ok {
				t.Fatalf("session join=%T %#v", row["session"], row["session"])
			}
			want := 2
			if description == "should find many models with join" || description == "should find many with join and limit" {
				want = 3
			}
			if option.Limit != nil {
				want = *option.Limit
			}
			if len(sessions) != want {
				t.Fatalf("session join len=%d, want %d", len(sessions), want)
			}
		}
		if option, exists := params.Join["account"]; exists {
			accounts, ok := row["account"].([]storage.Record)
			if !ok {
				t.Fatalf("account join=%T %#v", row["account"], row["account"])
			}
			want := 3
			if description != "should find many models with join" && option.Limit == nil {
				want = 1
			}
			if option.Limit != nil {
				want = *option.Limit
			}
			if len(accounts) != want {
				t.Fatalf("account join len=%d, want %d", len(accounts), want)
			}
		}
		if _, exists := params.Join["oneToOneTable"]; exists {
			if _, ok := row["oneToOneTable"].(storage.Record); !ok {
				t.Fatalf("one-to-one join=%T %#v", row["oneToOneTable"], row["oneToOneTable"])
			}
		}
	}
}

func runMemoryMixedJoinScenario(t *testing.T, harness *memoryBehaviorHarness) {
	t.Helper()
	users := make([]storage.Record, 4)
	for index := 1; index <= 4; index++ {
		users[index-1] = harness.user(t, index, nil)
	}
	harness.oneToOne(t, 1, users[0]["id"].(string))
	harness.session(t, 1, users[0]["id"].(string))
	harness.oneToOne(t, 2, users[1]["id"].(string))
	harness.session(t, 3, users[2]["id"].(string))
	rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Join: map[string]storage.JoinOption{
		"oneToOneTable": {}, "session": {},
	}})
	for index, user := range users {
		row := memoryRowByID(t, rows, user["id"].(string))
		_, hasOne := row["oneToOneTable"].(storage.Record)
		sessions := row["session"].([]storage.Record)
		wantOne := index == 0 || index == 1
		wantSessions := 0
		if index == 0 || index == 2 {
			wantSessions = 1
		}
		if hasOne != wantOne || len(sessions) != wantSessions {
			t.Fatalf("mixed joins user[%d] = %#v", index, row)
		}
	}
}

func assertMemoryJoinedManyState(t *testing.T, rows []storage.Record, id string, wantSessions int, expectArray bool) {
	t.Helper()
	row := memoryRowByID(t, rows, id)
	sessions, ok := row["session"].([]storage.Record)
	if ok != expectArray || len(sessions) != wantSessions {
		t.Fatalf("user %s session join = %T %#v", id, row["session"], row["session"])
	}
}

func memoryRowByID(t *testing.T, rows []storage.Record, id string) storage.Record {
	t.Helper()
	for _, row := range rows {
		if row["id"] == id {
			return row
		}
	}
	t.Fatalf("row %s not found in %#v", id, rows)
	return nil
}
