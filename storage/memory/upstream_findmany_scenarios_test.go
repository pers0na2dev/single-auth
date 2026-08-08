package memory_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func supportsMemoryFindManyScenario(description string) bool {
	switch description {
	case "backwards join should only return single record not array",
		"contains should not interpret regex patterns", "contains with mode insensitive",
		"ends_with should not interpret regex patterns", "ends_with with mode insensitive",
		"eq and ne operators with null value in AND group should use IS NULL / IS NOT NULL",
		"eq and ne operators with null value in OR group should use IS NULL / IS NOT NULL",
		"eq operator with null value (single condition) should use IS NULL",
		"eq with mode insensitive", "in with mode insensitive", "ne with mode insensitive", "not_in with mode insensitive",
		"should be able to perform a complex limited join", "should be able to perform a limited join",
		"should find many models", "should find many models with contains operator",
		"should find many models with contains operator (using symbol)", "should find many models with date fields",
		"should find many models with ends_with operator", "should find many models with eq operator",
		"should find many models with gt operator", "should find many models with gte operator",
		"should find many models with in operator", "should find many models with join",
		"should find many models with limit", "should find many models with limit and offset",
		"should find many models with lt operator", "should find many models with lte operator",
		"should find many models with ne operator", "should find many models with not_in operator",
		"should find many models with offset", "should find many models with sortBy",
		"should find many models with sortBy and limit", "should find many models with sortBy and limit and offset",
		"should find many models with sortBy and limit and offset and where", "should find many models with sortBy and offset",
		"should find many models with starts_with operator",
		"should find many with both one-to-one and one-to-many joins", "should find many with join and limit",
		"should find many with join and offset", "should find many with join and sortBy",
		"should find many with join and where clause", "should find many with join, where, limit, and offset",
		"should find many with one-to-one join", "should handle mixed joins correctly when some are missing",
		"should handle multiple where conditions with different operators", "should return an empty array when no models are found",
		"should return empty array for one-to-many join when joined records don't exist",
		"should return empty array when base records don't exist with joins",
		"should return null for one-to-one join when joined records don't exist",
		"should select fields", "should select fields with multiple joins",
		"should select fields with one-to-many join", "should select fields with one-to-one join",
		"starts_with should not interpret regex patterns", "starts_with with mode insensitive":
		return true
	default:
		return false
	}
}

func runMemoryFindManyScenario(t *testing.T, harness *memoryBehaviorHarness, _ memoryAdapterVector, description string) {
	t.Helper()
	if isMemoryFindManyJoinScenario(description) {
		runMemoryFindManyJoinScenario(t, harness, description)
		return
	}
	switch description {
	case "should find many models":
		for index := 1; index <= 3; index++ {
			harness.user(t, index, nil)
		}
		requireMemoryIDs(t, mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user"}), harness.id(1), harness.id(2), harness.id(3))
	case "should find many models with date fields":
		for index := 1; index <= 3; index++ {
			harness.user(t, index, nil)
		}
		rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{{Field: "createdAt", Value: harness.now.Add(3 * time.Minute), Operator: storage.OpLt}}})
		requireMemoryIDs(t, rows, harness.id(1), harness.id(2))
	case "should return an empty array when no models are found":
		rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{{Field: "id", Value: harness.id(999)}}})
		if rows == nil || len(rows) != 0 {
			t.Fatalf("empty result = %#v", rows)
		}
	case "should select fields":
		for index := 1; index <= 3; index++ {
			harness.user(t, index, nil)
		}
		rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Select: []string{"id", "email"}})
		if len(rows) != 3 {
			t.Fatalf("selected rows=%d", len(rows))
		}
		for _, row := range rows {
			if len(row) != 2 || row["id"] == nil || row["email"] == nil {
				t.Fatalf("selected row = %#v", row)
			}
		}
	case "should handle multiple where conditions with different operators":
		harness.user(t, 1, storage.Record{"name": "john doe", "email": "john@example.com"})
		harness.user(t, 2, storage.Record{"name": "jane smith", "email": "jane@gmail.com"})
		rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{
			{Field: "email", Value: "john@example.com"}, {Field: "name", Value: "john", Operator: storage.OpContains},
		}})
		requireMemoryIDs(t, rows, harness.id(1))
	case "eq operator with null value (single condition) should use IS NULL":
		runMemoryNullQueryScenario(t, harness, "single")
	case "eq and ne operators with null value in AND group should use IS NULL / IS NOT NULL":
		runMemoryNullQueryScenario(t, harness, "and")
	case "eq and ne operators with null value in OR group should use IS NULL / IS NOT NULL":
		runMemoryNullQueryScenario(t, harness, "or")
	default:
		if runMemoryFindManyPatternScenario(t, harness, description) {
			return
		}
		if runMemoryFindManyOperatorScenario(t, harness, description) {
			return
		}
		if runMemoryFindManyPageScenario(t, harness, description) {
			return
		}
		t.Fatalf("unsupported findMany scenario %q", description)
	}
}

func runMemoryNullQueryScenario(t *testing.T, harness *memoryBehaviorHarness, kind string) {
	t.Helper()
	nullVerified := harness.user(t, 1, storage.Record{"image": nil, "emailVerified": true})
	nullUnverified := harness.user(t, 2, storage.Record{"image": nil, "emailVerified": false})
	imageVerified := harness.user(t, 3, storage.Record{"image": "avatar.png", "emailVerified": true})
	switch kind {
	case "single":
		equal := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{{Field: "image", Value: nil}}})
		requireMemoryIDs(t, equal, nullVerified["id"].(string), nullUnverified["id"].(string))
		notEqual := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{{Field: "image", Value: nil, Operator: storage.OpNe}}})
		requireMemoryIDs(t, notEqual, imageVerified["id"].(string))
	case "and":
		equal := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{
			{Field: "image", Value: nil}, {Field: "emailVerified", Value: true},
		}})
		requireMemoryIDs(t, equal, nullVerified["id"].(string))
		notEqual := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{
			{Field: "image", Value: nil, Operator: storage.OpNe}, {Field: "emailVerified", Value: true},
		}})
		requireMemoryIDs(t, notEqual, imageVerified["id"].(string))
	case "or":
		equal := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{
			{Field: "image", Value: nil, Connector: storage.Or}, {Field: "email", Value: imageVerified["email"], Connector: storage.Or},
		}})
		requireMemoryIDs(t, equal, nullVerified["id"].(string), nullUnverified["id"].(string), imageVerified["id"].(string))
		notEqual := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{
			{Field: "image", Value: nil, Operator: storage.OpNe, Connector: storage.Or}, {Field: "email", Value: nullVerified["email"], Connector: storage.Or},
		}})
		requireMemoryIDs(t, notEqual, nullVerified["id"].(string), imageVerified["id"].(string))
	default:
		t.Fatalf("unknown null scenario %q", kind)
	}
}

func runMemoryFindManyPatternScenario(t *testing.T, harness *memoryBehaviorHarness, description string) bool {
	t.Helper()
	type patternCase struct {
		operator storage.Operator
		stored   string
		query    string
		mode     storage.ComparisonMode
	}
	var scenario patternCase
	switch description {
	case "starts_with should not interpret regex patterns":
		scenario = patternCase{storage.OpStartsWith, ".*danger", ".*", storage.Sensitive}
	case "ends_with should not interpret regex patterns":
		scenario = patternCase{storage.OpEndsWith, "danger.*", ".*", storage.Sensitive}
	case "contains should not interpret regex patterns":
		scenario = patternCase{storage.OpContains, "prefix-.*-suffix", ".*", storage.Sensitive}
	case "starts_with with mode insensitive":
		scenario = patternCase{storage.OpStartsWith, "STARTSwith@test.com", "starts", storage.Insensitive}
	case "ends_with with mode insensitive":
		scenario = patternCase{storage.OpEndsWith, "user@ENDSWITH.Com", "endswith.com", storage.Insensitive}
	case "contains with mode insensitive":
		scenario = patternCase{storage.OpContains, "prefixCONTAINSsuffix@test.com", "containssuffix", storage.Insensitive}
	default:
		return false
	}
	field := "name"
	values := storage.Record{"name": scenario.stored}
	if scenario.mode == storage.Insensitive {
		field = "email"
		values = storage.Record{"email": scenario.stored}
	}
	target := harness.user(t, 1, values)
	harness.user(t, 2, nil)
	rows := mustMemoryFindMany(t, harness.adapter, storage.FindManyParams{Model: "user", Where: []storage.Where{{
		Field: field, Value: scenario.query, Operator: scenario.operator, Mode: scenario.mode,
	}}})
	requireMemoryIDs(t, rows, target["id"].(string))
	return true
}

func runMemoryFindManyOperatorScenario(t *testing.T, harness *memoryBehaviorHarness, description string) bool {
	t.Helper()
	params := storage.FindManyParams{Model: "user", Limit: storage.Int(100)}
	want := []string{}
	switch description {
	case "should find many models with eq operator":
		params.Where = []storage.Where{{Field: "email", Value: "user-01@email.com"}}
		want = []string{harness.id(1)}
	case "should find many models with ne operator":
		params.Where = []storage.Where{{Field: "email", Value: "user-01@email.com", Operator: storage.OpNe}}
		want = []string{harness.id(2), harness.id(3)}
	case "should find many models with gt operator":
		params.Where = []storage.Where{{Field: "rank", Value: 1, Operator: storage.OpGt}}
		want = []string{harness.id(2), harness.id(3)}
	case "should find many models with gte operator":
		params.Where = []storage.Where{{Field: "rank", Value: 2, Operator: storage.OpGTE}}
		want = []string{harness.id(2), harness.id(3)}
	case "should find many models with lt operator":
		params.Where = []storage.Where{{Field: "rank", Value: 3, Operator: storage.OpLt}}
		want = []string{harness.id(1), harness.id(2)}
	case "should find many models with lte operator":
		params.Where = []storage.Where{{Field: "rank", Value: 2, Operator: storage.OpLTE}}
		want = []string{harness.id(1), harness.id(2)}
	case "should find many models with in operator":
		params.Where = []storage.Where{{Field: "id", Value: []string{harness.id(1), harness.id(2)}, Operator: storage.OpIn}}
		want = []string{harness.id(1), harness.id(2)}
	case "should find many models with not_in operator":
		params.Where = []storage.Where{{Field: "id", Value: []string{harness.id(1), harness.id(2)}, Operator: storage.OpNotIn}}
		want = []string{harness.id(3)}
	case "should find many models with starts_with operator":
		params.Where = []storage.Where{{Field: "name", Value: "user-", Operator: storage.OpStartsWith}}
		want = []string{harness.id(1), harness.id(2), harness.id(3)}
	case "should find many models with ends_with operator":
		params.Where = []storage.Where{{Field: "name", Value: "02", Operator: storage.OpEndsWith}}
		want = []string{harness.id(2)}
	case "should find many models with contains operator":
		params.Where = []storage.Where{{Field: "email", Value: "mail", Operator: storage.OpContains}}
		want = []string{harness.id(1), harness.id(2), harness.id(3)}
	case "should find many models with contains operator (using symbol)":
		params.Where = []storage.Where{{Field: "email", Value: "@", Operator: storage.OpContains}}
		want = []string{harness.id(1), harness.id(2), harness.id(3)}
	case "eq with mode insensitive":
		params.Where = []storage.Where{{Field: "email", Value: "USER-01@EMAIL.COM", Mode: storage.Insensitive}}
		want = []string{harness.id(1)}
	case "ne with mode insensitive":
		params.Where = []storage.Where{{Field: "email", Value: "USER-01@EMAIL.COM", Operator: storage.OpNe, Mode: storage.Insensitive}}
		want = []string{harness.id(2), harness.id(3)}
	case "in with mode insensitive":
		params.Where = []storage.Where{{Field: "email", Value: []string{"USER-01@EMAIL.COM"}, Operator: storage.OpIn, Mode: storage.Insensitive}}
		want = []string{harness.id(1)}
	case "not_in with mode insensitive":
		params.Where = []storage.Where{{Field: "email", Value: []string{"USER-01@EMAIL.COM"}, Operator: storage.OpNotIn, Mode: storage.Insensitive}}
		want = []string{harness.id(2), harness.id(3)}
	default:
		return false
	}
	for index := 1; index <= 3; index++ {
		harness.user(t, index, nil)
	}
	rows := mustMemoryFindMany(t, harness.adapter, params)
	requireMemoryIDs(t, rows, want...)
	return true
}

func runMemoryFindManyPageScenario(t *testing.T, harness *memoryBehaviorHarness, description string) bool {
	t.Helper()
	for index := 1; index <= 10; index++ {
		name := "page-user"
		if index >= 6 {
			name = "page-user-last"
		}
		harness.user(t, index, storage.Record{"name": name})
	}
	params := storage.FindManyParams{Model: "user"}
	wantRanks := []int{}
	switch description {
	case "should find many models with limit":
		params.Limit = storage.Int(2)
		wantRanks = []int{1, 2}
	case "should find many models with offset":
		params.Offset = storage.Int(2)
		wantRanks = []int{3, 4, 5, 6, 7, 8, 9, 10}
	case "should find many models with limit and offset":
		params.Limit, params.Offset = storage.Int(2), storage.Int(2)
		wantRanks = []int{3, 4}
	case "should find many models with sortBy":
		params.SortBy = &storage.Sort{Field: "numericField", Direction: storage.Ascending}
		wantRanks = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	case "should find many models with sortBy and offset":
		params.SortBy, params.Offset = &storage.Sort{Field: "numericField", Direction: storage.Ascending}, storage.Int(2)
		wantRanks = []int{3, 4, 5, 6, 7, 8, 9, 10}
	case "should find many models with sortBy and limit":
		params.SortBy, params.Limit = &storage.Sort{Field: "numericField", Direction: storage.Ascending}, storage.Int(2)
		wantRanks = []int{1, 2}
	case "should find many models with sortBy and limit and offset":
		params.SortBy, params.Limit, params.Offset = &storage.Sort{Field: "numericField", Direction: storage.Ascending}, storage.Int(2), storage.Int(2)
		wantRanks = []int{3, 4}
	case "should find many models with sortBy and limit and offset and where":
		params.SortBy, params.Limit, params.Offset = &storage.Sort{Field: "numericField", Direction: storage.Ascending}, storage.Int(2), storage.Int(2)
		params.Where = []storage.Where{{Field: "name", Value: "last", Operator: storage.OpEndsWith}}
		wantRanks = []int{8, 9}
	default:
		return false
	}
	rows := mustMemoryFindMany(t, harness.adapter, params)
	gotRanks := make([]int, len(rows))
	for index, row := range rows {
		gotRanks[index] = row["numericField"].(int)
	}
	if !reflect.DeepEqual(gotRanks, wantRanks) {
		t.Fatalf("page ranks = %v, want %v", gotRanks, wantRanks)
	}
	return true
}

func isMemoryFindManyJoinScenario(description string) bool {
	return strings.Contains(strings.ToLower(description), "join") || description == "backwards join should only return single record not array"
}
