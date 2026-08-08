package redis

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type redisStorageOracle struct {
	SchemaVersion   int                `json:"schemaVersion"`
	UpstreamVersion string             `json:"upstreamVersion"`
	OracleKind      string             `json:"oracleKind"`
	Sources         []redisStorageFile `json:"sources"`
	Runtime         redisStorageFile   `json:"runtime"`
	ManifestTestIDs []string           `json:"manifestTestIDs"`
	Tests           []redisStorageCase `json:"tests"`
}

type redisStorageFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type redisStorageCase struct {
	Title       string
	Observation any
}

func TestRedisStorageRuntimeBehavior(t *testing.T) {
	oracle := loadRedisStorageOracle(t)
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			actual := executeRedisStorageBehaviorCase(t, vector.Title)
			assertRedisStorageJSON(t, actual, vector.Observation)
		})
	}
}

func executeRedisStorageBehaviorCase(t *testing.T, title string) map[string]any {
	t.Helper()
	switch title {
	case "uses GETDEL when it is supported":
		client := newMockRedis()
		client.values["ba:verification-key"] = "stored-value"
		store := mustRedisBehaviorStore(t, client, "ba:")
		result, err := store.GetAndDelete(t.Context(), "verification-key")
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"result": result, "callCalls": client.commandCalls("GETDEL"), "evalCalls": [][]any{},
		}
	case "falls back to Lua when GETDEL is unavailable":
		client := newMockRedis()
		client.getDelSupported = false
		client.values["ba:verification-key"] = "stored-value"
		client.values["ba:other-verification-key"] = "stored-value"
		store := mustRedisBehaviorStore(t, client, "ba:")
		results := make([]string, 0, 2)
		for _, key := range []string{"verification-key", "other-verification-key"} {
			result, err := store.GetAndDelete(t.Context(), key)
			if err != nil {
				t.Fatal(err)
			}
			results = append(results, result)
		}
		evalCalls := make([]map[string]any, 0, 2)
		for _, call := range client.commandCalls("EVAL") {
			evalCalls = append(evalCalls, map[string]any{
				"numKeys": call[2], "key": call[3], "script": redisStorageScriptShape(call[1].(string)),
			})
		}
		return map[string]any{
			"results": results, "callCalls": client.commandCalls("GETDEL"), "evalCalls": evalCalls,
		}
	case "rethrows GETDEL errors that are not unknown-command errors":
		callError := errors.New("Authentication required")
		client := newMockRedis()
		client.commandErrors["GETDEL"] = []error{callError}
		store := mustRedisBehaviorStore(t, client, "ba:")
		_, err := store.GetAndDelete(t.Context(), "verification-key")
		if err == nil {
			t.Fatal("expected GETDEL error")
		}
		return map[string]any{
			"error": callError.Error(), "sameError": errors.Is(err, callError), "evalCalls": len(client.commandCalls("EVAL")),
		}
	case "increments atomically and sets the ttl only on creation":
		client := newMockRedis()
		store := mustRedisBehaviorStore(t, client, "ba:")
		results := make([]int64, 0, 3)
		for range 3 {
			result, err := store.Increment(t.Context(), "rate:1", 60)
			if err != nil {
				t.Fatal(err)
			}
			results = append(results, result)
		}
		_, ttl, _ := client.snapshot("ba:rate:1")
		evalCalls := client.commandCalls("EVAL")
		return map[string]any{
			"results": results, "ttl": ttl, "evalCallCount": len(evalCalls),
			"firstEval": map[string]any{
				"numKeys": evalCalls[0][2], "key": evalCalls[0][3], "ttl": evalCalls[0][4],
				"script": redisStorageScriptShape(evalCalls[0][1].(string)),
			},
		}
	case "clears every prefixed key by paging through SCAN":
		client := newMockRedis()
		client.scanPages = []any{
			[]any{"42", []string{"ba:session:1"}},
			[]any{"0", []string{"ba:rate:1"}},
		}
		store := mustRedisBehaviorStore(t, client, "ba:")
		if err := store.Clear(t.Context()); err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"resolved": true, "scanCalls": redisStorageArguments(client.commandCalls("SCAN")),
			"delCalls": redisStorageArguments(client.commandCalls("DEL")), "keysCalls": len(client.commandCalls("KEYS")),
		}
	case "does not call DEL when clearing an empty store":
		client := newMockRedis()
		client.scanPages = []any{[]any{"0", []string{}}}
		store := mustRedisBehaviorStore(t, client, "ba:")
		if err := store.Clear(t.Context()); err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"resolved": true, "scanCalls": redisStorageArguments(client.commandCalls("SCAN")),
			"delCalls": redisStorageArguments(client.commandCalls("DEL")),
		}
	case "propagates a mid-iteration failure, leaving earlier pages deleted":
		readOnly := errors.New("READONLY You can't write against a read only replica.")
		client := newMockRedis()
		client.scanPages = []any{
			[]any{"9", []string{"ba:session:1"}},
			[]any{"0", []string{"ba:session:2"}},
		}
		client.commandErrors["DEL"] = []error{nil, readOnly}
		store := mustRedisBehaviorStore(t, client, "ba:")
		err := store.Clear(t.Context())
		if !errors.Is(err, readOnly) {
			t.Fatalf("clear error=%v", err)
		}
		return map[string]any{
			"error": readOnly.Error(), "delCalls": redisStorageArguments(client.commandCalls("DEL")),
		}
	case "lists keys via SCAN, stripping the prefix and deduping across pages":
		client := newMockRedis()
		client.scanPages = []any{
			[]any{"7", []string{"ba:session:1", "ba:session:2"}},
			[]any{"0", []string{"ba:session:2", "ba:rate:1"}},
		}
		store := mustRedisBehaviorStore(t, client, "ba:")
		result, err := store.ListKeys(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(result)
		return map[string]any{
			"result": result, "scanCalls": redisStorageArguments(client.commandCalls("SCAN")),
			"keysCalls": len(client.commandCalls("KEYS")),
		}
	case "escapes glob metacharacters in the prefix so SCAN matches it literally":
		client := newMockRedis()
		client.scanPages = []any{[]any{"0", []string{}}}
		store := mustRedisBehaviorStore(t, client, "ba[1]:")
		if err := store.Clear(t.Context()); err != nil {
			t.Fatal(err)
		}
		return map[string]any{"scanCalls": redisStorageArguments(client.commandCalls("SCAN"))}
	case "only sets the ttl on the call that creates the key":
		client := newMockRedis()
		store := mustRedisBehaviorStore(t, client, "ba:")
		results := make([]int64, 0, 2)
		for range 2 {
			result, err := store.Increment(t.Context(), "rate:2", 30)
			if err != nil {
				t.Fatal(err)
			}
			results = append(results, result)
		}
		evalCalls := client.commandCalls("EVAL")
		return map[string]any{
			"results": results, "evalCallCount": len(evalCalls),
			"firstScript": redisStorageScriptShape(evalCalls[0][1].(string)),
		}
	default:
		t.Fatalf("unknown Redis storage title %q", title)
		return nil
	}
}

func loadRedisStorageOracle(t *testing.T) redisStorageOracle {
	t.Helper()
	oracle := redisStorageOracle{Tests: redisStorageScenarios}
	if len(oracle.Tests) != 10 {
		t.Fatalf("Redis storage scenarios=%d, want 10", len(oracle.Tests))
	}
	for _, vector := range oracle.Tests {
		if vector.Title == "" || vector.Observation == nil {
			t.Fatalf("invalid Redis storage scenario: %#v", vector)
		}
	}
	return oracle
}

func mustRedisBehaviorStore(t *testing.T, client Commander, prefix string) *Store {
	t.Helper()
	store, err := New(client, Options{KeyPrefix: Prefix(prefix)})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func redisStorageArguments(calls [][]any) [][]any {
	result := make([][]any, 0, len(calls))
	for _, call := range calls {
		result = append(result, append([]any(nil), call[1:]...))
	}
	return result
}

func redisStorageScriptShape(script string) map[string]bool {
	return map[string]bool{
		"get":       strings.Contains(script, `redis.call("GET", KEYS[1])`),
		"del":       strings.Contains(script, `redis.call("DEL", KEYS[1])`),
		"incr":      strings.Contains(script, `redis.call("INCR", KEYS[1])`),
		"equalsOne": strings.Contains(script, "== 1"),
		"expire":    strings.Contains(script, `redis.call("EXPIRE"`),
	}
}

func assertRedisStorageJSON(t *testing.T, actual, expected any) {
	t.Helper()
	actualValue := normalizeRedisStorageValue(actual)
	expectedValue := normalizeRedisStorageValue(expected)
	if !reflect.DeepEqual(actualValue, expectedValue) {
		t.Fatalf("Redis storage observation=%#v want=%#v", actualValue, expectedValue)
	}
}

func normalizeRedisStorageValue(value any) any {
	if value == nil {
		return nil
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Interface, reflect.Pointer:
		if reflected.IsNil() {
			return nil
		}
		return normalizeRedisStorageValue(reflected.Elem().Interface())
	case reflect.Map:
		result := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			result[iterator.Key().String()] = normalizeRedisStorageValue(iterator.Value().Interface())
		}
		return result
	case reflect.Slice, reflect.Array:
		result := make([]any, reflected.Len())
		for index := range reflected.Len() {
			result[index] = normalizeRedisStorageValue(reflected.Index(index).Interface())
		}
		return result
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(reflected.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(reflected.Uint())
	case reflect.Float32, reflect.Float64:
		return reflected.Convert(reflect.TypeOf(float64(0))).Float()
	default:
		return value
	}
}
