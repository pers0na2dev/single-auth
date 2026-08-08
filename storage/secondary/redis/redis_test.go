package redis

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var errRedisNil = errors.New("redis: nil")

type mockRedis struct {
	mu              sync.Mutex
	values          map[string]string
	ttls            map[string]int64
	calls           [][]any
	commandErrors   map[string][]error
	getDelSupported bool
	missingAsError  bool
	scanPages       []any
	scanIndex       int
}

func newMockRedis() *mockRedis {
	return &mockRedis{
		values: map[string]string{}, ttls: map[string]int64{}, commandErrors: map[string][]error{}, getDelSupported: true,
	}
}

func (mock *mockRedis) Do(ctx context.Context, arguments ...any) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	call := append([]any(nil), arguments...)
	mock.calls = append(mock.calls, call)
	if len(arguments) == 0 {
		return nil, errors.New("empty command")
	}
	command := strings.ToUpper(arguments[0].(string))
	if queued := mock.commandErrors[command]; len(queued) > 0 {
		err := queued[0]
		mock.commandErrors[command] = queued[1:]
		if err != nil {
			return nil, err
		}
	}
	switch command {
	case "GET":
		return mock.get(arguments[1].(string))
	case "SET":
		key, value := arguments[1].(string), arguments[2].(string)
		mock.values[key] = value
		delete(mock.ttls, key)
		return "OK", nil
	case "SETEX":
		key, ttl, value := arguments[1].(string), arguments[2].(int64), arguments[3].(string)
		mock.values[key] = value
		mock.ttls[key] = ttl
		return "OK", nil
	case "DEL":
		var deleted int64
		for _, raw := range arguments[1:] {
			key := raw.(string)
			if _, exists := mock.values[key]; exists {
				deleted++
			}
			delete(mock.values, key)
			delete(mock.ttls, key)
		}
		return deleted, nil
	case "GETDEL":
		if !mock.getDelSupported {
			return nil, errors.New("ERR unknown command 'GETDEL'")
		}
		key := arguments[1].(string)
		value, err := mock.get(key)
		if err != nil {
			return nil, err
		}
		delete(mock.values, key)
		delete(mock.ttls, key)
		return value, nil
	case "EVAL":
		script := arguments[1].(string)
		key := arguments[3].(string)
		if script == getAndDeleteScript {
			value, err := mock.get(key)
			if err != nil {
				return nil, err
			}
			delete(mock.values, key)
			delete(mock.ttls, key)
			return value, nil
		}
		if script == incrementScript {
			current, _ := strconv.ParseInt(mock.values[key], 10, 64)
			next := current + 1
			mock.values[key] = strconv.FormatInt(next, 10)
			if next == 1 {
				mock.ttls[key] = arguments[4].(int64)
			}
			return next, nil
		}
		return nil, errors.New("unknown script")
	case "SCAN":
		if mock.scanIndex >= len(mock.scanPages) {
			return []any{"0", []any{}}, nil
		}
		reply := mock.scanPages[mock.scanIndex]
		mock.scanIndex++
		return reply, nil
	default:
		return nil, fmt.Errorf("unsupported command %s", command)
	}
}

func (mock *mockRedis) get(key string) (any, error) {
	value, exists := mock.values[key]
	if !exists {
		if mock.missingAsError {
			return nil, errRedisNil
		}
		return nil, nil
	}
	return value, nil
}

func (mock *mockRedis) commandCalls(command string) [][]any {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	var result [][]any
	for _, call := range mock.calls {
		if strings.EqualFold(call[0].(string), command) {
			result = append(result, append([]any(nil), call...))
		}
	}
	return result
}

func (mock *mockRedis) snapshot(key string) (string, int64, bool) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	value, exists := mock.values[key]
	return value, mock.ttls[key], exists
}

func TestGetSetDeletePrefixTTLAndMissingNormalization(t *testing.T) {
	client := newMockRedis()
	client.missingAsError = true
	store, err := New(client, Options{IsNotFound: func(err error) bool { return errors.Is(err, errRedisNil) }})
	if err != nil {
		t.Fatal(err)
	}
	if store.KeyPrefix() != "single-auth:" {
		t.Fatalf("prefix = %q", store.KeyPrefix())
	}
	if err := store.Set(t.Context(), "session", "payload", 60); err != nil {
		t.Fatal(err)
	}
	if value, ttl, exists := client.snapshot("single-auth:session"); !exists || value != "payload" || ttl != 60 {
		t.Fatalf("stored value=%q ttl=%d exists=%v", value, ttl, exists)
	}
	if got, err := store.Get(t.Context(), "session"); err != nil || got != "payload" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if err := store.Set(t.Context(), "persistent", "value", 0); err != nil {
		t.Fatal(err)
	}
	if value, ttl, exists := client.snapshot("single-auth:persistent"); !exists || value != "value" || ttl != 0 {
		t.Fatalf("persistent value=%q ttl=%d exists=%v", value, ttl, exists)
	}
	if err := store.Delete(t.Context(), "session"); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(t.Context(), "session"); err != nil || got != "" {
		t.Fatalf("missing get = %q, %v", got, err)
	}

	wantSetEX := []any{"SETEX", "single-auth:session", int64(60), "payload"}
	if calls := client.commandCalls("SETEX"); len(calls) != 1 || !reflect.DeepEqual(calls[0], wantSetEX) {
		t.Fatalf("SETEX calls = %#v", calls)
	}
	if calls := client.commandCalls("SET"); len(calls) != 1 || !reflect.DeepEqual(calls[0], []any{"SET", "single-auth:persistent", "value"}) {
		t.Fatalf("SET calls = %#v", calls)
	}
}

func TestConstructorValidationExplicitEmptyPrefixAndCancellation(t *testing.T) {
	if _, err := New(nil, Options{}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("nil client error = %v", err)
	}
	var typedNil *mockRedis
	if _, err := New(typedNil, Options{}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("typed nil client error = %v", err)
	}
	client := newMockRedis()
	if _, err := New(client, Options{ScanCount: -1}); err == nil {
		t.Fatal("negative scan count accepted")
	}
	store, err := New(client, Options{KeyPrefix: Prefix("")})
	if err != nil {
		t.Fatal(err)
	}
	if store.KeyPrefix() != "" {
		t.Fatalf("explicit prefix = %q", store.KeyPrefix())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Get(ctx, "key"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("cancelled call reached Redis: %#v", client.calls)
	}
}

func TestGetAndDeleteNativeFallbackAndErrors(t *testing.T) {
	t.Run("native", func(t *testing.T) {
		client := newMockRedis()
		client.values["ba:verification"] = "secret"
		store, err := New(client, Options{KeyPrefix: Prefix("ba:")})
		if err != nil {
			t.Fatal(err)
		}
		first, err := store.GetAndDelete(t.Context(), "verification")
		if err != nil || first != "secret" {
			t.Fatalf("first = %q, %v", first, err)
		}
		second, err := store.GetAndDelete(t.Context(), "verification")
		if err != nil || second != "" {
			t.Fatalf("second = %q, %v", second, err)
		}
		if len(client.commandCalls("GETDEL")) != 2 || len(client.commandCalls("EVAL")) != 0 {
			t.Fatalf("calls = %#v", client.calls)
		}
	})

	t.Run("lua-fallback-is-cached", func(t *testing.T) {
		client := newMockRedis()
		client.getDelSupported = false
		client.values["ba:first"] = "one"
		client.values["ba:second"] = "two"
		store, err := New(client, Options{KeyPrefix: Prefix("ba:")})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := store.GetAndDelete(t.Context(), "first"); err != nil || got != "one" {
			t.Fatalf("first = %q, %v", got, err)
		}
		if got, err := store.GetAndDelete(t.Context(), "second"); err != nil || got != "two" {
			t.Fatalf("second = %q, %v", got, err)
		}
		if got := len(client.commandCalls("GETDEL")); got != 1 {
			t.Fatalf("GETDEL probes = %d", got)
		}
		calls := client.commandCalls("EVAL")
		if len(calls) != 2 || calls[0][1] != getAndDeleteScript || calls[0][2] != int64(1) || calls[0][3] != "ba:first" {
			t.Fatalf("EVAL calls = %#v", calls)
		}
	})

	t.Run("operational-error-does-not-fallback", func(t *testing.T) {
		client := newMockRedis()
		client.commandErrors["GETDEL"] = []error{errors.New("NOAUTH Authentication required")}
		store, err := New(client, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetAndDelete(t.Context(), "key"); err == nil || !strings.Contains(err.Error(), "NOAUTH") {
			t.Fatalf("error = %v", err)
		}
		if len(client.commandCalls("EVAL")) != 0 {
			t.Fatalf("unexpected fallback: %#v", client.calls)
		}
	})
}

func TestConcurrentGetAndDeleteHasOneWinnerAndOneCapabilityProbe(t *testing.T) {
	client := newMockRedis()
	client.getDelSupported = false
	client.values["ba:once"] = "winner"
	store, err := New(client, Options{KeyPrefix: Prefix("ba:")})
	if err != nil {
		t.Fatal(err)
	}
	const racers = 128
	start := make(chan struct{})
	results := make(chan string, racers)
	errorsChannel := make(chan error, racers)
	var wait sync.WaitGroup
	for range racers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			value, err := store.GetAndDelete(context.Background(), "once")
			if err != nil {
				errorsChannel <- err
				return
			}
			results <- value
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	winners := 0
	for result := range results {
		if result == "winner" {
			winners++
		} else if result != "" {
			t.Errorf("unexpected result %q", result)
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d", winners)
	}
	if probes := len(client.commandCalls("GETDEL")); probes != 1 {
		t.Fatalf("GETDEL probes = %d", probes)
	}
}

func TestIncrementFixedWindowAndConcurrentSafety(t *testing.T) {
	client := newMockRedis()
	store, err := New(client, Options{KeyPrefix: Prefix("ba:")})
	if err != nil {
		t.Fatal(err)
	}
	for index, ttl := range []int64{60, 120, 120} {
		got, err := store.Increment(t.Context(), "rate", ttl)
		if err != nil || got != int64(index+1) {
			t.Fatalf("increment %d = %d, %v", index, got, err)
		}
	}
	if value, ttl, exists := client.snapshot("ba:rate"); !exists || value != "3" || ttl != 60 {
		t.Fatalf("counter value=%q ttl=%d exists=%v", value, ttl, exists)
	}
	if _, err := store.Increment(t.Context(), "invalid", 0); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("invalid TTL error = %v", err)
	}

	const racers = 256
	start := make(chan struct{})
	values := make(chan int64, racers)
	errorsChannel := make(chan error, racers)
	var wait sync.WaitGroup
	for range racers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			value, err := store.Increment(context.Background(), "parallel", 30)
			if err != nil {
				errorsChannel <- err
				return
			}
			values <- value
		}()
	}
	close(start)
	wait.Wait()
	close(values)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	seen := make([]int, racers)
	for value := range values {
		if value < 1 || value > racers {
			t.Fatalf("counter result = %d", value)
		}
		seen[value-1]++
	}
	for index, count := range seen {
		if count != 1 {
			t.Fatalf("result %d appeared %d times", index+1, count)
		}
	}
	if value, ttl, exists := client.snapshot("ba:parallel"); !exists || value != "256" || ttl != 30 {
		t.Fatalf("parallel value=%q ttl=%d exists=%v", value, ttl, exists)
	}
}

func TestListKeysUsesEscapedScanAndDeduplicates(t *testing.T) {
	client := newMockRedis()
	client.scanPages = []any{
		[]any{[]byte("7"), []any{[]byte("ba[1]:session:1"), "ba[1]:session:2"}},
		[]any{int64(0), []string{"ba[1]:session:2", "ba[1]:rate:1", "unrelated"}},
	}
	store, err := New(client, Options{KeyPrefix: Prefix("ba[1]:"), ScanCount: 25})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.ListKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rate:1", "session:1", "session:2"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys = %#v, want %#v", keys, want)
	}
	calls := client.commandCalls("SCAN")
	if len(calls) != 2 || !reflect.DeepEqual(calls[0], []any{"SCAN", "0", "MATCH", `ba\[1\]:*`, "COUNT", int64(25)}) || calls[1][1] != "7" {
		t.Fatalf("SCAN calls = %#v", calls)
	}
}

func TestClearPagesEmptyStoreAndPartialFailure(t *testing.T) {
	t.Run("pages-and-empty-page", func(t *testing.T) {
		client := newMockRedis()
		client.values["ba:one"] = "1"
		client.values["ba:two"] = "2"
		client.scanPages = []any{
			[]any{"5", []any{}},
			[]any{"0", []any{"ba:one", "unrelated", "ba:two"}},
		}
		store, err := New(client, Options{KeyPrefix: Prefix("ba:")})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Clear(t.Context()); err != nil {
			t.Fatal(err)
		}
		calls := client.commandCalls("DEL")
		if len(calls) != 1 || !reflect.DeepEqual(calls[0], []any{"DEL", "ba:one", "ba:two"}) {
			t.Fatalf("DEL calls = %#v", calls)
		}
	})

	t.Run("empty", func(t *testing.T) {
		client := newMockRedis()
		client.scanPages = []any{[]any{"0", []any{}}}
		store, _ := New(client, Options{})
		if err := store.Clear(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(client.commandCalls("DEL")) != 0 {
			t.Fatalf("empty clear called DEL: %#v", client.calls)
		}
	})

	t.Run("partial-failure", func(t *testing.T) {
		client := newMockRedis()
		client.values["ba:one"] = "1"
		client.values["ba:two"] = "2"
		client.scanPages = []any{
			[]any{"9", []any{"ba:one"}},
			[]any{"0", []any{"ba:two"}},
		}
		client.commandErrors["DEL"] = []error{nil, errors.New("READONLY replica")}
		store, _ := New(client, Options{KeyPrefix: Prefix("ba:")})
		err := store.Clear(t.Context())
		if err == nil || !strings.Contains(err.Error(), "READONLY") {
			t.Fatalf("partial error = %v", err)
		}
		if _, _, exists := client.snapshot("ba:one"); exists {
			t.Fatal("first page was not deleted")
		}
		if _, _, exists := client.snapshot("ba:two"); !exists {
			t.Fatal("failed second page was deleted")
		}
	})
}

func TestReplyValidationAndScriptShape(t *testing.T) {
	if !strings.Contains(getAndDeleteScript, `redis.call("GET", KEYS[1])`) || !strings.Contains(getAndDeleteScript, `redis.call("DEL", KEYS[1])`) {
		t.Fatalf("get-delete script = %q", getAndDeleteScript)
	}
	if !strings.Contains(incrementScript, `redis.call("INCR", KEYS[1])`) || !strings.Contains(incrementScript, "value == 1") || !strings.Contains(incrementScript, `redis.call("EXPIRE", KEYS[1], ARGV[1])`) {
		t.Fatalf("increment script = %q", incrementScript)
	}
	for _, reply := range []any{int64(1), "2", []byte("3"), uint32(4)} {
		if _, err := integerReply(reply); err != nil {
			t.Fatalf("integer reply %#v: %v", reply, err)
		}
	}
	if _, err := integerReply(struct{}{}); !errors.Is(err, ErrInvalidReply) {
		t.Fatalf("integer invalid reply = %v", err)
	}
	if _, _, err := scanReply([]any{"not-a-cursor", []any{}}); !errors.Is(err, ErrInvalidReply) {
		t.Fatalf("scan invalid reply = %v", err)
	}
}
