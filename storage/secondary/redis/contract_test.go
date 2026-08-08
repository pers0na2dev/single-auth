package redis_test

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	redisstore "github.com/pers0na2dev/single-auth/storage/secondary/redis"
)

var (
	_ singleauth.SecondaryStorage       = (*redisstore.Store)(nil)
	_ singleauth.SecondaryGetAndDeleter = (*redisstore.Store)(nil)
	_ ratelimit.SecondaryIncrementer    = (*redisstore.Store)(nil)
)

type contractCommander struct {
	mu     sync.Mutex
	values map[string]string
	ttls   map[string]int64
}

func newContractCommander() *contractCommander {
	return &contractCommander{values: map[string]string{}, ttls: map[string]int64{}}
}

func (client *contractCommander) Do(_ context.Context, args ...any) (any, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	command := strings.ToUpper(args[0].(string))
	switch command {
	case "GET":
		value, exists := client.values[args[1].(string)]
		if !exists {
			return nil, nil
		}
		return value, nil
	case "SET":
		client.values[args[1].(string)] = args[2].(string)
		return "OK", nil
	case "SETEX":
		key := args[1].(string)
		client.values[key] = args[3].(string)
		client.ttls[key] = args[2].(int64)
		return "OK", nil
	case "DEL":
		delete(client.values, args[1].(string))
		return int64(1), nil
	case "GETDEL":
		key := args[1].(string)
		value, exists := client.values[key]
		delete(client.values, key)
		if !exists {
			return nil, nil
		}
		return value, nil
	case "EVAL":
		key := args[3].(string)
		current, _ := strconv.ParseInt(client.values[key], 10, 64)
		current++
		client.values[key] = strconv.FormatInt(current, 10)
		if current == 1 {
			client.ttls[key] = args[4].(int64)
		}
		return current, nil
	default:
		panic("unexpected command " + command)
	}
}

func TestRootSecondaryAndRateLimitContracts(t *testing.T) {
	client := newContractCommander()
	store, err := redisstore.New(client, redisstore.Options{KeyPrefix: redisstore.Prefix("contract:")})
	if err != nil {
		t.Fatal(err)
	}
	var secondary singleauth.SecondaryStorage = store
	if err := secondary.Set(t.Context(), "session", "payload", 90); err != nil {
		t.Fatal(err)
	}
	if value, err := secondary.Get(t.Context(), "session"); err != nil || value != "payload" {
		t.Fatalf("root get = %q, %v", value, err)
	}
	atomic := any(secondary).(singleauth.SecondaryGetAndDeleter)
	if value, err := atomic.GetAndDelete(t.Context(), "session"); err != nil || value != "payload" {
		t.Fatalf("root get-and-delete = %q, %v", value, err)
	}
	if value, err := secondary.Get(t.Context(), "session"); err != nil || value != "" {
		t.Fatalf("root missing get = %q, %v", value, err)
	}

	rateStore := ratelimit.NewSecondaryStore(store, ratelimit.SecondaryOptions{})
	rateAtomic, ok := rateStore.(ratelimit.AtomicStorage)
	if !ok {
		t.Fatal("Redis store did not activate atomic rate limiting")
	}
	for attempt := 1; attempt <= 3; attempt++ {
		decision, err := rateAtomic.Consume(t.Context(), "rate", ratelimit.Rule{Window: 17, Max: 2})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed != (attempt <= 2) {
			t.Fatalf("attempt %d allowed=%v", attempt, decision.Allowed)
		}
	}
	client.mu.Lock()
	ttl := client.ttls["contract:rate"]
	client.mu.Unlock()
	if ttl != 17 {
		t.Fatalf("fixed-window TTL = %d", ttl)
	}
}
