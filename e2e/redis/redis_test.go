package redis_e2e_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	redisstore "github.com/pers0na2dev/single-auth/storage/secondary/redis"
)

const redisImage = "redis:7.4.2-alpine@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952"

type commander struct {
	client *goredis.Client
}

func (value commander) Do(ctx context.Context, args ...any) (any, error) {
	return value.client.Do(ctx, args...).Result()
}

func TestRedisSecondaryStorageAgainstRealServer(t *testing.T) {
	ctx := t.Context()
	container, err := testcontainers.Run(
		ctx,
		redisImage,
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithOccurrence(1).
				WithStartupTimeout(45*time.Second),
		),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required Redis container: %v", err)
		}
		t.Skipf("Docker is unavailable for local Redis E2E: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("Redis container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate Redis container: %v", terminateErr)
		}
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatal(err)
	}
	client := goredis.NewClient(&goredis.Options{
		Addr: net.JoinHostPort(host, port.Port()),
	})
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("close Redis client: %v", closeErr)
		}
	})
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping Redis: %v", err)
	}

	prefix := "single-auth:e2e:"
	store, err := redisstore.New(commander{client: client}, redisstore.Options{
		KeyPrefix: redisstore.Prefix(prefix),
		IsNotFound: func(err error) bool {
			return errors.Is(err, goredis.Nil)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("set-get-ttl-list-and-clear", func(t *testing.T) {
		if err := store.Set(t.Context(), "session:a", `{"token":"a"}`, 30); err != nil {
			t.Fatal(err)
		}
		if err := store.Set(t.Context(), "session:b", `{"token":"b"}`, 0); err != nil {
			t.Fatal(err)
		}
		value, err := store.Get(t.Context(), "session:a")
		if err != nil || value != `{"token":"a"}` {
			t.Fatalf("get value=%q err=%v", value, err)
		}
		ttl, err := client.TTL(t.Context(), prefix+"session:a").Result()
		if err != nil || ttl <= 0 || ttl > 30*time.Second {
			t.Fatalf("ttl=%s err=%v", ttl, err)
		}
		keys, err := store.ListKeys(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(keys)
		if len(keys) != 2 || keys[0] != "session:a" || keys[1] != "session:b" {
			t.Fatalf("keys=%#v", keys)
		}
		if err := store.Clear(t.Context()); err != nil {
			t.Fatal(err)
		}
		keys, err = store.ListKeys(t.Context())
		if err != nil || len(keys) != 0 {
			t.Fatalf("keys after clear=%#v err=%v", keys, err)
		}
	})

	t.Run("get-and-delete-is-atomic", func(t *testing.T) {
		if err := store.Set(t.Context(), "verification", "winner", 30); err != nil {
			t.Fatal(err)
		}
		const racers = 32
		values := make(chan string, racers)
		errorsChannel := make(chan error, racers)
		var group sync.WaitGroup
		group.Add(racers)
		for range racers {
			go func() {
				defer group.Done()
				value, consumeErr := store.GetAndDelete(context.Background(), "verification")
				if consumeErr != nil {
					errorsChannel <- consumeErr
					return
				}
				if value != "" {
					values <- value
				}
			}()
		}
		group.Wait()
		close(values)
		close(errorsChannel)
		for consumeErr := range errorsChannel {
			t.Error(consumeErr)
		}
		var winners []string
		for value := range values {
			winners = append(winners, value)
		}
		if len(winners) != 1 || winners[0] != "winner" {
			t.Fatalf("atomic winners=%#v", winners)
		}
	})

	t.Run("increment-is-atomic-and-does-not-extend-ttl", func(t *testing.T) {
		const racers = 32
		counts := make(chan int64, racers)
		errorsChannel := make(chan error, racers)
		var group sync.WaitGroup
		group.Add(racers)
		for range racers {
			go func() {
				defer group.Done()
				count, incrementErr := store.Increment(context.Background(), "rate", 20)
				if incrementErr != nil {
					errorsChannel <- incrementErr
					return
				}
				counts <- count
			}()
		}
		group.Wait()
		close(counts)
		close(errorsChannel)
		for incrementErr := range errorsChannel {
			t.Error(incrementErr)
		}
		var observed []int64
		for count := range counts {
			observed = append(observed, count)
		}
		sort.Slice(observed, func(left, right int) bool { return observed[left] < observed[right] })
		if len(observed) != racers || observed[0] != 1 || observed[len(observed)-1] != racers {
			t.Fatalf("increment counts=%#v", observed)
		}
		before, err := client.TTL(t.Context(), prefix+"rate").Result()
		if err != nil || before <= 0 || before > 20*time.Second {
			t.Fatalf("initial rate ttl=%s err=%v", before, err)
		}
		time.Sleep(1100 * time.Millisecond)
		if _, err := store.Increment(t.Context(), "rate", 20); err != nil {
			t.Fatal(err)
		}
		after, err := client.TTL(t.Context(), prefix+"rate").Result()
		if err != nil || after >= before {
			t.Fatalf("rate ttl was extended: before=%s after=%s err=%v", before, after, err)
		}
	})
}
