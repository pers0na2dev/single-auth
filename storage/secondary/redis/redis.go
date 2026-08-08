package redis

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	defaultKeyPrefix = "single-auth:"
	defaultScanCount = int64(100)

	getAndDeleteScript = `local value = redis.call("GET", KEYS[1])
if value ~= false then
  redis.call("DEL", KEYS[1])
end
return value`

	incrementScript = `local value = redis.call("INCR", KEYS[1])
if value == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return value`
)

var (
	// ErrInvalidClient means New received a nil Commander.
	ErrInvalidClient = errors.New("redis secondary storage: invalid client")
	// ErrInvalidTTL means Increment received a non-positive fixed-window TTL.
	ErrInvalidTTL = errors.New("redis secondary storage: increment TTL must be positive")
	// ErrInvalidReply means the Redis client returned a reply shape that cannot
	// be interpreted for the issued command.
	ErrInvalidReply = errors.New("redis secondary storage: invalid Redis reply")
)

// Commander is the minimal Redis client surface used by Store. Implementations
// execute one command and return its decoded RESP value. A missing bulk value
// should preferably be returned as (nil, nil); Options.IsNotFound can normalize
// clients that instead return a sentinel error such as redis.Nil.
//
// A go-redis adapter, for example, can forward to client.Do(ctx, args...).Result().
type Commander interface {
	Do(context.Context, ...any) (any, error)
}

// CommandFunc adapts a function to Commander.
type CommandFunc func(context.Context, ...any) (any, error)

func (function CommandFunc) Do(ctx context.Context, args ...any) (any, error) {
	return function(ctx, args...)
}

// Options configures Store.
type Options struct {
	// KeyPrefix is prepended verbatim to every key. Nil selects
	// "single-auth:"; a pointer to an empty string explicitly disables prefixing.
	KeyPrefix *string
	// ScanCount is Redis SCAN's per-page hint for ListKeys and Clear. Zero
	// selects 100.
	ScanCount int64
	// IsNotFound recognizes a client-specific missing-key sentinel error.
	IsNotFound func(error) bool
}

// Prefix returns a pointer suitable for Options.KeyPrefix, including an empty
// prefix when explicit unprefixed storage is desired.
func Prefix(value string) *string { return &value }

// Store is a concurrency-safe reference implementation Redis secondary store. It does not
// own or close the configured Commander.
type Store struct {
	client     Commander
	prefix     string
	scanCount  int64
	notFound   func(error) bool
	getDelMode atomic.Uint32
	getDelMu   sync.Mutex
}

const (
	getDelUnknown uint32 = iota
	getDelSupported
	getDelUnsupported
)

// New validates options and returns a Redis-backed secondary store.
func New(client Commander, options Options) (*Store, error) {
	if nilCommander(client) {
		return nil, ErrInvalidClient
	}
	prefix := defaultKeyPrefix
	if options.KeyPrefix != nil {
		prefix = *options.KeyPrefix
	}
	scanCount := options.ScanCount
	if scanCount == 0 {
		scanCount = defaultScanCount
	}
	if scanCount < 0 {
		return nil, fmt.Errorf("redis secondary storage: scan count must be positive")
	}
	return &Store{
		client: client, prefix: prefix, scanCount: scanCount, notFound: options.IsNotFound,
	}, nil
}

func nilCommander(client Commander) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// KeyPrefix returns the configured raw key prefix.
func (store *Store) KeyPrefix() string { return store.prefix }

// Get returns an empty string for a missing key.
func (store *Store) Get(ctx context.Context, key string) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	reply, err := store.client.Do(ctx, "GET", store.key(key))
	if err != nil {
		if store.isNotFound(err) {
			return "", nil
		}
		return "", operationError(ctx, "GET", err)
	}
	value, err := stringReply(reply)
	if err != nil {
		return "", fmt.Errorf("redis secondary storage: GET: %w", err)
	}
	return value, nil
}

// Set stores value persistently when ttlSeconds is non-positive and uses
// Redis SETEX when it is positive, matching reference implementation's Redis adapter.
func (store *Store) Set(ctx context.Context, key, value string, ttlSeconds int64) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	var err error
	if ttlSeconds > 0 {
		_, err = store.client.Do(ctx, "SETEX", store.key(key), ttlSeconds, value)
	} else {
		_, err = store.client.Do(ctx, "SET", store.key(key), value)
	}
	return operationError(ctx, "SET", err)
}

// Delete removes key. Removing a missing key succeeds.
func (store *Store) Delete(ctx context.Context, key string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	_, err := store.client.Do(ctx, "DEL", store.key(key))
	return operationError(ctx, "DEL", err)
}

// GetAndDelete atomically returns and removes key. Redis 6.2+ uses GETDEL;
// older servers use a Lua fallback. The capability state is synchronized so a
// concurrent first use does not issue a thundering herd of failed probes.
func (store *Store) GetAndDelete(ctx context.Context, key string) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	prefixed := store.key(key)
	switch store.getDelMode.Load() {
	case getDelUnsupported:
		return store.getAndDeleteLua(ctx, prefixed)
	case getDelSupported:
		return store.getAndDeleteNative(ctx, prefixed, false)
	}

	store.getDelMu.Lock()
	defer store.getDelMu.Unlock()
	switch store.getDelMode.Load() {
	case getDelUnsupported:
		return store.getAndDeleteLua(ctx, prefixed)
	case getDelSupported:
		return store.getAndDeleteNative(ctx, prefixed, false)
	default:
		return store.getAndDeleteNative(ctx, prefixed, true)
	}
}

func (store *Store) getAndDeleteNative(ctx context.Context, key string, probing bool) (string, error) {
	reply, err := store.client.Do(ctx, "GETDEL", key)
	if err != nil {
		if isUnknownCommand(err) {
			store.getDelMode.Store(getDelUnsupported)
			return store.getAndDeleteLua(ctx, key)
		}
		if store.isNotFound(err) {
			store.getDelMode.Store(getDelSupported)
			return "", nil
		}
		if probing {
			store.getDelMode.Store(getDelUnknown)
		}
		return "", operationError(ctx, "GETDEL", err)
	}
	store.getDelMode.Store(getDelSupported)
	value, decodeErr := stringReply(reply)
	if decodeErr != nil {
		return "", fmt.Errorf("redis secondary storage: GETDEL: %w", decodeErr)
	}
	return value, nil
}

func (store *Store) getAndDeleteLua(ctx context.Context, key string) (string, error) {
	reply, err := store.client.Do(ctx, "EVAL", getAndDeleteScript, int64(1), key)
	if err != nil {
		if store.isNotFound(err) {
			return "", nil
		}
		return "", operationError(ctx, "EVAL GET+DEL", err)
	}
	value, decodeErr := stringReply(reply)
	if decodeErr != nil {
		return "", fmt.Errorf("redis secondary storage: EVAL GET+DEL: %w", decodeErr)
	}
	return value, nil
}

// Increment atomically increments a fixed-window counter and applies expiry
// only when the counter is created (the INCR result is 1). Later increments do
// not extend the window TTL.
func (store *Store) Increment(ctx context.Context, key string, ttlSeconds int64) (int64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	if ttlSeconds <= 0 {
		return 0, fmt.Errorf("%w: %d", ErrInvalidTTL, ttlSeconds)
	}
	reply, err := store.client.Do(ctx, "EVAL", incrementScript, int64(1), store.key(key), ttlSeconds)
	if err != nil {
		return 0, operationError(ctx, "EVAL INCR+EXPIRE", err)
	}
	value, err := integerReply(reply)
	if err != nil {
		return 0, fmt.Errorf("redis secondary storage: EVAL INCR+EXPIRE: %w", err)
	}
	return value, nil
}

func (store *Store) key(key string) string { return store.prefix + key }

func (store *Store) isNotFound(err error) bool {
	return err != nil && store.notFound != nil && store.notFound(err)
}

func isUnknownCommand(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unknown command")
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("redis secondary storage: nil context")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func operationError(ctx context.Context, operation string, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("redis secondary storage: %s: %w", operation, err)
}

func stringReply(reply any) (string, error) {
	switch value := reply.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	case []byte:
		return string(value), nil
	default:
		return "", fmt.Errorf("%w: expected bulk string, got %T", ErrInvalidReply, reply)
	}
}

func integerReply(reply any) (int64, error) {
	switch value := reply.(type) {
	case int:
		return int64(value), nil
	case int8:
		return int64(value), nil
	case int16:
		return int64(value), nil
	case int32:
		return int64(value), nil
	case int64:
		return value, nil
	case uint:
		if uint64(value) > uint64(^uint64(0)>>1) {
			break
		}
		return int64(value), nil
	case uint8:
		return int64(value), nil
	case uint16:
		return int64(value), nil
	case uint32:
		return int64(value), nil
	case uint64:
		if value <= uint64(^uint64(0)>>1) {
			return int64(value), nil
		}
	case string:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			return parsed, nil
		}
	case []byte:
		parsed, err := strconv.ParseInt(string(value), 10, 64)
		if err == nil {
			return parsed, nil
		}
	}
	return 0, fmt.Errorf("%w: expected integer, got %T", ErrInvalidReply, reply)
}
