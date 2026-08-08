package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// DatabaseOptions configures reference implementation's rateLimit model backend.
type DatabaseOptions struct {
	Model        string
	GlobalWindow int64
	Now          func() time.Time
	Error        func(string, error)
}

// DatabaseStore stores rate limits through the shared storage adapter and
// uses IncrementOne guards for strict concurrency behavior.
type DatabaseStore struct {
	adapter       storage.TransactionAdapter
	model         string
	longestWindow int64
	now           func() time.Time
	logError      func(string, error)
}

// NewDatabaseStore constructs an atomic database-backed store.
func NewDatabaseStore(adapter storage.TransactionAdapter, options DatabaseOptions) *DatabaseStore {
	modelName := options.Model
	if modelName == "" {
		modelName = "rateLimit"
	}
	longest := options.GlobalWindow
	if longest <= 0 {
		longest = DefaultWindow
	}
	// The password-reset special rule is the longest built-in rule.
	if longest < 60 {
		longest = 60
	}
	return &DatabaseStore{
		adapter:       adapter,
		model:         modelName,
		longestWindow: longest,
		now:           options.Now,
		logError:      options.Error,
	}
}

// Get reads one rateLimit row.
func (store *DatabaseStore) Get(ctx context.Context, key string) (*Record, error) {
	rows, err := store.adapter.FindMany(ctx, storage.FindManyParams{
		Model: store.model,
		Where: []storage.Where{{Field: "key", Value: key}},
		Limit: storage.Int(1),
	})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return decodeRateLimit(rows[0])
}

// Set implements reference implementation's legacy database storage operation. Like the
// upstream wrapper, write errors are logged and swallowed.
func (store *DatabaseStore) Set(ctx context.Context, key string, value Record, update bool, _ int64) error {
	value.Key = key
	var err error
	if update {
		_, err = store.adapter.UpdateMany(ctx, storage.UpdateManyParams{
			Model:  store.model,
			Where:  []storage.Where{{Field: "key", Value: key}},
			Update: storage.Record{"count": value.Count, "lastRequest": value.LastRequest},
		})
	} else {
		_, err = store.adapter.Create(ctx, storage.CreateParams{Model: store.model, Data: storage.Record{
			"key": key, "count": value.Count, "lastRequest": value.LastRequest,
		}})
	}
	if err != nil {
		store.error("Error setting rate limit", err)
	}
	return nil
}

// Consume atomically checks and advances one database counter.
func (store *DatabaseStore) Consume(ctx context.Context, key string, rule Rule) (ConsumeResult, error) {
	windowMillis := secondsToMillis(rule.Window)
	for {
		if err := ctx.Err(); err != nil {
			return ConsumeResult{}, err
		}
		data, err := store.Get(ctx, key)
		if err != nil {
			return ConsumeResult{}, err
		}
		now := unixMillis(store.now)
		if data == nil {
			_, createErr := store.adapter.Create(ctx, storage.CreateParams{Model: store.model, Data: storage.Record{
				"key": key, "count": int64(1), "lastRequest": now,
			}})
			if createErr == nil {
				return ConsumeResult{Allowed: true}, nil
			}
			existing, readErr := store.Get(ctx, key)
			if readErr != nil {
				return ConsumeResult{}, readErr
			}
			if existing == nil {
				return ConsumeResult{}, createErr
			}
			continue
		}

		if now-data.LastRequest > windowMillis {
			reset, incrementErr := store.adapter.IncrementOne(ctx, storage.IncrementOneParams{
				Model: store.model,
				Where: []storage.Where{
					{Field: "key", Value: key},
					{Field: "lastRequest", Operator: storage.OpLTE, Value: data.LastRequest},
				},
				Increment: map[string]float64{},
				Set:       storage.Record{"count": int64(1), "lastRequest": now},
			})
			if incrementErr != nil {
				return ConsumeResult{}, incrementErr
			}
			if reset != nil {
				store.prune(ctx, now)
				return ConsumeResult{Allowed: true}, nil
			}
			continue
		}

		incremented, incrementErr := store.adapter.IncrementOne(ctx, storage.IncrementOneParams{
			Model: store.model,
			Where: []storage.Where{
				{Field: "key", Value: key},
				{Field: "lastRequest", Operator: storage.OpGt, Value: now - windowMillis},
				{Field: "count", Operator: storage.OpLt, Value: rule.Max},
			},
			Increment: map[string]float64{"count": 1},
			Set:       storage.Record{"lastRequest": now},
		})
		if incrementErr != nil {
			return ConsumeResult{}, incrementErr
		}
		if incremented != nil {
			return ConsumeResult{Allowed: true}, nil
		}

		fresh, readErr := store.Get(ctx, key)
		if readErr != nil {
			return ConsumeResult{}, readErr
		}
		if fresh == nil || now-fresh.LastRequest > windowMillis {
			continue
		}
		retry := retryAfterAt(fresh.LastRequest, rule.Window, unixMillis(store.now))
		return ConsumeResult{Allowed: false, RetryAfter: &retry}, nil
	}
}

func (store *DatabaseStore) prune(ctx context.Context, now int64) {
	_, err := store.adapter.DeleteMany(ctx, storage.DeleteManyParams{
		Model: store.model,
		Where: []storage.Where{{
			Field: "lastRequest", Operator: storage.OpLt,
			Value: now - secondsToMillis(store.longestWindow),
		}},
	})
	if err != nil {
		store.error("Error pruning rate limit rows", err)
	}
}

func (store *DatabaseStore) error(message string, err error) {
	if store.logError != nil {
		store.logError(message, err)
	}
}

func decodeRateLimit(row storage.Record) (*Record, error) {
	key, ok := row["key"].(string)
	if !ok {
		return nil, fmt.Errorf("ratelimit: database key has type %T", row["key"])
	}
	count, err := numericInt64(row["count"])
	if err != nil {
		return nil, fmt.Errorf("ratelimit: database count: %w", err)
	}
	lastRequest, err := numericInt64(row["lastRequest"])
	if err != nil {
		return nil, fmt.Errorf("ratelimit: database lastRequest: %w", err)
	}
	return &Record{Key: key, Count: count, LastRequest: lastRequest}, nil
}

func numericInt64(value any) (int64, error) {
	switch number := value.(type) {
	case int:
		return int64(number), nil
	case int8:
		return int64(number), nil
	case int16:
		return int64(number), nil
	case int32:
		return int64(number), nil
	case int64:
		return number, nil
	case uint:
		if uint64(number) > math.MaxInt64 {
			return 0, fmt.Errorf("value %v overflows int64", number)
		}
		return int64(number), nil
	case uint8:
		return int64(number), nil
	case uint16:
		return int64(number), nil
	case uint32:
		return int64(number), nil
	case uint64:
		if number > math.MaxInt64 {
			return 0, fmt.Errorf("value %v overflows int64", number)
		}
		return int64(number), nil
	case float32:
		return checkedFloat(float64(number))
	case float64:
		return checkedFloat(number)
	case json.Number:
		return number.Int64()
	case string:
		return strconv.ParseInt(number, 10, 64)
	default:
		return 0, fmt.Errorf("unsupported numeric type %T", value)
	}
}

func checkedFloat(number float64) (int64, error) {
	if math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || number < math.MinInt64 || number > math.MaxInt64 {
		return 0, fmt.Errorf("invalid integer %v", number)
	}
	return int64(number), nil
}
