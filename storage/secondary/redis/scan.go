package redis

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ListKeys enumerates this store's keys through non-blocking SCAN pages,
// strips the configured prefix, and de-duplicates keys that SCAN repeats.
// Redis only guarantees best-effort visibility while the keyspace changes.
func (store *Store) ListKeys(ctx context.Context) ([]string, error) {
	seen := make(map[string]struct{})
	err := store.scan(ctx, func(keys []string) error {
		for _, key := range keys {
			if !strings.HasPrefix(key, store.prefix) {
				continue
			}
			seen[strings.TrimPrefix(key, store.prefix)] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(seen))
	for key := range seen {
		result = append(result, key)
	}
	sort.Strings(result)
	return result, nil
}

// Clear deletes this store's keys page by page using SCAN and batched DEL.
// It never uses blocking KEYS. Clear is idempotent but not atomic: an error
// after an earlier page was deleted leaves a partially cleared store.
func (store *Store) Clear(ctx context.Context) error {
	return store.scan(ctx, func(keys []string) error {
		// SCAN MATCH should already enforce this boundary, but validate replies
		// again before deletion so a buggy client/response decoder cannot make a
		// prefixed store delete an unrelated key.
		matched := make([]string, 0, len(keys))
		for _, key := range keys {
			if strings.HasPrefix(key, store.prefix) {
				matched = append(matched, key)
			}
		}
		if len(matched) == 0 {
			return nil
		}
		arguments := make([]any, 0, len(matched)+1)
		arguments = append(arguments, "DEL")
		for _, key := range matched {
			arguments = append(arguments, key)
		}
		_, err := store.client.Do(ctx, arguments...)
		return operationError(ctx, "DEL scan page", err)
	})
}

func (store *Store) scan(ctx context.Context, visit func([]string) error) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	cursor := "0"
	pattern := escapeGlob(store.prefix) + "*"
	for {
		reply, err := store.client.Do(ctx, "SCAN", cursor, "MATCH", pattern, "COUNT", store.scanCount)
		if err != nil {
			return operationError(ctx, "SCAN", err)
		}
		next, keys, err := scanReply(reply)
		if err != nil {
			return fmt.Errorf("redis secondary storage: SCAN: %w", err)
		}
		if len(keys) > 0 {
			if err := visit(keys); err != nil {
				return err
			}
		}
		cursor = next
		if cursor == "0" {
			return nil
		}
		if err := contextError(ctx); err != nil {
			return err
		}
	}
}

func escapeGlob(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, character := range value {
		switch character {
		case '\\', '*', '?', '[', ']':
			builder.WriteByte('\\')
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

func scanReply(reply any) (string, []string, error) {
	parts, ok := reply.([]any)
	if !ok || len(parts) != 2 {
		return "", nil, fmt.Errorf("%w: expected two-element SCAN array, got %T", ErrInvalidReply, reply)
	}
	cursor, err := cursorReply(parts[0])
	if err != nil {
		return "", nil, err
	}
	keys, err := keyArrayReply(parts[1])
	if err != nil {
		return "", nil, err
	}
	return cursor, keys, nil
}

func cursorReply(reply any) (string, error) {
	switch value := reply.(type) {
	case string:
		if _, err := strconv.ParseUint(value, 10, 64); err == nil {
			return value, nil
		}
	case []byte:
		text := string(value)
		if _, err := strconv.ParseUint(text, 10, 64); err == nil {
			return text, nil
		}
	case int64:
		if value >= 0 {
			return strconv.FormatInt(value, 10), nil
		}
	case uint64:
		return strconv.FormatUint(value, 10), nil
	}
	return "", fmt.Errorf("%w: invalid SCAN cursor %T", ErrInvalidReply, reply)
}

func keyArrayReply(reply any) ([]string, error) {
	switch values := reply.(type) {
	case []string:
		return append([]string(nil), values...), nil
	case []any:
		keys := make([]string, 0, len(values))
		for _, value := range values {
			key, err := stringReply(value)
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
		return keys, nil
	default:
		return nil, fmt.Errorf("%w: invalid SCAN keys %T", ErrInvalidReply, reply)
	}
}
