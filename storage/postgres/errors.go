package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

type sqlStateError interface {
	SQLState() string
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func normalizeError(ctx context.Context, operation string, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	message := strings.ToLower(err.Error())
	if postgresSQLState(err) == "23505" ||
		strings.Contains(message, "duplicate key value violates unique constraint") ||
		strings.Contains(message, "duplicate key violates unique constraint") {
		return fmt.Errorf("%w: %s: %v", storage.ErrUniqueConstraint, operation, err)
	}
	return fmt.Errorf("postgres: %s: %w", operation, err)
}

func postgresSQLState(err error) string {
	for current := err; current != nil; current = errors.Unwrap(current) {
		var state sqlStateError
		if errors.As(current, &state) {
			return state.SQLState()
		}
		// lib/pq exposes Code as a field whose underlying type is string,
		// whereas pgx exposes SQLState(). Reflection keeps this package free of
		// either production driver while still normalizing both.
		value := reflect.ValueOf(current)
		if value.Kind() == reflect.Pointer && !value.IsNil() {
			value = value.Elem()
		}
		if value.IsValid() && value.Kind() == reflect.Struct {
			code := value.FieldByName("Code")
			if code.IsValid() && code.CanInterface() {
				if text := fmt.Sprint(code.Interface()); len(text) == 5 {
					return text
				}
			}
		}
	}
	return ""
}
