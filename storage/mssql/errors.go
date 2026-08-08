package mssql

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("mssql: nil context")
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
	number := mssqlErrorNumber(err)
	if number == 2601 || number == 2627 ||
		strings.Contains(message, "cannot insert duplicate key row") ||
		strings.Contains(message, "violation of unique key constraint") ||
		strings.Contains(message, "violation of primary key constraint") {
		return fmt.Errorf("%w: %s: %v", storage.ErrUniqueConstraint, operation, err)
	}
	return fmt.Errorf("mssql: %s: %w", operation, err)
}

func mssqlErrorNumber(err error) int64 {
	for current := err; current != nil; current = errors.Unwrap(current) {
		// microsoft/go-mssqldb exposes Number on its concrete error. Reflection
		// keeps this package free of a production driver dependency.
		value := reflect.ValueOf(current)
		if value.Kind() == reflect.Pointer && !value.IsNil() {
			value = value.Elem()
		}
		if value.IsValid() && value.Kind() == reflect.Struct {
			number := value.FieldByName("Number")
			if number.IsValid() {
				switch number.Kind() {
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					return number.Int()
				case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					if number.Uint() <= uint64(^uint64(0)>>1) {
						return int64(number.Uint())
					}
				}
			}
		}
	}
	return 0
}
