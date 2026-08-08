package mysql

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
		return errors.New("mysql: nil context")
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
	if mysqlErrorNumber(err) == 1062 ||
		strings.Contains(message, "duplicate entry") ||
		strings.Contains(message, "error 1062") {
		return fmt.Errorf("%w: %s: %v", storage.ErrUniqueConstraint, operation, err)
	}
	return fmt.Errorf("mysql: %s: %w", operation, err)
}

func mysqlErrorNumber(err error) uint64 {
	for current := err; current != nil; current = errors.Unwrap(current) {
		// go-sql-driver/mysql and common MariaDB drivers expose Number on their
		// concrete error type. Reflection keeps production driver selection in
		// the caller's module.
		value := reflect.ValueOf(current)
		if value.Kind() == reflect.Pointer && !value.IsNil() {
			value = value.Elem()
		}
		if value.IsValid() && value.Kind() == reflect.Struct {
			number := value.FieldByName("Number")
			if number.IsValid() {
				switch number.Kind() {
				case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					return number.Uint()
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					if number.Int() >= 0 {
						return uint64(number.Int())
					}
				}
			}
		}
	}
	return 0
}
