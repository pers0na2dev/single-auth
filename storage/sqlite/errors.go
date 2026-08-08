package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

type sqliteErrorCoder interface {
	Code() int
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("sqlite: nil context")
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
	uniqueMessage := strings.Contains(message, "unique constraint") ||
		strings.Contains(message, "primary key constraint") ||
		strings.Contains(message, "is not unique")
	var coder sqliteErrorCoder
	if errors.As(err, &coder) {
		code := coder.Code()
		// 1555 and 2067 are SQLITE_CONSTRAINT_PRIMARYKEY and
		// SQLITE_CONSTRAINT_UNIQUE. Some drivers expose only primary code 19,
		// so require a uniqueness-specific message for that less precise form.
		if code == 1555 || code == 2067 || (code == 19 && uniqueMessage) {
			return fmt.Errorf("%w: %s: %v", storage.ErrUniqueConstraint, operation, err)
		}
	}
	if uniqueMessage {
		return fmt.Errorf("%w: %s: %v", storage.ErrUniqueConstraint, operation, err)
	}
	return fmt.Errorf("sqlite: %s: %w", operation, err)
}
