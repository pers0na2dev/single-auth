package mongodb

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/pers0na2dev/single-auth/storage"
)

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("mongodb: nil context")
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
	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("%w: %s: %v", storage.ErrUniqueConstraint, operation, err)
	}
	return fmt.Errorf("mongodb: %s: %w", operation, err)
}

func noDocument(err error) bool { return errors.Is(err, mongo.ErrNoDocuments) }
