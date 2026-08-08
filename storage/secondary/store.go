// Package secondary defines optional key-value storage contracts used for
// sessions, verification values, and rate-limit counters.
package secondary

import "context"

// Storage is the string-valued secondary storage contract.
type Storage interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string, int64) error
	Delete(context.Context, string) error
}

// GetAndDeleter provides cross-process atomic consumption for single-use
// values.
type GetAndDeleter interface {
	GetAndDelete(context.Context, string) (string, error)
}

// ValueStorage is the object-valued form of Storage. Set receives canonical
// JSON while GetValue may return an already-decoded value.
type ValueStorage interface {
	GetValue(context.Context, string) (any, error)
	Set(context.Context, string, string, int64) error
	Delete(context.Context, string) error
}

// ValueGetAndDeleter provides atomic consumption for object-valued stores.
type ValueGetAndDeleter interface {
	GetAndDeleteValue(context.Context, string) (any, error)
}
