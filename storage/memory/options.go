// Package memory provides the concurrent in-memory single-auth adapter.
package memory

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

type IDGenerator func(model string) (any, error)

// Database is the caller-owned, adapter-native backing store used by
// reference implementation's memory adapter. The adapter serializes access internally, but
// callers must not read or mutate the map concurrently with adapter operations.
type Database map[string][]storage.Record

type Option func(*config) error

type config struct {
	schema       storage.Schema
	capabilities storage.Capabilities
	idGenerator  IDGenerator
	clock        func() time.Time
	defaultLimit int
	initial      map[string][]storage.Record
	backing      Database
}

// WithDatabase uses database as the adapter's backing object instead of
// allocating a private map. Mutations and successful transaction commits keep
// the map identity intact, matching @single-auth/memory-adapter's MemoryDB
// contract. Records already present in the map must use adapter-native physical
// model and field names.
func WithDatabase(database Database) Option {
	return func(config *config) error {
		if database == nil {
			return fmt.Errorf("memory: database is nil")
		}
		config.backing = database
		return nil
	}
}

func defaultConfig() config {
	return config{
		schema:       storage.CoreSchema(),
		capabilities: storage.NativeCapabilities(),
		idGenerator:  randomID,
		clock:        time.Now,
		defaultLimit: 100,
	}
}

// WithSchema replaces the default core schema. Compose plugin fields with
// storage.Schema.Merge before passing the result.
func WithSchema(schema storage.Schema) Option {
	return func(config *config) error {
		config.schema = schema.Clone()
		return nil
	}
}

// WithInitialData seeds canonical records at construction time. Input is deep
// copied and then passed through the same transforms as Create.
func WithInitialData(data map[string][]storage.Record) Option {
	return func(config *config) error {
		config.initial = data
		return nil
	}
}

// WithIDGenerator injects deterministic, serial, or backend-shaped IDs.
func WithIDGenerator(generator IDGenerator) Option {
	return func(config *config) error {
		if generator == nil {
			return fmt.Errorf("memory: ID generator is nil")
		}
		config.idGenerator = generator
		return nil
	}
}

// WithClock injects the clock used by schema defaults and on-update values.
func WithClock(clock func() time.Time) Option {
	return func(config *config) error {
		if clock == nil {
			return fmt.Errorf("memory: clock is nil")
		}
		config.clock = clock
		return nil
	}
}

// WithDefaultFindManyLimit changes reference implementation's default limit of 100.
func WithDefaultFindManyLimit(limit int) Option {
	return func(config *config) error {
		if limit < 0 {
			return fmt.Errorf("memory: default limit must be non-negative")
		}
		config.defaultLimit = limit
		return nil
	}
}

// WithScalarCapabilities exercises adapter-factory conversions while retaining
// memory's native transaction, join, and atomic-operation guarantees.
func WithScalarCapabilities(capabilities storage.Capabilities) Option {
	return func(config *config) error {
		capabilities.Transactions = true
		capabilities.Joins = true
		capabilities.AtomicConsumeOne = true
		capabilities.AtomicIncrement = true
		config.capabilities = capabilities
		return nil
	}
}

func randomID(string) (any, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("memory: generate ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
