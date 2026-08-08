// Package sqlite implements the single-auth storage contract on top of an
// already opened SQLite database/sql handle. The package deliberately does not
// import a concrete SQL driver. The caller must configure connection-wide
// SQLite settings such as foreign_keys and busy_timeout through its driver;
// RETURNING and JSON functions must be available in the selected SQLite build.
package sqlite

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// IDGenerator creates a canonical identifier for a model.
type IDGenerator func(model string) (any, error)

// Options configure an Adapter. A zero Schema selects storage.CoreSchema and
// a zero DefaultFindManyLimit selects reference implementation's default of 100.
type Options struct {
	Schema               storage.Schema
	IDGenerator          IDGenerator
	Clock                func() time.Time
	DefaultFindManyLimit int
}

type config struct {
	schema       storage.Schema
	idGenerator  IDGenerator
	clock        func() time.Time
	defaultLimit int
	capabilities storage.Capabilities
}

func normalizeOptions(options Options) (config, error) {
	schema := options.Schema
	if len(schema.Models) == 0 {
		schema = storage.CoreSchema()
	}
	schema = schema.Clone()
	if err := schema.Validate(); err != nil {
		return config{}, fmt.Errorf("sqlite: schema: %w", err)
	}
	if err := validateReservedNames(schema); err != nil {
		return config{}, err
	}

	defaultLimit := options.DefaultFindManyLimit
	if defaultLimit == 0 {
		defaultLimit = 100
	}
	if defaultLimit < 0 {
		return config{}, fmt.Errorf("sqlite: default limit must be non-negative")
	}
	idGenerator := options.IDGenerator
	if idGenerator == nil {
		idGenerator = randomID
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}

	capabilities := storage.NativeCapabilities()
	capabilities.NumericIDs = false
	capabilities.JSON = false
	capabilities.Dates = false
	capabilities.Booleans = false
	capabilities.Arrays = false
	capabilities.SchemaCreation = true

	return config{
		schema:       schema,
		idGenerator:  idGenerator,
		clock:        clock,
		defaultLimit: defaultLimit,
		capabilities: capabilities,
	}, nil
}

func randomID(string) (any, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return nil, fmt.Errorf("sqlite: generate ID: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}
