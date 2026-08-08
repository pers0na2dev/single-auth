// Package mysql implements the single-auth storage contract on top of an
// already opened MySQL database/sql handle. It deliberately imports no
// concrete MySQL driver; the caller owns and closes the handle.
package mysql

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// IDGenerator creates a canonical identifier for a model.
type IDGenerator func(model string) (any, error)

// IDType selects the physical MySQL primary-key representation.
type IDType string

const (
	// TextID stores generated identifiers in VARCHAR(36) columns.
	TextID IDType = "text"
	// UUIDID stores RFC 4122 identifiers in VARCHAR(36) columns. reference implementation's
	// MySQL adapters generate these client-side because MySQL has no native UUID
	// type or portable UUID default.
	UUIDID IDType = "uuid"
	// SerialID uses INTEGER AUTO_INCREMENT. Missing IDs are omitted from INSERT
	// and recovered through database/sql Result.LastInsertId.
	SerialID IDType = "serial"
)

// Options configure an Adapter. A zero Schema selects storage.CoreSchema and
// a zero DefaultFindManyLimit selects reference implementation's default of 100.
type Options struct {
	Schema               storage.Schema
	IDGenerator          IDGenerator
	IDType               IDType
	Clock                func() time.Time
	DefaultFindManyLimit int
}

type config struct {
	schema       storage.Schema
	idGenerator  IDGenerator
	clock        func() time.Time
	defaultLimit int
	idType       IDType
	databaseID   bool
	capabilities storage.Capabilities
}

func normalizeOptions(options Options) (config, error) {
	schema := options.Schema
	if len(schema.Models) == 0 {
		schema = storage.CoreSchema()
	}
	schema = schema.Clone()
	if err := schema.Validate(); err != nil {
		return config{}, fmt.Errorf("mysql: schema: %w", err)
	}
	if err := validateReservedNames(schema); err != nil {
		return config{}, err
	}

	defaultLimit := options.DefaultFindManyLimit
	if defaultLimit == 0 {
		defaultLimit = 100
	}
	if defaultLimit < 0 {
		return config{}, fmt.Errorf("mysql: default limit must be non-negative")
	}
	idGenerator := options.IDGenerator
	idType := options.IDType
	if idType == "" {
		idType = TextID
	}
	if idType != TextID && idType != UUIDID && idType != SerialID {
		return config{}, fmt.Errorf("mysql: unsupported ID type %q", idType)
	}
	databaseID := idType == SerialID
	if idGenerator == nil && !databaseID {
		if idType == UUIDID {
			idGenerator = randomUUID
		} else {
			idGenerator = randomID
		}
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}

	capabilities := storage.NativeCapabilities()
	capabilities.NumericIDs = idType == SerialID
	// These flags follow reference implementation's MySQL adapters. MySQL has JSON and
	// BOOLEAN syntax, but drivers exchange JSON as text and booleans as integer
	// scalars, so the adapter performs the conversions itself.
	capabilities.UUIDs = false
	capabilities.JSON = false
	capabilities.Booleans = false
	capabilities.Arrays = false
	capabilities.SchemaCreation = true

	return config{
		schema:       schema,
		idGenerator:  idGenerator,
		clock:        clock,
		defaultLimit: defaultLimit,
		idType:       idType,
		databaseID:   databaseID,
		capabilities: capabilities,
	}, nil
}

func randomID(string) (any, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return nil, fmt.Errorf("mysql: generate ID: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func randomUUID(string) (any, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return nil, fmt.Errorf("mysql: generate UUID: %w", err)
	}
	buffer[6] = (buffer[6] & 0x0f) | 0x40
	buffer[8] = (buffer[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buffer[0:4], buffer[4:6], buffer[6:8], buffer[8:10], buffer[10:16]), nil
}
