// Package mongodb implements the single-auth storage contract on top of the
// official MongoDB Go driver.
package mongodb

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// IDGenerator creates a canonical identifier for a model.
type IDGenerator func(model string) (any, error)

// IDType selects the BSON representation used by primary and foreign keys.
type IDType string

const (
	// ObjectID stores identifiers as BSON ObjectID values. This is the default
	// when no custom IDGenerator is configured, matching reference implementation's MongoDB
	// adapter.
	ObjectID IDType = "object-id"
	// UUIDID stores identifiers as RFC 4122 BSON binary subtype 4 values.
	UUIDID IDType = "uuid"
	// TextID stores identifiers as BSON strings. It is selected automatically
	// when a custom IDGenerator is supplied and IDType is omitted.
	TextID IDType = "text"
)

// Options configure an Adapter. A zero Schema selects storage.CoreSchema and
// a zero DefaultFindManyLimit selects reference implementation's default of 100.
type Options struct {
	Schema               storage.Schema
	IDGenerator          IDGenerator
	IDType               IDType
	Clock                func() time.Time
	DefaultFindManyLimit int
	// DisableTransactions is useful for standalone MongoDB deployments, which
	// do not support multi-document transactions. Transaction then returns
	// storage.ErrTransactionsUnsupported and Capabilities reports false.
	DisableTransactions bool
}

type config struct {
	schema       storage.Schema
	idGenerator  IDGenerator
	idType       IDType
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
		return config{}, fmt.Errorf("mongodb: schema: %w", err)
	}
	if err := validateMongoNames(schema); err != nil {
		return config{}, err
	}

	defaultLimit := options.DefaultFindManyLimit
	if defaultLimit == 0 {
		defaultLimit = 100
	}
	if defaultLimit < 0 {
		return config{}, fmt.Errorf("mongodb: default limit must be non-negative")
	}

	idType := options.IDType
	if idType == "" {
		if options.IDGenerator != nil {
			idType = TextID
		} else {
			idType = ObjectID
		}
	}
	if idType != ObjectID && idType != UUIDID && idType != TextID {
		return config{}, fmt.Errorf("mongodb: unsupported ID type %q", idType)
	}
	idGenerator := options.IDGenerator
	if idGenerator == nil && idType == TextID {
		idGenerator = randomTextID
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}

	capabilities := storage.NativeCapabilities()
	capabilities.NumericIDs = false
	capabilities.Transactions = !options.DisableTransactions
	capabilities.SchemaCreation = true

	return config{
		schema:       schema,
		idGenerator:  idGenerator,
		idType:       idType,
		clock:        clock,
		defaultLimit: defaultLimit,
		capabilities: capabilities,
	}, nil
}

func randomTextID(string) (any, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return nil, fmt.Errorf("mongodb: generate ID: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}
