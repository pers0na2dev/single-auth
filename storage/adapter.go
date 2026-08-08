// Package storage defines the transport- and database-neutral persistence
// contract used by single-auth.
package storage

import (
	"context"
	"errors"

	"github.com/pers0na2dev/single-auth/core/model"
)

// Record is a dynamic model row. A missing key and a present key containing
// nil intentionally mean different things (absent and explicit null).
type Record = model.Record

var (
	// ErrModelNotFound means a query referenced a model outside the adapter schema.
	ErrModelNotFound = errors.New("storage: model not found")
	// ErrFieldNotFound means a query referenced a field outside the model schema.
	ErrFieldNotFound = errors.New("storage: field not found")
	// ErrInvalidQuery means a query operator or operand is malformed.
	ErrInvalidQuery = errors.New("storage: invalid query")
	// ErrInvalidIncrement means IncrementOne has no assignments or a non-numeric value.
	ErrInvalidIncrement = errors.New("storage: invalid increment")
	// ErrTransactionsUnsupported means an adapter cannot provide rollback semantics.
	ErrTransactionsUnsupported = errors.New("storage: transactions unsupported")
	// ErrUniqueConstraint means a create or update would duplicate an id or a
	// schema field marked Unique.
	ErrUniqueConstraint = errors.New("storage: unique constraint violation")
)

// Capabilities describes the native behavior and scalar representations of an
// adapter. The public Adapter contract still requires atomic methods and
// Transaction; these flags let wrappers decide whether conversion or fallback
// behavior is needed for a concrete backend.
type Capabilities struct {
	NumericIDs       bool
	UUIDs            bool
	JSON             bool
	Dates            bool
	Booleans         bool
	Arrays           bool
	Transactions     bool
	Joins            bool
	SchemaCreation   bool
	AtomicConsumeOne bool
	AtomicIncrement  bool
}

// SchemaCreation is an adapter-generated schema artifact. Append and Overwrite
// are mutually independent flags for behavior with reference implementation's CLI contract;
// consumers should give Overwrite precedence when both are true.
type SchemaCreation struct {
	Code      string
	Path      string
	Append    bool
	Overwrite bool
}

// SchemaCreator is the optional schema-generation extension implemented by
// adapters that advertise Capabilities.SchemaCreation.
type SchemaCreator interface {
	CreateSchema(context.Context, Schema, string) (SchemaCreation, error)
}

// SchemaEnsurer is the optional runtime migration capability implemented by
// native adapters that can create or reconcile their configured schema.
type SchemaEnsurer interface {
	EnsureSchema(context.Context) error
}

// NativeCapabilities describes an adapter that stores every reference implementation value
// natively and implements the complete contract itself.
func NativeCapabilities() Capabilities {
	return Capabilities{
		NumericIDs:       true,
		UUIDs:            true,
		JSON:             true,
		Dates:            true,
		Booleans:         true,
		Arrays:           true,
		Transactions:     true,
		Joins:            true,
		SchemaCreation:   false,
		AtomicConsumeOne: true,
		AtomicIncrement:  true,
	}
}

// Adapter is the full reference implementation storage contract. A nil Record with nil
// error is the Go representation of an upstream null result.
type Adapter interface {
	TransactionAdapter

	ID() string
	Capabilities() Capabilities
	Transaction(context.Context, func(TransactionAdapter) error) error
}

// TransactionAdapter is the operation set exposed inside a transaction. It
// deliberately omits Transaction, matching reference implementation's DBTransactionAdapter.
type TransactionAdapter interface {
	Create(context.Context, CreateParams) (Record, error)
	FindOne(context.Context, FindOneParams) (Record, error)
	FindMany(context.Context, FindManyParams) ([]Record, error)
	Count(context.Context, CountParams) (int64, error)
	Update(context.Context, UpdateParams) (Record, error)
	UpdateMany(context.Context, UpdateManyParams) (int64, error)
	Delete(context.Context, DeleteParams) error
	DeleteMany(context.Context, DeleteManyParams) (int64, error)
	ConsumeOne(context.Context, ConsumeOneParams) (Record, error)
	IncrementOne(context.Context, IncrementOneParams) (Record, error)
}

type CreateParams struct {
	Model        string
	Data         Record
	Select       []string
	ForceAllowID bool
}

type FindOneParams struct {
	Model  string
	Where  []Where
	Select []string
	Join   map[string]JoinOption
}

type FindManyParams struct {
	Model  string
	Where  []Where
	Limit  *int
	Select []string
	SortBy *Sort
	Offset *int
	Join   map[string]JoinOption
}

type CountParams struct {
	Model string
	Where []Where
}

type UpdateParams struct {
	Model  string
	Where  []Where
	Update Record
}

type UpdateManyParams struct {
	Model  string
	Where  []Where
	Update Record
}

type DeleteParams struct {
	Model string
	Where []Where
}

type DeleteManyParams struct {
	Model string
	Where []Where
}

type ConsumeOneParams struct {
	Model string
	Where []Where
}

type IncrementOneParams struct {
	Model     string
	Where     []Where
	Increment map[string]float64
	Set       Record
}

// Int returns a pointer suitable for optional limit and offset fields.
func Int(value int) *int {
	return &value
}
