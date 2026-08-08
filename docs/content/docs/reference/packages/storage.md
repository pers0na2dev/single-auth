---
title: "github.com/pers0na2dev/single-auth/storage"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/storage.

- Import path: `github.com/pers0na2dev/single-auth/storage`
- Package name: `storage`

Package storage defines the transport- and database-neutral persistence
contract used by single-auth.

## Variables

```go
var (
	ErrModelNotFound = errors.New("storage: model not found")

	ErrFieldNotFound = errors.New("storage: field not found")

	ErrInvalidQuery = errors.New("storage: invalid query")

	ErrInvalidIncrement = errors.New("storage: invalid increment")

	ErrTransactionsUnsupported = errors.New("storage: transactions unsupported")

	ErrUniqueConstraint = errors.New("storage: unique constraint violation")
)
```

## Functions

### `Bool`

Bool returns a bool pointer for explicit DB field flags.

```go
func Bool(value bool) *bool
```

### `DecodeValue`

DecodeValue reverses EncodeValue and then applies the configured output transform.

```go
func DecodeValue(capabilities Capabilities, field FieldAttribute, value any) (any, error)
```

### `EncodeValue`

EncodeValue converts a canonical value into a backend representation based
on capabilities, matching reference implementation's adapter factory conversions.

```go
func EncodeValue(capabilities Capabilities, field FieldAttribute, value any) (any, error)
```

### `Int`

Int returns a pointer suitable for optional limit and offset fields.

```go
func Int(value int) *int
```

### `RunWithTransaction`

RunWithTransaction mirrors reference implementation's transaction context behavioral compatibility. A
nested call reuses the active transaction instead of asking an adapter to
open another one.

```go
func RunWithTransaction(
	ctx context.Context,
	adapter Adapter,
	callback func(context.Context, TransactionAdapter) error,
) error
```

## Types

### `Adapter`

Adapter is the full reference implementation storage contract. A nil Record with nil
error is the Go representation of an upstream null result.

```go
type Adapter interface {
	TransactionAdapter

	ID() string
	Capabilities() Capabilities
	Transaction(context.Context, func(TransactionAdapter) error) error
}
```

## Constructors and functions for `Adapter`

### `NewAdapterFactory`

NewAdapterFactory wraps a custom adapter with reference implementation-compatible model,
field, value, transaction, and atomic-operation behavioral compatibility.

```go
func NewAdapterFactory(config AdapterFactoryConfig, driver CustomAdapter) (Adapter, error)
```

### `AdapterAction`

AdapterAction is the operation currently being normalized by an adapter
factory. The stable string values let custom adapters share one set of
transport-independent transformation rules.

```go
type AdapterAction string
```

## Constants associated with `AdapterAction`

```go
const (
	ActionCreate       AdapterAction = "create"
	ActionUpdate       AdapterAction = "update"
	ActionUpdateMany   AdapterAction = "updateMany"
	ActionFindOne      AdapterAction = "findOne"
	ActionFindMany     AdapterAction = "findMany"
	ActionDelete       AdapterAction = "delete"
	ActionDeleteMany   AdapterAction = "deleteMany"
	ActionConsumeOne   AdapterAction = "consumeOne"
	ActionIncrementOne AdapterAction = "incrementOne"
	ActionCount        AdapterAction = "count"
)
```

### `AdapterFactoryConfig`

AdapterFactoryConfig describes the compatibility boundary between the
canonical single-auth storage contract and an adapter-native driver.

A nil Capabilities value selects reference implementation's factory defaults: native
numbers, dates, and booleans; stringified JSON and arrays; no native joins.
Transaction callbacks receive an already factory-wrapped transaction
adapter, just like reference implementation's DBTransactionAdapter callback.

```go
type AdapterFactoryConfig struct {
	AdapterID   string
	AdapterName string
	Schema      Schema

	Capabilities         *Capabilities
	DefaultFindManyLimit int
	// IDGeneration mirrors advanced.database.generateId. UseNumericIDs is kept
	// as a compatibility alias for IDGenerationSerial.
	IDGeneration        IDGenerationMode
	UseNumericIDs       bool
	DisableIDGeneration bool
	Clock               func() time.Time
	// GenerateID is the end-user generator and has priority over
	// CustomIDGenerator, matching reference implementation's function-valued generateId.
	GenerateID        func(model string) (any, error)
	CustomIDGenerator IDGenerator
	Random            io.Reader
	Warn              func(message string)

	MapKeysTransformInput  map[string]string
	MapKeysTransformOutput map[string]string
	DisableTransformInput  bool
	DisableTransformOutput bool
	DisableTransformJoin   bool

	TransformInput  func(AdapterTransformContext) (any, error)
	TransformOutput func(AdapterOutputTransformContext) (any, error)
	Transaction     func(context.Context, func(TransactionAdapter) error) error
}
```

### `AdapterOutputTransformContext`

AdapterOutputTransformContext is the output counterpart of
AdapterTransformContext. Field is the canonical field name exposed by the
public Adapter contract.

```go
type AdapterOutputTransformContext struct {
	Data           any
	Field          string
	FieldAttribute FieldAttribute
	Model          string
	Schema         Schema
	Select         []string
}
```

### `AdapterTransformContext`

AdapterTransformContext is supplied to custom scalar transformations after
schema aliases and the factory's built-in representation conversions have
been applied.

```go
type AdapterTransformContext struct {
	Action         AdapterAction
	Data           any
	Field          string
	FieldAttribute FieldAttribute
	Model          string
	Schema         Schema
}
```

### `AuthModelOptions`

AuthModelOptions configure one of reference implementation's four core models.
Fields maps canonical field names to their physical database names, while
AdditionalFields are merged last and may replace core or plugin metadata.

```go
type AuthModelOptions struct {
	ModelName        string
	Fields           map[string]string
	AdditionalFields map[string]FieldAttribute
}
```

### `AuthPluginTable`

AuthPluginTable is the schema shape exposed by a reference implementation plugin.
DisableMigration is a pointer because an omitted value preserves the value
contributed by an earlier plugin, while an explicit false clears it.

```go
type AuthPluginTable struct {
	Fields           map[string]FieldAttribute
	ModelName        string
	DisableMigration *bool
}
```

### `AuthRateLimitTableOptions`

AuthRateLimitTableOptions configure reference implementation's optional database-backed
rate-limit table. Storage accepts the same values as reference implementation; only
"database" materializes the built-in table.

```go
type AuthRateLimitTableOptions struct {
	Storage   string
	ModelName string
	Fields    map[string]string
}
```

### `AuthSessionTableOptions`

AuthSessionTableOptions configure the session table and its persistence
when a secondary store is present.

```go
type AuthSessionTableOptions struct {
	AuthModelOptions
	StoreSessionInDatabase bool
}
```

### `AuthTablesOptions`

AuthTablesOptions are the storage-relevant subset of CompatibilityOptions.
SecondaryStorage records presence rather than a concrete implementation;
getAuthTables only branches on whether the option was configured.

```go
type AuthTablesOptions struct {
	User             AuthModelOptions
	Session          AuthSessionTableOptions
	Account          AuthModelOptions
	Verification     AuthVerificationTableOptions
	RateLimit        AuthRateLimitTableOptions
	SecondaryStorage bool
	Plugins          []AuthTablesPlugin
}
```

### `AuthTablesPlugin`

AuthTablesPlugin contributes tables in plugin order. Later plugins replace
fields with the same canonical name and otherwise accumulate metadata.

```go
type AuthTablesPlugin struct {
	ID     string
	Schema map[string]AuthPluginTable
}
```

### `AuthVerificationTableOptions`

AuthVerificationTableOptions configure the verification table and its
persistence when a secondary store is present.

```go
type AuthVerificationTableOptions struct {
	AuthModelOptions
	StoreInDatabase bool
}
```

### `Capabilities`

Capabilities describes the native behavioral compatibility and scalar representations of an
adapter. The public Adapter contract still requires atomic methods and
Transaction; these flags let wrappers decide whether conversion or fallback
behavioral compatibility is needed for a concrete backend.

```go
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
```

## Constructors and functions for `Capabilities`

### `NativeCapabilities`

NativeCapabilities describes an adapter that stores every reference implementation value
natively and implements the complete contract itself.

```go
func NativeCapabilities() Capabilities
```

### `ComparisonMode`

```go
type ComparisonMode string
```

## Constants associated with `ComparisonMode`

```go
const (
	Sensitive   ComparisonMode = "sensitive"
	Insensitive ComparisonMode = "insensitive"
)
```

### `Connector`

```go
type Connector string
```

## Constants associated with `Connector`

```go
const (
	And Connector = "AND"
	Or  Connector = "OR"
)
```

### `ConsumeOneParams`

```go
type ConsumeOneParams struct {
	Model string
	Where []Where
}
```

### `CountParams`

```go
type CountParams struct {
	Model string
	Where []Where
}
```

### `CreateParams`

```go
type CreateParams struct {
	Model        string
	Data         Record
	Select       []string
	ForceAllowID bool
}
```

### `CustomAdapter`

CustomAdapter is the low-level operation set consumed by NewAdapterFactory.
Its params contain physical model/field names and adapter-native values.
ConsumeOne and IncrementOne are optional; the factory supplies compatibility
fallbacks when they are nil.

DeleteMany deliberately returns any. reference implementation accepts third-party
adapters written in JavaScript, where an invalid document-store response can
reach this boundary at runtime. The factory validates and narrows it to the
public int64 contract instead of silently treating a malformed response as a
lost consume race.

```go
type CustomAdapter struct {
	Create     func(context.Context, CreateParams) (Record, error)
	FindOne    func(context.Context, FindOneParams) (Record, error)
	FindMany   func(context.Context, FindManyParams) ([]Record, error)
	Count      func(context.Context, CountParams) (int64, error)
	Update     func(context.Context, UpdateParams) (Record, error)
	UpdateMany func(context.Context, UpdateManyParams) (int64, error)
	Delete     func(context.Context, DeleteParams) error
	DeleteMany func(context.Context, DeleteManyParams) (any, error)

	ConsumeOne   func(context.Context, ConsumeOneParams) (Record, error)
	IncrementOne func(context.Context, IncrementOneParams) (Record, error)
}
```

### `DefaultModelNameOptions`

DefaultModelNameOptions are the inputs accepted by reference implementation's
initGetDefaultModelName helper. Schema keys are the canonical model names;
ModelSchema.ModelName values are their optional physical aliases.

```go
type DefaultModelNameOptions struct {
	Schema    Schema
	UsePlural bool
}
```

### `DefaultModelNameResolver`

DefaultModelNameResolver maps either a canonical schema key or a physical
model-name alias back to the canonical key.

```go
type DefaultModelNameResolver func(model string) (string, error)
```

## Constructors and functions for `DefaultModelNameResolver`

### `InitGetDefaultModelName`

InitGetDefaultModelName is the Go equivalent of reference implementation's
initGetDefaultModelName. Exact schema-key matches deliberately win over
aliases so a remapped model cannot redirect internal canonical queries.

```go
func InitGetDefaultModelName(options DefaultModelNameOptions) DefaultModelNameResolver
```

### `DeleteAction`

```go
type DeleteAction string
```

## Constants associated with `DeleteAction`

```go
const (
	NoAction   DeleteAction = "no action"
	Restrict   DeleteAction = "restrict"
	Cascade    DeleteAction = "cascade"
	SetNull    DeleteAction = "set null"
	SetDefault DeleteAction = "set default"
)
```

### `DeleteManyParams`

```go
type DeleteManyParams struct {
	Model string
	Where []Where
}
```

### `DeleteParams`

```go
type DeleteParams struct {
	Model string
	Where []Where
}
```

### `FieldAttribute`

FieldAttribute is the Go equivalent of reference implementation's DBFieldAttribute.
Pointer booleans preserve the distinction between omitted (upstream default)
and explicitly false.

```go
type FieldAttribute struct {
	Type         FieldType
	Enum         []string
	Required     *bool
	Returned     *bool
	Input        *bool
	DefaultValue ValueFactory
	OnUpdate     ValueFactory
	Transform    FieldTransform
	References   *Reference
	Unique       bool
	BigInt       bool
	FieldName    string
	Sortable     bool
	Index        bool
}
```

## Methods on `FieldAttribute`

### `IsInput`

```go
func (f FieldAttribute) IsInput() bool
```

### `IsRequired`

```go
func (f FieldAttribute) IsRequired() bool
```

### `IsReturned`

```go
func (f FieldAttribute) IsReturned() bool
```

### `FieldTransform`

```go
type FieldTransform struct {
	Input  Transform
	Output Transform
}
```

### `FieldType`

```go
type FieldType string
```

## Constants associated with `FieldType`

```go
const (
	FieldString      FieldType = "string"
	FieldNumber      FieldType = "number"
	FieldBoolean     FieldType = "boolean"
	FieldDate        FieldType = "date"
	FieldJSON        FieldType = "json"
	FieldStringArray FieldType = "string[]"
	FieldNumberArray FieldType = "number[]"
	FieldEnum        FieldType = "enum"
)
```

### `FindManyParams`

```go
type FindManyParams struct {
	Model  string
	Where  []Where
	Limit  *int
	Select []string
	SortBy *Sort
	Offset *int
	Join   map[string]JoinOption
}
```

### `FindOneParams`

```go
type FindOneParams struct {
	Model  string
	Where  []Where
	Select []string
	Join   map[string]JoinOption
}
```

### `IDFieldFactory`

IDFieldFactory resolves the implicit ID field for one schema model.

```go
type IDFieldFactory func(IDFieldOptions) (FieldAttribute, error)
```

## Constructors and functions for `IDFieldFactory`

### `InitGetIDField`

InitGetIDField is the Go equivalent of reference implementation's initGetIdField. The
returned FieldAttribute plugs directly into the existing adapter schema and
keeps the upstream default-value and transform ordering.

```go
func InitGetIDField(options IDFieldFactoryOptions) IDFieldFactory
```

### `IDFieldFactoryOptions`

IDFieldFactoryOptions configures InitGetIDField. GenerateIDFunc has the same
priority as a function-valued reference implementation generateId option, followed by the
UUID mode, CustomIDGenerator, and the built-in 32-character generator.

```go
type IDFieldFactoryOptions struct {
	Schema              Schema
	UsePlural           bool
	DisableIDGeneration bool
	GenerateID          IDGenerationMode
	GenerateIDFunc      IDGenerator
	CustomIDGenerator   IDGenerator
	SupportsUUIDs       bool
	Random              io.Reader
	Warn                func(message string)
}
```

### `IDFieldOptions`

IDFieldOptions are the per-model arguments accepted by an IDFieldFactory.

```go
type IDFieldOptions struct {
	CustomModelName string
	ForceAllowID    bool
}
```

### `IDGenerationMode`

IDGenerationMode is the Go representation of reference implementation's
advanced.database.generateId option. IDGenerationNone corresponds to the
JavaScript value false; IDGenerationDefault corresponds to an omitted
option.

```go
type IDGenerationMode string
```

## Constants associated with `IDGenerationMode`

```go
const (
	IDGenerationDefault IDGenerationMode = ""
	IDGenerationNone    IDGenerationMode = "none"
	IDGenerationSerial  IDGenerationMode = "serial"
	IDGenerationUUID    IDGenerationMode = "uuid"
)
```

### `IDGenerator`

IDGenerator generates an ID for a canonical schema model.

```go
type IDGenerator func(model string) (any, error)
```

### `IncrementOneParams`

```go
type IncrementOneParams struct {
	Model     string
	Where     []Where
	Increment map[string]float64
	Set       Record
}
```

### `InvalidDeleteManyResultError`

InvalidDeleteManyResultError reports a custom adapter that returned a value
which cannot be represented by the public deleted-row count contract.

```go
type InvalidDeleteManyResultError struct {
	AdapterID string
	Value     any
}
```

## Methods on `InvalidDeleteManyResultError`

### `Error`

```go
func (e *InvalidDeleteManyResultError) Error() string
```

### `JoinConfig`

JoinConfig is the physical join description derived from JoinOption and the
configured schema.

```go
type JoinConfig struct {
	From     string
	To       string
	Limit    int
	Relation Relation
}
```

### `JoinOn`

JoinOn is the physical field pair used by a native custom-adapter join.
From belongs to the base model and To belongs to the joined model.

```go
type JoinOn struct {
	From string
	To   string
}
```

### `JoinOption`

JoinOption requests a relation inferred from the schema. Model allows the
map key to be a relation alias instead of the joined model name, while
RelationName selects one foreign key when the same models have multiple
named relations. A nil Limit uses the adapter default. A pointer permits an
explicit limit of zero.

```go
type JoinOption struct {
	Model        string
	RelationName string
	Limit        *int
	// On and Relation are populated by AdapterFactory when a custom adapter
	// advertises native join support. Callers normally leave them empty and let
	// the factory infer the relationship from Schema.
	On       *JoinOn
	Relation Relation
}
```

### `ModelResolutionError`

ModelResolutionError preserves reference implementation's public error message while
still allowing callers to match storage.ErrModelNotFound with errors.Is.

```go
type ModelResolutionError struct {
	Model string
}
```

## Methods on `ModelResolutionError`

### `Error`

```go
func (e *ModelResolutionError) Error() string
```

### `Unwrap`

```go
func (e *ModelResolutionError) Unwrap() error
```

### `ModelSchema`

```go
type ModelSchema struct {
	ModelName         string
	Fields            map[string]FieldAttribute
	DisableMigrations bool
	Order             int
}
```

### `Operator`

```go
type Operator string
```

## Constants associated with `Operator`

```go
const (
	OpEq         Operator = "eq"
	OpNe         Operator = "ne"
	OpLt         Operator = "lt"
	OpLTE        Operator = "lte"
	OpGt         Operator = "gt"
	OpGTE        Operator = "gte"
	OpIn         Operator = "in"
	OpNotIn      Operator = "not_in"
	OpContains   Operator = "contains"
	OpStartsWith Operator = "starts_with"
	OpEndsWith   Operator = "ends_with"
)
```

### `Record`

Record is a dynamic model row. A missing key and a present key containing
nil intentionally mean different things (absent and explicit null).

```go
type Record = model.Record
```

### `RecordSchema`

RecordSchema is the Go counterpart of reference implementation's toZodSchema helper. It
selects the fields visible on the input or output side and validates a
record while stripping unknown fields.

```go
type RecordSchema struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `RecordSchema`

### `ToRecordSchema`

ToRecordSchema creates an input schema when clientSide is true and an output
schema otherwise. Input-disabled and output-disabled fields are omitted on
their respective side.

```go
func ToRecordSchema(fields map[string]FieldAttribute, clientSide bool) RecordSchema
```

## Methods on `RecordSchema`

### `FieldNames`

FieldNames returns the selected canonical fields in deterministic order.

```go
func (schema RecordSchema) FieldNames() []string
```

### `HasField`

HasField reports whether a field is part of this input/output schema.

```go
func (schema RecordSchema) HasField(name string) bool
```

### `Parse`

Parse validates selected fields and returns a stripped copy. Optional fields
accept both absence and nil, matching Zod's nullish behavioral compatibility in reference implementation.

```go
func (schema RecordSchema) Parse(input Record) (Record, error)
```

### `Reference`

```go
type Reference struct {
	Model        string
	Field        string
	OnDelete     DeleteAction
	RelationName string
}
```

### `Relation`

```go
type Relation string
```

## Constants associated with `Relation`

```go
const (
	OneToOne   Relation = "one-to-one"
	OneToMany  Relation = "one-to-many"
	ManyToMany Relation = "many-to-many"
)
```

### `Schema`

Schema maps canonical model names to their fields and optional physical
names. Canonical names win over aliases when the two collide, matching the
reference implementation resolver.

```go
type Schema struct {
	Models    map[string]ModelSchema
	UsePlural bool
}
```

## Constructors and functions for `Schema`

### `CoreSchema`

CoreSchema returns the five base reference implementation tables. Session, verification,
and rateLimit can be omitted by higher-level configuration when secondary
storage is selected.

```go
func CoreSchema() Schema
```

### `GetAuthTables`

GetAuthTables returns reference implementation's effective database table metadata.
It mirrors @single-auth/core's getAuthTables merge order and always returns
an independent schema that callers may safely mutate.

```go
func GetAuthTables(options AuthTablesOptions) Schema
```

## Methods on `Schema`

### `Clone`

Clone returns a deep copy safe for independent plugin composition.

```go
func (s Schema) Clone() Schema
```

### `Merge`

Merge composes plugin/additional schemas. Later fields replace earlier
fields with the same canonical name, as reference implementation does.

```go
func (s Schema) Merge(extension Schema) (Schema, error)
```

### `ResolveField`

ResolveField accepts a canonical or configured physical field name. The id
field exists implicitly on every adapter model.

```go
func (s Schema) ResolveField(modelName, candidate string) (FieldAttribute, string, error)
```

### `ResolveModel`

ResolveModel accepts a canonical name, configured physical name, or plural
physical name. Exact canonical matches take precedence over aliases.

```go
func (s Schema) ResolveModel(candidate string) (ModelSchema, string, error)
```

### `Validate`

Validate checks names, field kinds, aliases, and references.

```go
func (s Schema) Validate() error
```

### `SchemaCreation`

SchemaCreation is an adapter-generated schema artifact. Append and Overwrite
are mutually independent flags for behavioral compatibility with reference implementation's CLI contract;
consumers should give Overwrite precedence when both are true.

```go
type SchemaCreation struct {
	Code      string
	Path      string
	Append    bool
	Overwrite bool
}
```

### `SchemaCreator`

SchemaCreator is the optional schema-generation extension implemented by
adapters that advertise Capabilities.SchemaCreation.

```go
type SchemaCreator interface {
	CreateSchema(context.Context, Schema, string) (SchemaCreation, error)
}
```

### `SchemaEnsurer`

SchemaEnsurer is the optional runtime migration capability implemented by
native adapters that can create or reconcile their configured schema.

```go
type SchemaEnsurer interface {
	EnsureSchema(context.Context) error
}
```

### `Sort`

```go
type Sort struct {
	Field     string
	Direction SortDirection
}
```

### `SortDirection`

```go
type SortDirection string
```

## Constants associated with `SortDirection`

```go
const (
	Ascending  SortDirection = "asc"
	Descending SortDirection = "desc"
)
```

### `TransactionAdapter`

TransactionAdapter is the operation set exposed inside a transaction. It
deliberately omits Transaction, matching reference implementation's DBTransactionAdapter.

```go
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
```

## Constructors and functions for `TransactionAdapter`

### `CurrentTransactionAdapter`

CurrentTransactionAdapter returns the transaction adapter bound by
RunWithTransaction, or fallback outside an active transaction.

```go
func CurrentTransactionAdapter(ctx context.Context, fallback TransactionAdapter) TransactionAdapter
```

### `Transform`

```go
type Transform func(any) (any, error)
```

### `UpdateManyParams`

```go
type UpdateManyParams struct {
	Model  string
	Where  []Where
	Update Record
}
```

### `UpdateParams`

```go
type UpdateParams struct {
	Model  string
	Where  []Where
	Update Record
}
```

### `ValueContext`

ValueContext makes defaults and on-update values deterministic in tests.

```go
type ValueContext struct {
	Now func() time.Time
}
```

### `ValueFactory`

```go
type ValueFactory func(ValueContext) (any, error)
```

## Constructors and functions for `ValueFactory`

### `StaticValue`

StaticValue adapts a constant into a schema default/on-update factory.

```go
func StaticValue(value any) ValueFactory
```

### `Where`

Where is one predicate in an authentication storage query. SQL and document
adapters group every AND predicate together and
every OR predicate together, then require both non-empty groups to match.
The memory adapter retains its own left-to-right behavioral compatibility.
Zero-value Operator, Connector, and Mode normalize to eq, AND, and sensitive.

```go
type Where struct {
	Field     string
	Value     any
	Operator  Operator
	Connector Connector
	Mode      ComparisonMode
}
```

## Constructors and functions for `Where`

### `GroupWhere`

GroupWhere normalizes a query and partitions it using the grouping semantics
shared by reference implementation's database-backed adapters. The relative order inside
each group is preserved so generated parameter bindings remain deterministic.

```go
func GroupWhere(clauses []Where) (andClauses, orClauses []Where, err error)
```

## Methods on `Where`

### `Normalize`

Normalize validates the clause and fills reference implementation defaults.

```go
func (w Where) Normalize() (Where, error)
```

