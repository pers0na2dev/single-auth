---
title: "github.com/pers0na2dev/single-auth/plugins/additionalfields"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/additionalfields.

- Import path: `github.com/pers0na2dev/single-auth/plugins/additionalfields`
- Package name: `additionalfields`

Package additionalfields ports single-auth 1.6.26's server-side
additionalFields contract.

single-auth does not implement additional fields as an independent server
plugin. The feature is composed through the core schema, input parsers,
adapter transforms, endpoint handlers, cookie cache, and secondary session
storage. This package exposes that contract as an engine.Plugin without
coupling it to either net/http or fasthttp.

The returned plugin contributes field metadata to the host schema and runs
the create/update request parser for signUpEmail, updateUser, and
updateSession. single-auth's root runtime consumes the contributed schema for
database defaults and transforms, returned:false filtering, cookie-cache
serialization, and secondary-storage session propagation. Therefore no
adapter or secondary-storage handle is duplicated in Runtime. Integrations
that create users, accounts, or sessions outside the built-in endpoints can
retain the same behavioral compatibility by keeping the Processor returned by Compile and
calling its parsing helpers before their own persistence operation.

## Constants

```go
const (
	CodeFieldNotAllowed             = "FIELD_NOT_ALLOWED"
	CodeAsyncValidationNotSupported = "ASYNC_VALIDATION_NOT_SUPPORTED"
	CodeValidation                  = "VALIDATION_ERROR"
	CodeMissingField                = "MISSING_FIELD"
)
```

```go
const Version = "1.6.26"
```

## Functions

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots a single-auth additional-fields plugin.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory contributes the schema before the root adapter is constructed
and binds the processor clock to the final auth runtime.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

## Types

### `Action`

Action controls create-only defaults and required-field checks.

```go
type Action string
```

## Constants associated with `Action`

```go
const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
)
```

### `Field`

Field is one ordered additional field. Attribute is the exact storage-layer
DBFieldAttribute equivalent used by single-auth adapters.

```go
type Field struct {
	Name       string
	Attribute  storage.FieldAttribute
	Validators FieldValidators
}
```

### `FieldValidators`

FieldValidators retains both DBFieldAttribute validator slots. single-auth
1.6.26 invokes Input from its endpoint parser; Output is metadata-only in
the upstream runtime and is exposed through Processor.ValidateOutput for
callers that explicitly need it.

```go
type FieldValidators struct {
	Input  Validator
	Output Validator
}
```

### `Fields`

Fields is ordered because single-auth iterates JavaScript object properties
in declaration order and reports the first failing field.

```go
type Fields []Field
```

### `Issue`

Issue is the subset of a Standard Schema issue observed by single-auth's
parser. Only the first issue message is exposed on the wire.

```go
type Issue struct {
	Message string `json:"message"`
}
```

### `ModelName`

ModelName is one single-auth base model that accepts additionalFields.

```go
type ModelName string
```

## Constants associated with `ModelName`

```go
const (
	ModelUser         ModelName = "user"
	ModelSession      ModelName = "session"
	ModelAccount      ModelName = "account"
	ModelVerification ModelName = "verification"
)
```

### `Options`

Options configures additional fields on single-auth's four base models.

```go
type Options struct {
	User         Fields
	Session      Fields
	Account      Fields
	Verification Fields
	Runtime      Runtime
}
```

### `Processor`

Processor is an immutable compiled additional-fields contract. It is safe
for concurrent use when the configured callbacks are themselves safe.

```go
type Processor struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Processor`

### `Compile`

Compile validates and snapshots options for reuse by endpoint and internal
server paths.

```go
func Compile(input Options) (*Processor, error)
```

## Methods on `Processor`

### `BuildSyntheticUserOutput`

BuildSyntheticUserOutput builds the enumeration-protection user shape used
by sign-up. It includes single-auth's base user fields plus configured
fields, applies defaults, supplies null for non-explicitly-required missing
fields, filters returned:false, and preserves id when supplied.

```go
func (p *Processor) BuildSyntheticUserOutput(data storage.Record) (storage.Record, error)
```

### `FilterOutput`

FilterOutput removes returned:false fields and deep-copies the result,
matching filterOutputFields(structuredClone(data), schema).

```go
func (p *Processor) FilterOutput(
	modelName ModelName,
	data storage.Record,
) (storage.Record, error)
```

### `GetSessionDefaultFields`

GetSessionDefaultFields is the upstream-named alias for SessionDefaults.

```go
func (p *Processor) GetSessionDefaultFields() (storage.Record, error)
```

### `ParseAccountInput`

ParseAccountInput is ParseInput for account creation.

```go
func (p *Processor) ParseAccountInput(data storage.Record) (storage.Record, error)
```

### `ParseAccountOutput`

ParseAccountOutput filters one account response, including single-auth's
six core credential/token fields marked returned:false.

```go
func (p *Processor) ParseAccountOutput(data storage.Record) (storage.Record, error)
```

### `ParseAdditionalUserInput`

ParseAdditionalUserInput parses user additional fields for creation.

```go
func (p *Processor) ParseAdditionalUserInput(data storage.Record) (storage.Record, error)
```

### `ParseAdditionalUserInputFromProviderProfile`

ParseAdditionalUserInputFromProviderProfile is the upstream-named alias for
ParseProviderUserInput.

```go
func (p *Processor) ParseAdditionalUserInputFromProviderProfile(
	profile storage.Record,
	action Action,
) (storage.Record, error)
```

### `ParseInput`

ParseInput ports parseInputData from single-auth 1.6.26. Missing map keys,
present nil values, and present zero values remain distinct.

```go
func (p *Processor) ParseInput(
	modelName ModelName,
	data storage.Record,
	action Action,
) (storage.Record, error)
```

### `ParseProviderUserInput`

ParseProviderUserInput filters input:false profile keys before parsing. This
mirrors parseAdditionalUserInputFromProviderProfile.

```go
func (p *Processor) ParseProviderUserInput(
	profile storage.Record,
	action Action,
) (storage.Record, error)
```

### `ParseSessionInput`

ParseSessionInput is ParseInput for the session model.

```go
func (p *Processor) ParseSessionInput(data storage.Record, action Action) (storage.Record, error)
```

### `ParseSessionOutput`

ParseSessionOutput filters one session response.

```go
func (p *Processor) ParseSessionOutput(data storage.Record) (storage.Record, error)
```

### `ParseUserInput`

ParseUserInput is ParseInput for the user model.

```go
func (p *Processor) ParseUserInput(data storage.Record, action Action) (storage.Record, error)
```

### `ParseUserOutput`

ParseUserOutput filters one user response.

```go
func (p *Processor) ParseUserOutput(data storage.Record) (storage.Record, error)
```

### `Plugin`

Plugin returns an independent descriptor backed by the immutable processor.

```go
func (p *Processor) Plugin() engine.Plugin
```

### `Schema`

Schema returns an independent plugin schema snapshot.

```go
func (p *Processor) Schema() storage.Schema
```

### `SessionDefaults`

SessionDefaults evaluates every configured session default on each call.

```go
func (p *Processor) SessionDefaults() (storage.Record, error)
```

### `ValidateOutput`

ValidateOutput explicitly executes validator.output. single-auth 1.6.26
stores this metadata but does not invoke it from parseUserOutput or the
adapter factory, so this method is never installed as an automatic hook.

```go
func (p *Processor) ValidateOutput(modelName ModelName, data storage.Record) (storage.Record, error)
```

### `Runtime`

Runtime contains request-independent values single-auth normally obtains
from its auth context. Adapter, cookie, and secondary-storage dependencies
deliberately remain owned by the host and consume the plugin schema.

```go
type Runtime struct {
	Clock func() time.Time
}
```

### `ValidationResult`

ValidationResult is the synchronous result of a Standard Schema validator.
A non-nil Issues slice means validation failed, including an empty slice.
Async models a validator returning a Promise, which single-auth rejects.

```go
type ValidationResult struct {
	Value  any
	Issues []Issue
	Async  bool
}
```

### `Validator`

Validator is the Go equivalent of StandardSchemaV1["~standard"].validate.
Returning a plain error models a validator that throws.

```go
type Validator func(any) (ValidationResult, error)
```

