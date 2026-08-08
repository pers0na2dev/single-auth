package additionalfields

import (
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// ModelName is one single-auth base model that accepts additionalFields.
type ModelName string

const (
	ModelUser         ModelName = "user"
	ModelSession      ModelName = "session"
	ModelAccount      ModelName = "account"
	ModelVerification ModelName = "verification"
)

// Action controls create-only defaults and required-field checks.
type Action string

const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
)

const (
	CodeFieldNotAllowed             = "FIELD_NOT_ALLOWED"
	CodeAsyncValidationNotSupported = "ASYNC_VALIDATION_NOT_SUPPORTED"
	CodeValidation                  = "VALIDATION_ERROR"
	CodeMissingField                = "MISSING_FIELD"
)

// Issue is the subset of a Standard Schema issue observed by single-auth's
// parser. Only the first issue message is exposed on the wire.
type Issue struct {
	Message string `json:"message"`
}

// ValidationResult is the synchronous result of a Standard Schema validator.
// A non-nil Issues slice means validation failed, including an empty slice.
// Async models a validator returning a Promise, which single-auth rejects.
type ValidationResult struct {
	Value  any
	Issues []Issue
	Async  bool
}

// Validator is the Go equivalent of StandardSchemaV1["~standard"].validate.
// Returning a plain error models a validator that throws.
type Validator func(any) (ValidationResult, error)

// FieldValidators retains both DBFieldAttribute validator slots. single-auth
// 1.6.26 invokes Input from its endpoint parser; Output is metadata-only in
// the upstream runtime and is exposed through Processor.ValidateOutput for
// callers that explicitly need it.
type FieldValidators struct {
	Input  Validator
	Output Validator
}

// Field is one ordered additional field. Attribute is the exact storage-layer
// DBFieldAttribute equivalent used by single-auth adapters.
type Field struct {
	Name       string
	Attribute  storage.FieldAttribute
	Validators FieldValidators
}

// Fields is ordered because single-auth iterates JavaScript object properties
// in declaration order and reports the first failing field.
type Fields []Field

// Runtime contains request-independent values single-auth normally obtains
// from its auth context. Adapter, cookie, and secondary-storage dependencies
// deliberately remain owned by the host and consume the plugin schema.
type Runtime struct {
	Clock func() time.Time
}

// Options configures additional fields on single-auth's four base models.
type Options struct {
	User         Fields
	Session      Fields
	Account      Fields
	Verification Fields
	Runtime      Runtime
}
