---
title: "github.com/pers0na2dev/single-auth/plugins/username"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/username.

- Import path: `github.com/pers0na2dev/single-auth/plugins/username`
- Package name: `username`

Package username ports single-auth 1.6.26's username plugin. It adds
normalized user and display-username fields, validates sign-up and user
updates, and exposes username credential sign-in and availability checks.

## Constants

```go
const (
	CodeInvalidUsernameOrPassword = "INVALID_USERNAME_OR_PASSWORD"
	CodeEmailNotVerified          = "EMAIL_NOT_VERIFIED"
	CodeUnexpectedError           = "UNEXPECTED_ERROR"
	CodeUsernameAlreadyTaken      = "USERNAME_IS_ALREADY_TAKEN"
	CodeUsernameTooShort          = "USERNAME_TOO_SHORT"
	CodeUsernameTooLong           = "USERNAME_TOO_LONG"
	CodeInvalidUsername           = "INVALID_USERNAME"
	CodeInvalidDisplayUsername    = "INVALID_DISPLAY_USERNAME"
)
```

```go
const (
	Version = "1.6.26"
)
```

## Functions

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots a standalone username plugin.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory contributes the username fields before adapter construction and
binds persistence, password, session, cookie, and verification services to
the final root runtime.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema returns an independent schema extension for options.

```go
func Schema(options Options) (storage.Schema, error)
```

## Types

### `HashPasswordContextFunc`

```go
type HashPasswordContextFunc func(*engine.Context, string) (string, error)
```

### `IssueSessionFunc`

```go
type IssueSessionFunc func(*engine.Context, string, bool) (*SessionState, error)
```

### `Normalizer`

Normalizer transforms a value before persistence or lookup. Callback
implementations must be deterministic and safe for concurrent use.

```go
type Normalizer func(string) string
```

### `Options`

Options configures the single-auth-compatible username plugin.

```go
type Options struct {
	Schema SchemaOptions

	MinUsernameLength int
	MaxUsernameLength int

	UsernameValidator        Validator
	DisplayUsernameValidator Validator

	// UsernameNormalization defaults to strings.ToLower. Set
	// DisableUsernameNormalization to preserve the submitted username.
	UsernameNormalization        Normalizer
	DisableUsernameNormalization bool
	// DisplayUsernameNormalization defaults to the identity function.
	DisplayUsernameNormalization Normalizer

	ValidationOrder ValidationOrders
	Runtime         Runtime
}
```

### `ResolveBaseURLFunc`

```go
type ResolveBaseURLFunc func(contract.Request) (string, error)
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context) (*SessionState, error)
```

### `RunBackgroundFunc`

```go
type RunBackgroundFunc func(context.Context, func(context.Context) error) error
```

### `Runtime`

Runtime contains dependencies injected by NewFactory. It remains public so
focused descriptor tests can assemble the standalone plugin.

```go
type Runtime struct {
	Adapter storage.Adapter
	Logger  *logger.Logger
	Clock   func() time.Time
	Secret  string

	HashPassword func(string) (string, error)
	// HashPasswordContext preserves request-scoped password wrapper semantics
	// when the plugin performs the timing-equalization hash for an unknown user.
	HashPasswordContext HashPasswordContextFunc
	VerifyPassword      func(hash, password string) bool

	IssueSession     IssueSessionFunc
	ResolveSession   ResolveSessionFunc
	SerializeUser    SerializeUserFunc
	ResolveBaseURL   ResolveBaseURLFunc
	ValidateRedirect ValidateRedirectFunc
	RunBackground    RunBackgroundFunc

	RequireEmailVerification bool
	SendOnSignIn             bool
	VerificationExpiresIn    time.Duration
	SendVerificationEmail    SendVerificationEmailFunc

	RegisterDatabaseHooks func(singleauth.DatabaseHooks) error
}
```

### `SchemaOptions`

```go
type SchemaOptions struct{ User UserSchemaOptions }
```

### `SendVerificationEmailFunc`

```go
type SendVerificationEmailFunc func(context.Context, VerificationMessage) error
```

### `SerializeUserFunc`

```go
type SerializeUserFunc func(storage.Record) any
```

### `SessionState`

SessionState is the session/user pair issued by the host.

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `UserSchemaOptions`

```go
type UserSchemaOptions struct {
	// ModelName is the physical database model name. Empty uses the canonical
	// user model name.
	ModelName string
	// Username and DisplayUsername are physical database field names. Empty
	// values use the canonical names.
	Username        string
	DisplayUsername string
}
```

### `ValidateRedirectFunc`

```go
type ValidateRedirectFunc func(*engine.Context, string, string) error
```

### `ValidationOrder`

ValidationOrder selects which representation is passed to a validator.

```go
type ValidationOrder string
```

## Constants associated with `ValidationOrder`

```go
const (
	PreNormalization  ValidationOrder = "pre-normalization"
	PostNormalization ValidationOrder = "post-normalization"
)
```

### `ValidationOrders`

ValidationOrders independently configure username and display-username
validation. Empty values select PreNormalization.

```go
type ValidationOrders struct {
	Username        ValidationOrder
	DisplayUsername ValidationOrder
}
```

### `Validator`

Validator is the Go equivalent of single-auth's sync-or-async validator.
Callback implementations must be safe for concurrent use.

```go
type Validator func(string) (bool, error)
```

### `VerificationMessage`

VerificationMessage is delivered when username sign-in is blocked by an
unverified email and SendOnSignIn is enabled.

```go
type VerificationMessage struct {
	User  model.User
	URL   string
	Token string
}
```

