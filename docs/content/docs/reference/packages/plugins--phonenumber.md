---
title: "github.com/pers0na2dev/single-auth/plugins/phonenumber"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/phonenumber.

- Import path: `github.com/pers0na2dev/single-auth/plugins/phonenumber`
- Package name: `phonenumber`

Package phonenumber implements the single-auth 1.6.26 phone-number plugin.

The package is transport neutral. NewFactory binds the plugin to a
single-auth instance, so the same endpoints are available through the
direct API, net/http, fasthttp, and Fiber adapters.

## Constants

```go
const (
	CodeInvalidPhoneNumber         = "INVALID_PHONE_NUMBER"
	CodePhoneNumberExists          = "PHONE_NUMBER_EXIST"
	CodePhoneNumberNotRegistered   = "PHONE_NUMBER_NOT_EXIST"
	CodeInvalidPhoneOrPassword     = "INVALID_PHONE_NUMBER_OR_PASSWORD"
	CodeUnexpectedError            = "UNEXPECTED_ERROR"
	CodeOTPNotFound                = "OTP_NOT_FOUND"
	CodeOTPExpired                 = "OTP_EXPIRED"
	CodeInvalidOTP                 = "INVALID_OTP"
	CodePhoneNumberNotVerified     = "PHONE_NUMBER_NOT_VERIFIED"
	CodePhoneNumberCannotBeUpdated = "PHONE_NUMBER_CANNOT_BE_UPDATED"
	CodeSendOTPNotImplemented      = "SEND_OTP_NOT_IMPLEMENTED"
	CodeTooManyAttempts            = "TOO_MANY_ATTEMPTS"
)
```

```go
const Version = "1.6.26"
```

## Functions

### `MustNew`

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots a standalone phone-number plugin.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds phone-number to the final root adapter, password chain,
session/cookie lifecycle, verification storage, and database hooks.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema returns an independent storage extension for options.

```go
func Schema(options Options) (storage.Schema, error)
```

## Types

### `BackgroundRunner`

```go
type BackgroundRunner func(context.Context, func(context.Context) error) error
```

### `ConsumeVerificationFunc`

```go
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)
```

### `CreateUserFunc`

```go
type CreateUserFunc func(*engine.Context, storage.Record) (storage.Record, error)
```

### `CreateVerificationFunc`

```go
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
```

### `DeleteVerificationFunc`

```go
type DeleteVerificationFunc func(context.Context, string) error
```

### `FindVerificationFunc`

```go
type FindVerificationFunc func(context.Context, string) (storage.Record, error)
```

### `HashPasswordFunc`

```go
type HashPasswordFunc func(*engine.Context, string) (string, error)
```

### `IssueSessionFunc`

```go
type IssueSessionFunc func(*engine.Context, string, bool) (*SessionState, error)
```

### `OTPMessage`

OTPMessage is passed to phone OTP delivery and verification callbacks.

```go
type OTPMessage struct {
	PhoneNumber string `json:"phoneNumber"`
	Code        string `json:"code"`
}
```

### `Options`

Options configures the single-auth-compatible phone-number plugin.

```go
type Options struct {
	OTPLength              int
	SendOTP                SendOTPFunc
	VerifyOTP              VerifyOTPFunc
	SendPasswordResetOTP   SendOTPFunc
	ExpiresIn              time.Duration
	PhoneNumberValidator   PhoneNumberValidator
	RequireVerification    bool
	CallbackOnVerification VerificationCallback
	SignUpOnVerification   *SignUpOnVerificationOptions
	Schema                 SchemaOptions
	AllowedAttempts        int
	Runtime                Runtime
}
```

### `ParseUserInputFunc`

```go
type ParseUserInputFunc func(*engine.Context, map[string]any) (storage.Record, error)
```

### `PasswordResetHookFunc`

```go
type PasswordResetHookFunc func(context.Context, *engine.Context, storage.Record) error
```

### `PhoneNumberValidator`

```go
type PhoneNumberValidator func(string) (bool, error)
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context) (*SessionState, error)
```

### `RevokeSessionsFunc`

```go
type RevokeSessionsFunc func(*engine.Context, string) error
```

### `Runtime`

Runtime contains services normally supplied by single-auth's endpoint
context. NewFactory fills this structure from the final root runtime.

```go
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader

	ResolveSession ResolveSessionFunc
	IssueSession   IssueSessionFunc
	CreateUser     CreateUserFunc
	ParseUserInput ParseUserInputFunc
	SerializeUser  SerializeUserFunc

	HashPassword                  HashPasswordFunc
	VerifyPassword                func(hash, password string) bool
	PasswordMinLength             int
	PasswordMaxLength             int
	OnPasswordReset               PasswordResetHookFunc
	RevokeSessions                RevokeSessionsFunc
	RevokeSessionsOnPasswordReset bool

	RunBackground          BackgroundRunner
	BackgroundTasksEnabled bool
	Warn                   func(string)
	LogError               func(string, error)

	CreateVerification CreateVerificationFunc
	// PeekVerification returns the newest verification without deleting an
	// expired row. This preserves single-auth's OTP_EXPIRED taxonomy.
	PeekVerification    FindVerificationFunc
	FindVerification    FindVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
	DeleteVerification  DeleteVerificationFunc

	RegisterDatabaseHooks func(singleauth.DatabaseHooks) error
}
```

### `SchemaOptions`

```go
type SchemaOptions struct{ User UserSchemaOptions }
```

### `SendOTPFunc`

```go
type SendOTPFunc func(context.Context, OTPMessage, *engine.Context) error
```

### `SerializeUserFunc`

```go
type SerializeUserFunc func(storage.Record) any
```

### `SessionState`

SessionState is the host session/user pair used by phone endpoints.

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `SignUpOnVerificationOptions`

SignUpOnVerificationOptions configures user creation after a valid OTP for
a phone number which is not associated with an existing user.

```go
type SignUpOnVerificationOptions struct {
	GetTempEmail func(phoneNumber string) string
	GetTempName  func(phoneNumber string) string
}
```

### `UserSchemaOptions`

UserSchemaOptions maps canonical phone fields to physical database names.

```go
type UserSchemaOptions struct {
	ModelName           string
	PhoneNumber         string
	PhoneNumberVerified string
}
```

### `VerificationCallback`

```go
type VerificationCallback func(context.Context, VerificationEvent, *engine.Context) error
```

### `VerificationEvent`

VerificationEvent is delivered after a phone number has been associated
with a user and marked verified.

```go
type VerificationEvent struct {
	PhoneNumber string
	User        storage.Record
}
```

### `VerifyOTPFunc`

```go
type VerifyOTPFunc func(context.Context, OTPMessage, *engine.Context) (bool, error)
```

