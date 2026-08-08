---
title: "github.com/pers0na2dev/single-auth/plugins/emailotp"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/emailotp.

- Import path: `github.com/pers0na2dev/single-auth/plugins/emailotp`
- Package name: `emailotp`

Package emailotp implements single-auth 1.6.26's email-otp plugin for the
transport-neutral single-auth engine.

## Constants

```go
const (
	ErrorOTPExpired      = "OTP_EXPIRED"
	ErrorInvalidOTP      = "INVALID_OTP"
	ErrorTooManyAttempts = "TOO_MANY_ATTEMPTS"
)
```

```go
const Version = "1.6.26"
```

## Functions

### `Identifier`

Identifier returns single-auth's exact verification identifier.

```go
func Identifier(otpType OTPType, email string) string
```

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots a single-auth email-otp plugin.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds email-otp to the final root adapter, session/cookie
lifecycle, hooks, password configuration, and security policy.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema is empty because email-otp 1.6.26 adds no plugin table. It consumes
single-auth's core verification, user, account, and session models.

```go
func Schema() storage.Schema
```

### `SplitStoredValue`

SplitStoredValue splits the stored code and attempt suffix at the final
colon, allowing custom encrypted values to contain colons.

```go
func SplitStoredValue(input string) (string, string)
```

## Types

### `BackgroundRunner`

```go
type BackgroundRunner func(context.Context, func(context.Context) error) error
```

### `ChangeEmailOptions`

```go
type ChangeEmailOptions struct {
	Enabled            bool
	VerifyCurrentEmail bool
}
```

### `ConsumeVerificationFunc`

```go
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)
```

### `CreateUserFunc`

```go
type CreateUserFunc func(*engine.Context, CreateUserInput) (storage.Record, error)
```

### `CreateUserInput`

```go
type CreateUserInput struct {
	Email      string
	Name       string
	Image      *string
	Additional storage.Record
}
```

### `CreateVerificationFunc`

```go
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
```

### `DecryptOTPFunc`

```go
type DecryptOTPFunc func(context.Context, string) (string, error)
```

### `DefaultVerificationHandler`

DefaultVerificationHandler is installed into the host's default email
verification option when OverrideDefaultEmailVerification is enabled.

```go
type DefaultVerificationHandler func(context.Context, string) error
```

### `DefaultVerificationInstaller`

```go
type DefaultVerificationInstaller func(DefaultVerificationHandler) error
```

### `DeleteVerificationFunc`

```go
type DeleteVerificationFunc func(context.Context, string) error
```

### `EncryptOTPFunc`

```go
type EncryptOTPFunc func(context.Context, string) (string, error)
```

### `FindVerificationFunc`

```go
type FindVerificationFunc func(context.Context, string) (storage.Record, error)
```

### `GenerateOTPFunc`

```go
type GenerateOTPFunc func(OTPData, *engine.Context) (string, error)
```

### `HashOTPFunc`

```go
type HashOTPFunc func(context.Context, string) (string, error)
```

### `IssueSessionFunc`

IssueSession creates a session for user and writes all host session cookies
to ctx. Returning nil is treated as a session creation failure.

```go
type IssueSessionFunc func(*engine.Context, storage.Record) (*SessionState, error)
```

### `OTPData`

```go
type OTPData struct {
	Email string  `json:"email"`
	Type  OTPType `json:"type"`
}
```

### `OTPMessage`

```go
type OTPMessage struct {
	Email string  `json:"email"`
	OTP   string  `json:"otp"`
	Type  OTPType `json:"type"`
}
```

### `OTPStorage`

OTPStorage configures built-in or custom persistence transforms. CustomHash
corresponds to upstream &#123;hash&#125;; CustomEncrypt and CustomDecrypt correspond
to upstream &#123;encrypt,decrypt&#125;.

```go
type OTPStorage struct {
	Mode          StoreMode
	CustomHash    HashOTPFunc
	CustomEncrypt EncryptOTPFunc
	CustomDecrypt DecryptOTPFunc
}
```

### `OTPType`

OTPType is one upstream email-otp purpose.

```go
type OTPType string
```

## Constants associated with `OTPType`

```go
const (
	TypeSignIn            OTPType = "sign-in"
	TypeEmailVerification OTPType = "email-verification"
	TypeForgetPassword    OTPType = "forget-password"
	TypeChangeEmail       OTPType = "change-email"
)
```

### `Options`

Options configures the single-auth-compatible email-otp plugin.

```go
type Options struct {
	SendVerificationOTP              SendOTPFunc
	OTPLength                        int
	ExpiresIn                        time.Duration
	GenerateOTP                      GenerateOTPFunc
	Storage                          OTPStorage
	ResendStrategy                   ResendStrategy
	SendVerificationOnSignUp         bool
	DisableSignUp                    bool
	AllowedAttempts                  int
	ChangeEmail                      ChangeEmailOptions
	OverrideDefaultEmailVerification bool
	AutoSignInAfterVerification      bool
	RateLimit                        RateLimitOptions
	Password                         PasswordOptions
	TrustedOrigins                   []string
	Runtime                          Runtime
}
```

### `ParseUserInputFunc`

```go
type ParseUserInputFunc func(*engine.Context, map[string]any) (storage.Record, error)
```

### `PasswordOptions`

```go
type PasswordOptions struct {
	MinLength       int
	MaxLength       int
	Hash            func(string) (string, error)
	HashWithContext func(*engine.Context, string) (string, error)
	OnReset         PasswordResetHookFunc
	RevokeSessions  bool
}
```

### `PasswordResetHookFunc`

```go
type PasswordResetHookFunc func(context.Context, *engine.Context, storage.Record) error
```

### `RateLimitOptions`

```go
type RateLimitOptions struct {
	Window int64
	Max    int64
}
```

### `RefreshSessionFunc`

RefreshSession rewrites the host cookie/cache for an existing session after
the plugin changes the user record.

```go
type RefreshSessionFunc func(*engine.Context, SessionState) error
```

### `ResendStrategy`

```go
type ResendStrategy string
```

## Constants associated with `ResendStrategy`

```go
const (
	ResendRotate ResendStrategy = "rotate"
	ResendReuse  ResendStrategy = "reuse"
)
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context, SessionResolution) (*SessionState, error)
```

### `RevokeSessionsFunc`

```go
type RevokeSessionsFunc func(*engine.Context, string) error
```

### `RevokeUnprovenAccessFunc`

```go
type RevokeUnprovenAccessFunc func(*engine.Context, string) error
```

### `Runtime`

Runtime contains dependencies single-auth normally injects through its
internal endpoint context. engine.Plugin intentionally has no root-runtime
dependency, so session/cookie and init-option behavioral compatibility is explicit here.

```go
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader
	Secret  string

	ResolveSession ResolveSessionFunc
	IssueSession   IssueSessionFunc
	RefreshSession RefreshSessionFunc

	CreateUser     CreateUserFunc
	ParseUserInput ParseUserInputFunc
	SerializeUser  SerializeUserFunc
	RevokeUnproven RevokeUnprovenAccessFunc
	// RevokeSessions must invalidate both database and secondary-storage
	// sessions when the host enables secondary session storage. The default
	// implementation deletes core session rows through Adapter.
	RevokeSessions RevokeSessionsFunc

	BeforeEmailVerification UserHookFunc
	AfterEmailVerification  UserHookFunc

	RunInBackground            BackgroundRunner
	ValidateSendRequest        SendRequestValidator
	InstallDefaultVerification DefaultVerificationInstaller
	Warn                       func(string)

	CreateVerification  CreateVerificationFunc
	FindVerification    FindVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
	UpdateVerification  UpdateVerificationFunc
	DeleteVerification  DeleteVerificationFunc
}
```

### `SendOTPFunc`

```go
type SendOTPFunc func(context.Context, OTPMessage, *engine.Context) error
```

### `SendRequestValidator`

```go
type SendRequestValidator func(*engine.Context) error
```

### `SerializeUserFunc`

```go
type SerializeUserFunc func(storage.Record) any
```

### `SessionResolution`

```go
type SessionResolution uint8
```

## Constants associated with `SessionResolution`

```go
const (
	SessionOptional SessionResolution = iota

	SessionAuthoritative
)
```

### `SessionState`

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `StoreMode`

StoreMode controls the representation persisted in verification.value.

```go
type StoreMode string
```

## Constants associated with `StoreMode`

```go
const (
	StorePlain     StoreMode = "plain"
	StoreHashed    StoreMode = "hashed"
	StoreEncrypted StoreMode = "encrypted"
)
```

### `UpdateVerificationFunc`

```go
type UpdateVerificationFunc func(context.Context, string, storage.Record) error
```

### `UserHookFunc`

```go
type UserHookFunc func(context.Context, *engine.Context, storage.Record) error
```

