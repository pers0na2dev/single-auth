---
title: "github.com/pers0na2dev/single-auth/plugins/twofactor"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/twofactor.

- Import path: `github.com/pers0na2dev/single-auth/plugins/twofactor`
- Package name: `twofactor`

Package twofactor implements the single-auth 1.6.26 two-factor plugin for
single-auth.

It provides TOTP enrollment and verification, emailed or otherwise delivered
OTP challenges, single-use backup codes, trusted devices, per-challenge
attempt caps, account-level lockout, passwordless-account management, custom
storage codecs and schema aliases. NewFactory binds it to the root Auth
runtime so the same behavioral compatibility is available through direct calls, net/http,
fasthttp and Fiber.

Package twofactor ports single-auth's built-in two-factor plugin.

## Constants

```go
const (
	CodeOTPNotEnabled            = "OTP_NOT_ENABLED"
	CodeOTPHasExpired            = "OTP_HAS_EXPIRED"
	CodeTOTPNotEnabled           = "TOTP_NOT_ENABLED"
	CodeTwoFactorNotEnabled      = "TWO_FACTOR_NOT_ENABLED"
	CodeBackupCodesNotEnabled    = "BACKUP_CODES_NOT_ENABLED"
	CodeInvalidBackupCode        = "INVALID_BACKUP_CODE"
	CodeInvalidCode              = "INVALID_CODE"
	CodeTooManyAttempts          = "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"
	CodeAccountTemporarilyLocked = "ACCOUNT_TEMPORARILY_LOCKED"
	CodeInvalidTwoFactorCookie   = "INVALID_TWO_FACTOR_COOKIE"
	CodeOTPNotConfigured         = "OTP_NOT_CONFIGURED"
	CodeTOTPNotConfigured        = "TOTP_NOT_CONFIGURED"
)
```

```go
const (
	DefaultTwoFactorCookieMaxAge = 10 * time.Minute
	DefaultTrustDeviceMaxAge     = 30 * 24 * time.Hour
	DefaultAllowedAttempts       = 5
	DefaultAccountLockoutLimit   = 10
	DefaultAccountLockoutWindow  = 15 * time.Minute
)
```

```go
const Version = "1.6.26"
```

## Functions

### `GenerateTOTP`

GenerateTOTP is the Go API equivalent of @single-auth/utils createOTP().totp().

```go
func GenerateTOTP(secret string, at time.Time, digits int, period time.Duration) (string, error)
```

### `MustNew`

```go
func MustNew(options Options) engine.Plugin
```

### `New`

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

```go
func Schema(options Options) (storage.Schema, error)
```

### `TOTPURI`

TOTPURI reproduces @single-auth/utils 0.4.2 query and encoding order.

```go
func TOTPURI(secret, issuer, account string, digits int, period time.Duration) string
```

### `VerifyTOTP`

VerifyTOTP uses the upstream default window of one period on either side.

```go
func VerifyTOTP(secret, input string, at time.Time, digits int, period time.Duration) (bool, error)
```

## Types

### `AccountLockoutOptions`

```go
type AccountLockoutOptions struct {
	Enabled           *bool
	MaxFailedAttempts int
	Duration          time.Duration
}
```

### `BackupCodeOptions`

```go
type BackupCodeOptions struct {
	Amount            int
	Length            int
	CustomGenerate    BackupCodesGenerateFunc
	Storage           OTPStorage
	AllowPasswordless *bool
}
```

### `BackupCodesGenerateFunc`

```go
type BackupCodesGenerateFunc func() []string
```

### `ConsumeVerificationFunc`

```go
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)
```

### `Cookie`

```go
type Cookie struct {
	Name       string
	Attributes cookies.Options
}
```

### `CookieResolver`

```go
type CookieResolver func(contract.Request, string, string) Cookie
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

### `IssueSessionFunc`

```go
type IssueSessionFunc func(*engine.Context, string, bool) (*SessionState, error)
```

### `OTPDecryptFunc`

```go
type OTPDecryptFunc func(string) (string, error)
```

### `OTPEncryptFunc`

```go
type OTPEncryptFunc func(string) (string, error)
```

### `OTPHashFunc`

```go
type OTPHashFunc func(string) (string, error)
```

### `OTPMessage`

OTPMessage is delivered to the configured out-of-band OTP sender.

```go
type OTPMessage struct {
	User storage.Record
	OTP  string
}
```

### `OTPOptions`

```go
type OTPOptions struct {
	Period          time.Duration
	Digits          int
	SendOTP         SendOTPFunc
	AllowedAttempts int
	Storage         OTPStorage
}
```

### `OTPStorage`

OTPStorage configures either a built-in storage mode or a custom codec.
Hash is one-way; Encrypt and Decrypt must be supplied together.

```go
type OTPStorage struct {
	Mode    OTPStorageMode
	Hash    OTPHashFunc
	Encrypt OTPEncryptFunc
	Decrypt OTPDecryptFunc
}
```

### `OTPStorageMode`

```go
type OTPStorageMode string
```

## Constants associated with `OTPStorageMode`

```go
const (
	OTPStoragePlain     OTPStorageMode = "plain"
	OTPStorageHashed    OTPStorageMode = "hashed"
	OTPStorageEncrypted OTPStorageMode = "encrypted"
)
```

### `Options`

Options mirrors single-auth 1.6.26 twoFactor options. Durations use Go
duration values while preserving the upstream defaults and wire behavioral compatibility.

```go
type Options struct {
	Issuer                   string
	TwoFactorTable           string
	TOTP                     TOTPOptions
	OTP                      OTPOptions
	BackupCodes              BackupCodeOptions
	SkipVerificationOnEnable bool
	AllowPasswordless        bool
	Schema                   SchemaOptions
	TwoFactorCookieMaxAge    time.Duration
	TrustDeviceMaxAge        time.Duration
	AccountLockout           AccountLockoutOptions
	Runtime                  Runtime
}
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context, singleauth.PluginSessionMode) (*SessionState, error)
```

### `Runtime`

Runtime is normally bound by NewFactory. It remains public for adapter and
protocol tests that instantiate the transport-neutral plugin directly.

```go
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader
	Secret  string
	AppName string

	EncryptSecret func([]byte) (string, error)
	DecryptSecret func(string) ([]byte, error)

	ResolveSession ResolveSessionFunc
	IssueSession   IssueSessionFunc
	DeleteSession  func(context.Context, string) error
	NewSession     func(*engine.Context) *SessionState
	SetNewSession  func(*engine.Context, *SessionState)
	SerializeUser  func(storage.Record) any

	SessionCookie           func(contract.Request) Cookie
	Cookie                  CookieResolver
	AccountCookieEnabled    bool
	OAuthStateCookieEnabled bool

	VerifyPassword func(hash, password string) bool
	RunBackground  func(context.Context, func(context.Context) error) error

	CreateVerification  CreateVerificationFunc
	FindVerification    FindVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
	DeleteVerification  DeleteVerificationFunc
}
```

### `SchemaOptions`

```go
type SchemaOptions struct {
	User      UserSchemaOptions
	TwoFactor TwoFactorSchemaOptions
}
```

### `SendOTPFunc`

```go
type SendOTPFunc func(context.Context, OTPMessage, *engine.Context) error
```

### `SessionState`

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `TOTPOptions`

```go
type TOTPOptions struct {
	Digits            int
	Period            time.Duration
	AllowPasswordless *bool
	Disable           bool
}
```

### `TwoFactorSchemaOptions`

```go
type TwoFactorSchemaOptions struct {
	ModelName               string
	Secret                  string
	BackupCodes             string
	UserID                  string
	Verified                string
	FailedVerificationCount string
	LockedUntil             string
}
```

### `TypedFactory`

TypedFactory is the concrete, non-erased two-factor plugin factory used by
typed plugin contexts. Its runtime behavioral compatibility delegates to the same production
factory as NewFactory.

```go
type TypedFactory struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedFactory`

### `NewTypedFactory`

```go
func NewTypedFactory(options Options) *TypedFactory
```

## Methods on `TypedFactory`

### `Build`

```go
func (factory *TypedFactory) Build(host singleauth.PluginHost) (engine.Plugin, error)
```

### `PluginID`

```go
func (*TypedFactory) PluginID() string
```

### `Schema`

```go
func (factory *TypedFactory) Schema() (storage.Schema, error)
```

### `UserAdditionalFields`

UserAdditionalFields is the statically inferred user contribution of the
two-factor plugin. model.Value preserves undefined, null, and boolean.

```go
type UserAdditionalFields struct {
	TwoFactorEnabled model.Value[bool]
}
```

## Constructors and functions for `UserAdditionalFields`

### `DecodeUserAdditionalFields`

```go
func DecodeUserAdditionalFields(fields model.Fields) (UserAdditionalFields, error)
```

### `UserSchemaOptions`

```go
type UserSchemaOptions struct {
	ModelName        string
	TwoFactorEnabled string
}
```

