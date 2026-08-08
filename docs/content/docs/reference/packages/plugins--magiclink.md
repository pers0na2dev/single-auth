---
title: "github.com/pers0na2dev/single-auth/plugins/magiclink"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/magiclink.

- Import path: `github.com/pers0na2dev/single-auth/plugins/magiclink`
- Package name: `magiclink`

Package magiclink implements single-auth 1.6.26's built-in magic-link
plugin for the transport-neutral single-auth engine.

## Constants

```go
const Version = "1.6.26"
```

## Functions

### `Float64`

```go
func Float64(value float64) *float64
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

NewFactory binds magic-link to the final root adapter, session lifecycle,
dynamic base URL, serializers, and trusted-origin policy.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema is empty because magic-link 1.6.26 adds no plugin model. It consumes
single-auth's core verification, user, account, and session models.

```go
func Schema() storage.Schema
```

## Types

### `BaseURLResolver`

```go
type BaseURLResolver func(*engine.Context) (string, error)
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
	Email string
	Name  string
}
```

### `CreateVerificationFunc`

```go
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
```

### `FormRequestValidator`

```go
type FormRequestValidator func(*engine.Context) error
```

### `GenerateTokenFunc`

```go
type GenerateTokenFunc func(context.Context, string) (string, error)
```

### `IssueSessionFunc`

IssueSession creates a session for user and writes the host's session
cookies to ctx. A nil state or session maps to failed_to_create_session.

```go
type IssueSessionFunc func(*engine.Context, storage.Record) (*SessionState, error)
```

### `MagicLinkMessage`

```go
type MagicLinkMessage struct {
	Email    string         `json:"email"`
	URL      string         `json:"url"`
	Token    string         `json:"token"`
	Metadata map[string]any `json:"metadata,omitempty"`
}
```

### `Options`

Options configures the single-auth-compatible magic-link plugin.

```go
type Options struct {
	ExpiresIn time.Duration
	// AllowedAttempts is deprecated and ignored. A non-nil value other than 1
	// emits the upstream compatibility warning. float64 preserves Infinity.
	AllowedAttempts *float64
	SendMagicLink   SendMagicLinkFunc
	DisableSignUp   bool
	RateLimit       RateLimitOptions
	GenerateToken   GenerateTokenFunc
	Storage         TokenStorage
	Runtime         Runtime
}
```

### `RateLimitOptions`

```go
type RateLimitOptions struct {
	Window int64
	Max    int64
}
```

### `RedirectKind`

```go
type RedirectKind string
```

## Constants associated with `RedirectKind`

```go
const (
	RedirectCallback RedirectKind = "callbackURL"
	RedirectNewUser  RedirectKind = "newUserCallbackURL"
	RedirectError    RedirectKind = "errorCallbackURL"
)
```

### `RedirectValidator`

```go
type RedirectValidator func(*engine.Context, string, RedirectKind) error
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
internal endpoint context. The host owns session cookies, user/session
output filtering, dynamic base URLs, secondary-session invalidation, and
canonical trusted-origin policy, so those dependencies are explicit.

```go
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader

	BaseURL        string
	BasePath       string
	ResolveBaseURL BaseURLResolver

	TrustedOrigins        []string
	ResolveTrustedOrigins TrustedOriginsResolver
	ValidateFormRequest   FormRequestValidator
	ValidateRedirect      RedirectValidator

	CreateUser       CreateUserFunc
	IssueSession     IssueSessionFunc
	SerializeUser    SerializeRecordFunc
	SerializeSession SerializeRecordFunc
	RevokeUnproven   RevokeUnprovenAccessFunc
	// RevokeSessions must invalidate database and secondary-storage sessions.
	// The default implementation deletes core session rows through Adapter.
	RevokeSessions RevokeSessionsFunc
	Warn           func(string)

	CreateVerification  CreateVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
}
```

### `SendMagicLinkFunc`

SendMagicLink is awaited by the endpoint, matching upstream 1.6.26. A host
that wants detached delivery should schedule durable work inside this
callback rather than relying on request-context work after it returns.

```go
type SendMagicLinkFunc func(context.Context, MagicLinkMessage, *engine.Context) error
```

### `SerializeRecordFunc`

```go
type SerializeRecordFunc func(storage.Record) any
```

### `SessionState`

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `TokenHashFunc`

```go
type TokenHashFunc func(context.Context, string) (string, error)
```

### `TokenStorage`

TokenStorage is the Go representation of upstream's plain, hashed, or
custom-hasher storeToken union.

```go
type TokenStorage struct {
	Mode       TokenStoreMode
	CustomHash TokenHashFunc
}
```

### `TokenStoreMode`

```go
type TokenStoreMode string
```

## Constants associated with `TokenStoreMode`

```go
const (
	StorePlain  TokenStoreMode = "plain"
	StoreHashed TokenStoreMode = "hashed"
)
```

### `TrustedOriginsResolver`

```go
type TrustedOriginsResolver func(context.Context, contract.Request) ([]string, error)
```

