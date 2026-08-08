---
title: "github.com/pers0na2dev/single-auth/plugins/onetimetoken"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/onetimetoken.

- Import path: `github.com/pers0na2dev/single-auth/plugins/onetimetoken`
- Package name: `onetimetoken`

Package onetimetoken implements single-auth 1.6.26's one-time-token plugin.

## Constants

```go
const Version = "1.6.26"
```

## Functions

### `Duration`

```go
func Duration(value time.Duration) *time.Duration
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

## Types

### `ConsumeVerificationFunc`

```go
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)
```

### `CreateVerificationFunc`

```go
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
```

### `FindSessionFunc`

```go
type FindSessionFunc func(context.Context, string) (*SessionState, error)
```

### `GenerateTokenFunc`

```go
type GenerateTokenFunc func(*engine.Context, SessionState) (string, error)
```

### `NewSessionFunc`

```go
type NewSessionFunc func(*engine.Context) *SessionState
```

### `Options`

```go
type Options struct {
	// ExpiresIn distinguishes omission from an explicit zero duration, matching
	// JavaScript's nullish default. Nil selects three minutes.
	ExpiresIn *time.Duration

	DisableClientRequest     bool
	GenerateToken            GenerateTokenFunc
	DisableSetSessionCookie  bool
	Storage                  TokenStorage
	SetOTTHeaderOnNewSession bool

	Runtime Runtime
}
```

### `RefreshSessionFunc`

```go
type RefreshSessionFunc func(*engine.Context, SessionState) error
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context) (*SessionState, error)
```

### `Runtime`

Runtime contains the request and persistence services supplied by
singleauth.PluginHost. Adapter is only used by standalone plugin instances
when explicit verification callbacks are omitted.

```go
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader

	ResolveSession ResolveSessionFunc
	FindSession    FindSessionFunc
	RefreshSession RefreshSessionFunc
	NewSession     NewSessionFunc

	SerializeSession SerializeRecordFunc
	SerializeUser    SerializeRecordFunc

	CreateVerification  CreateVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
}
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
	StoreCustom TokenStoreMode = "custom-hasher"
)
```

