---
title: "github.com/pers0na2dev/single-auth/plugins/multisession"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/multisession.

- Import path: `github.com/pers0na2dev/single-auth/plugins/multisession`
- Package name: `multisession`

Package multisession implements single-auth 1.6.26's multi-session plugin.

The package is transport neutral. NewFactory binds the plugin to a root
single-auth runtime, while New accepts an explicit Runtime for standalone
registries and tests.

## Constants

```go
const ErrorInvalidSessionToken = "INVALID_SESSION_TOKEN"
```

```go
const Version = "1.6.26"
```

## Functions

### `Int`

Int returns a pointer suitable for MaximumSessions.

```go
func Int(value int) *int
```

### `MustNew`

MustNew is New for static setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots a transport-neutral multi-session descriptor.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds the plugin to the final root adapter and request-scoped
cookie configuration.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

## Types

### `Cookie`

Cookie describes one request-resolved single-auth cookie.

```go
type Cookie struct {
	Name       string
	Attributes cookies.Options
}
```

### `DeleteSessionFunc`

```go
type DeleteSessionFunc func(context.Context, string) error
```

### `DeleteSessionsFunc`

```go
type DeleteSessionsFunc func(context.Context, []string) error
```

### `FindSessionFunc`

```go
type FindSessionFunc func(context.Context, string) (*SessionState, error)
```

### `FindSessionsFunc`

```go
type FindSessionsFunc func(context.Context, []string, bool) ([]SessionState, error)
```

### `NewSessionFunc`

```go
type NewSessionFunc func(*engine.Context) *SessionState
```

### `Options`

Options configures single-auth's multi-session plugin. Nil selects the
upstream default of five. A pointer preserves explicit zero and negative
values, both of which upstream accepts.

```go
type Options struct {
	MaximumSessions *int
	Runtime         Runtime
}
```

### `RefreshSessionFunc`

```go
type RefreshSessionFunc func(*engine.Context, SessionState, bool) error
```

### `ResolveSessionCookiesFunc`

```go
type ResolveSessionCookiesFunc func(contract.Request) SessionCookies
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context) (*SessionState, error)
```

### `Runtime`

Runtime contains dependencies single-auth normally injects into endpoint
context. NewFactory supplies the authoritative root implementations,
including secondary-storage-aware batch session operations.

```go
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Secret  string

	ResolveSession        ResolveSessionFunc
	FindSession           FindSessionFunc
	FindSessions          FindSessionsFunc
	RefreshSession        RefreshSessionFunc
	DeleteSession         DeleteSessionFunc
	DeleteSessions        DeleteSessionsFunc
	NewSession            NewSessionFunc
	ResolveSessionCookies ResolveSessionCookiesFunc
	SerializeSession      SerializeRecordFunc
	SerializeUser         SerializeRecordFunc
}
```

### `SerializeRecordFunc`

```go
type SerializeRecordFunc func(storage.Record) any
```

### `SessionCookies`

SessionCookies is the cookie set touched by deleteSessionCookie. Optional
cookies are nil when the corresponding root feature is disabled.

```go
type SessionCookies struct {
	SessionToken Cookie
	SessionData  Cookie
	DontRemember Cookie
	AccountData  *Cookie
	OAuthState   *Cookie
}
```

## Constructors and functions for `SessionCookies`

### `DefaultSessionCookies`

DefaultSessionCookies returns single-auth's ordinary non-secure defaults.
Root integrations should use NewFactory so dynamic domains, secure prefixes,
overrides, account cookies, and OAuth state strategy stay request scoped.

```go
func DefaultSessionCookies() SessionCookies
```

### `SessionState`

SessionState is single-auth's session/user pair.

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

