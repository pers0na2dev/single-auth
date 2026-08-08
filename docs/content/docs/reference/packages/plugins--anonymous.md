---
title: "github.com/pers0na2dev/single-auth/plugins/anonymous"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/anonymous.

- Import path: `github.com/pers0na2dev/single-auth/plugins/anonymous`
- Package name: `anonymous`

Package anonymous implements the single-auth 1.6.26 anonymous server plugin.

The descriptor is transport neutral. NewFactory binds it to single-auth's
canonical persistence, session, cookie, secondary-storage, and logging
semantics for net/http, fasthttp, Fiber, and direct endpoint invocation.

## Constants

```go
const (
	ErrorInvalidEmailFormat                         = "INVALID_EMAIL_FORMAT"
	ErrorFailedToCreateUser                         = "FAILED_TO_CREATE_USER"
	ErrorCouldNotCreateSession                      = "COULD_NOT_CREATE_SESSION"
	ErrorAnonymousUsersCannotSignInAgainAnonymously = "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"
	ErrorFailedToDeleteAnonymousUser                = "FAILED_TO_DELETE_ANONYMOUS_USER"
	ErrorFailedToDeleteAnonymousUserSessions        = "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS"
	ErrorUserIsNotAnonymous                         = "USER_IS_NOT_ANONYMOUS"
	ErrorDeleteAnonymousUserDisabled                = "DELETE_ANONYMOUS_USER_DISABLED"
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

New validates and snapshots a single-auth anonymous plugin descriptor.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds anonymous persistence, sessions, cookie cleanup, secondary
storage invalidation, and logging to the final root runtime.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema returns an independent copy of the anonymous user-field schema.

```go
func Schema() storage.Schema
```

## Types

### `Cookie`

Cookie describes one resolved single-auth cookie. Attributes are reused
when the delete endpoint expires the cookie.

```go
type Cookie struct {
	Name       string
	Attributes cookies.Options
}
```

### `CreateUserFunc`

```go
type CreateUserFunc func(*engine.Context, storage.Record) (storage.Record, error)
```

### `GenerateNameFunc`

```go
type GenerateNameFunc func(*engine.Context) (string, error)
```

### `GenerateRandomEmailFunc`

```go
type GenerateRandomEmailFunc func() (string, error)
```

### `IssueSessionFunc`

```go
type IssueSessionFunc func(*engine.Context, string) (*SessionState, error)
```

### `LinkAccountData`

LinkAccountData is passed before post-link cleanup. NewUser deliberately
contains both the new user and its session, matching the upstream callback.

```go
type LinkAccountData struct {
	AnonymousUser SessionState
	NewUser       SessionState
	Context       *engine.Context
}
```

### `LinkAccountFunc`

```go
type LinkAccountFunc func(LinkAccountData) error
```

### `LogErrorFunc`

```go
type LogErrorFunc func(string, ...any)
```

### `NewSessionFunc`

```go
type NewSessionFunc func(*engine.Context) *SessionState
```

### `Options`

Options configures the single-auth-compatible anonymous plugin.

```go
type Options struct {
	EmailDomainName            string
	OnLinkAccount              LinkAccountFunc
	DisableDeleteAnonymousUser bool
	GenerateName               GenerateNameFunc
	GenerateRandomEmail        GenerateRandomEmailFunc
	Schema                     storage.Schema
	Runtime                    Runtime
}
```

### `ResolveSessionCookiesFunc`

```go
type ResolveSessionCookiesFunc func(contract.Request) SessionCookies
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context, SessionResolution) (*SessionState, error)
```

### `RevokeSessionsFunc`

```go
type RevokeSessionsFunc func(*engine.Context, string) error
```

### `Runtime`

Runtime contains dependencies single-auth normally injects into the
endpoint context. NewFactory supplies all of them from PluginHost.

```go
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader

	ResolveSession        ResolveSessionFunc
	IssueSession          IssueSessionFunc
	NewSession            NewSessionFunc
	SetNewSession         SetNewSessionFunc
	CreateUser            CreateUserFunc
	SerializeUser         SerializeUserFunc
	RevokeSessions        RevokeSessionsFunc
	ResolveSessionCookies ResolveSessionCookiesFunc
	Error                 LogErrorFunc
}
```

### `SerializeUserFunc`

```go
type SerializeUserFunc func(storage.Record) any
```

### `SessionCookies`

SessionCookies contains every cookie deleted by deleteSessionCookie in
single-auth 1.6.26. AccountData and OAuthState are nil when their respective
storage options are disabled.

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

DefaultSessionCookies returns single-auth's non-secure default cookie set.
Root integrations should prefer NewFactory so overrides, secure prefixes,
dynamic domains, and optional account/OAuth cookies remain authoritative.

```go
func DefaultSessionCookies() SessionCookies
```

### `SessionResolution`

SessionResolution selects the authority required by an anonymous endpoint.

```go
type SessionResolution uint8
```

## Constants associated with `SessionResolution`

```go
const (
	SessionOptional SessionResolution = iota
	SessionRequired
	SessionAuthoritative
)
```

### `SessionState`

SessionState is the session/user pair exposed by single-auth endpoint
context session helpers.

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `SetNewSessionFunc`

```go
type SetNewSessionFunc func(*engine.Context, *SessionState)
```

