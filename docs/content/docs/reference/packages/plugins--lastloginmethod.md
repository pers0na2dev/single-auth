---
title: "github.com/pers0na2dev/single-auth/plugins/lastloginmethod"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/lastloginmethod.

- Import path: `github.com/pers0na2dev/single-auth/plugins/lastloginmethod`
- Package name: `lastloginmethod`

Package lastloginmethod implements single-auth 1.6.26's
last-login-method plugin.

The plugin is transport-neutral. NewFactory binds it to the root auth
runtime, so the same descriptor observes sessions issued through direct
calls, net/http, fasthttp, and Fiber. Database persistence is installed
through the root database-hook registry before user-defined hooks.

## Constants

```go
const (
	Version = "1.6.26"

	DefaultCookieName = "single-auth.last_used_login_method"
	DefaultMaxAge     = 60 * 60 * 24 * 30
)
```

## Functions

### `Int`

Int returns a pointer for options whose omitted and zero states differ.

```go
func Int(value int) *int
```

### `Method`

Method returns a method pointer suitable for ResolveMethodFunc.

```go
func Method(value string) *string
```

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New constructs a standalone engine descriptor. StoreInDatabase requires
Runtime.Adapter and Runtime.RegisterDatabaseHooks; NewFactory supplies both.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory contributes the optional user field before adapter construction
and installs database hooks during the root plugin initialization phase.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema returns an independent schema extension for options.

```go
func Schema(options Options) (storage.Schema, error)
```

## Types

### `BeforeStoreCookieFunc`

BeforeStoreCookieFunc decides whether the readable method cookie may be
written. Returning an error is equivalent to a rejected Promise upstream:
the error is logged, the cookie is skipped, and authentication continues.

```go
type BeforeStoreCookieFunc func(HookContext, string) (bool, error)
```

### `HookContext`

HookContext is the Go view of single-auth's GenericEndpointContext fields
used by this plugin. Path is the endpoint route pattern, not the concrete
URL, and is normalized to an empty string for a pathless endpoint.

```go
type HookContext struct {
	Endpoint *engine.Context
	Path     string
	Params   map[string]string
	Request  contract.Request
}
```

### `Options`

Options configures single-auth's last-login-method plugin.

```go
type Options struct {
	// CookieName is used verbatim and is deliberately unaffected by the root
	// cookie prefix. Empty selects DefaultCookieName.
	CookieName string
	// MaxAge is expressed in seconds. Nil selects DefaultMaxAge; a pointer to
	// zero preserves single-auth's explicit Max-Age=0 behavior.
	MaxAge *int

	CustomResolveMethod ResolveMethodFunc
	StoreInDatabase     bool
	BeforeStoreCookie   BeforeStoreCookieFunc
	Schema              SchemaOptions
	Runtime             Runtime
}
```

### `ResolveMethodFunc`

ResolveMethodFunc returns a method override. Nil means the custom resolver
declined to resolve and the built-in resolver must run, matching JavaScript
nullish-coalescing. A pointer to an empty string is an explicit empty result
and suppresses the built-in fallback.

```go
type ResolveMethodFunc func(HookContext) (*string, error)
```

### `Runtime`

Runtime contains dependencies injected by NewFactory. It is public so a
standalone engine plugin can be assembled in focused conformance tests.

```go
type Runtime struct {
	Adapter               storage.Adapter
	Logger                *logger.Logger
	SessionCookie         SessionCookieResolver
	RegisterDatabaseHooks func(singleauth.DatabaseHooks) error
}
```

### `SchemaOptions`

```go
type SchemaOptions struct {
	User UserSchemaOptions
}
```

### `SessionCookieResolver`

```go
type SessionCookieResolver func(contract.Request) (string, cookies.Options)
```

### `UserSchemaOptions`

```go
type UserSchemaOptions struct {
	// LastLoginMethod is the physical database field name for the canonical
	// lastLoginMethod field. Empty selects "lastLoginMethod".
	LastLoginMethod string
}
```

