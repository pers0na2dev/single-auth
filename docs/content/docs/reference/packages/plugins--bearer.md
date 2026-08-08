---
title: "github.com/pers0na2dev/single-auth/plugins/bearer"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/bearer.

- Import path: `github.com/pers0na2dev/single-auth/plugins/bearer`
- Package name: `bearer`

Package bearer implements the single-auth 1.6.26 bearer server plugin.

A valid Authorization bearer value is converted into the configured signed
session cookie before endpoint execution. Session cookies written by an
endpoint are exposed as Set-Auth-Token after execution.

## Constants

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

New validates and snapshots a single-auth bearer plugin.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds the bearer plugin to the final root secret and
request-scoped session cookie configuration during singleauth.New.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

## Types

### `Options`

Options configures the single-auth-compatible bearer plugin.

```go
type Options struct {
	// RequireSignature rejects raw session tokens. Signed cookie values remain
	// accepted. The single-auth default is false.
	RequireSignature bool
	Runtime          Runtime
}
```

### `Runtime`

Runtime contains the normalized root-auth values single-auth exposes to
plugin hooks through its internal context. The current public Go engine
context deliberately does not expose either value, so they are explicit.

```go
type Runtime struct {
	Secret            string
	SessionCookieName string
	// ResolveSessionCookie supplies the request-scoped session cookie name.
	// It is used by NewFactory for dynamic and secure root cookie settings.
	ResolveSessionCookie func(contract.Request) string
}
```

