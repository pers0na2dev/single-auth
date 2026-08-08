---
title: "github.com/pers0na2dev/single-auth/plugins/haveibeenpwned"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/haveibeenpwned.

- Import path: `github.com/pers0na2dev/single-auth/plugins/haveibeenpwned`
- Package name: `haveibeenpwned`

Package haveibeenpwned implements single-auth 1.6.26's Have I Been Pwned
password plugin using the Pwned Passwords k-anonymity range API.

## Constants

```go
const (
	Version  = "1.6.26"
	PluginID = "have-i-been-pwned"

	ErrorPasswordCompromised  = "PASSWORD_COMPROMISED"
	DefaultCompromisedMessage = "The password you entered has been compromised. Please choose a different password."
	RangeAPIBaseURL           = "https://api.pwnedpasswords.com/range/"
)
```

## Functions

### `Bool`

```go
func Bool(value bool) *bool
```

### `CheckPassword`

CheckPassword checks one plaintext password using the k-anonymity range
protocol. Empty passwords are ignored exactly like upstream; endpoint-level
required/length validation remains authoritative.

```go
func CheckPassword(ctx context.Context, password string, options Options) error
```

### `DefaultPaths`

DefaultPaths returns an independent copy of the upstream path allowlist.

```go
func DefaultPaths() []string
```

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New constructs the single-auth-compatible descriptor and installs its
password hash wrapper. The wrapper runs at the actual hash point so each
endpoint keeps its own validation, verification-token, and session order.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds the plugin to the root request-aware password hash chain
after singleauth.New has finalized its password and HTTP client options.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

## Types

### `HTTPDoer`

HTTPDoer is implemented by *http.Client. Supplying a client with a custom
RoundTripper keeps conformance tests and private deployments off the real
Pwned Passwords network endpoint.

```go
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
```

### `Options`

Options configures the single-auth-compatible plugin. Nil Paths selects the
upstream defaults; an explicit empty slice disables every endpoint path.

```go
type Options struct {
	CustomPasswordCompromisedMessage string
	Paths                            []string
	// Enabled defaults to true. Bool(false) disables checks while preserving
	// the original password hash behavior.
	Enabled    *bool
	HTTPClient HTTPDoer
	Runtime    Runtime
}
```

### `PasswordHashFunc`

PasswordHashFunc is the context-aware password hash chain installed by the
root PluginFactory. The endpoint context is nil outside an auth dispatch.

```go
type PasswordHashFunc func(*engine.Context, string) (string, error)
```

### `PasswordHashWrapper`

PasswordHashWrapper wraps the hash chain in plugin initialization order.

```go
type PasswordHashWrapper func(PasswordHashFunc) PasswordHashFunc
```

### `Runtime`

```go
type Runtime struct {
	WrapPasswordHash func(PasswordHashWrapper) error
}
```

