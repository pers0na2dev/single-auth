---
title: "github.com/pers0na2dev/single-auth/plugins/onetap"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/onetap.

- Import path: `github.com/pers0na2dev/single-auth/plugins/onetap`
- Package name: `onetap`

Package onetap ports single-auth's Google One Tap server plugin.

## Constants

```go
const Version = "1.6.26"
```

## Functions

### `MustNew`

```go
func MustNew(options Options) engine.Plugin
```

### `New`

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

```go
func NewFactory(options Options) singleauth.PluginFactory
```

## Types

### `Options`

```go
type Options struct {
	DisableSignup bool
	ClientID      string

	// VerifyIDToken is an injectable equivalent of verifyGoogleIdToken. Nil
	// uses the frozen providers.VerifyGoogleIDToken implementation.
	VerifyIDToken VerifyIDTokenFunc
	Runtime       Runtime
}
```

### `Runtime`

Runtime contains root identity/session services injected by NewFactory.

```go
type Runtime struct {
	Logger          *logger.Logger
	SocialProvider  func(string) *providers.Provider
	HandleOAuthUser func(*engine.Context, singleauth.PluginOAuthUserInput) (singleauth.PluginOAuthUserResult, error)
	RefreshSession  func(*engine.Context, singleauth.PluginSessionState, bool) error
	SerializeUser   func(map[string]any) any
}
```

### `VerifyIDTokenFunc`

```go
type VerifyIDTokenFunc func(context.Context, VerifyIDTokenInput) (map[string]any, error)
```

### `VerifyIDTokenInput`

```go
type VerifyIDTokenInput struct {
	Token      string
	Audience   any
	HTTPClient any
}
```

