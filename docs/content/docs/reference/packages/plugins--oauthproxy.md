---
title: "github.com/pers0na2dev/single-auth/plugins/oauthproxy"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/oauthproxy.

- Import path: `github.com/pers0na2dev/single-auth/plugins/oauthproxy`
- Package name: `oauthproxy`

Package oauthproxy ports single-auth 1.6.26's OAuth proxy plugin.

It moves an OAuth authorization-code callback through a trusted production
origin while creating the user and session only in the originating preview
environment. State and profile payloads are authenticated encryption values,
are bound to the original OAuth state, expire quickly, and are single-use
whenever the configured state strategy has server-side storage.

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

New constructs a standalone transport-neutral OAuth proxy plugin.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

```go
func NewFactory(options ...Options) singleauth.PluginFactory
```

## Types

### `Options`

Options mirrors the server options of single-auth's oAuthProxy plugin.
MaxAge is a Go duration; zero preserves single-auth's 60-second default.
Secret selects a dedicated legacy-compatible proxy key. SecretConfig is the
rotation-aware equivalent and takes precedence when both are provided.

```go
type Options struct {
	CurrentURL    string
	ProductionURL string
	MaxAge        time.Duration
	Secret        string
	SecretConfig  *baCrypto.SecretConfig
	Runtime       Runtime
}
```

### `Runtime`

Runtime is the transport-neutral host surface required by a standalone
plugin. NewFactory binds every field to the root singleauth.Auth runtime.

```go
type Runtime struct {
	BaseURL       string
	BasePath      string
	ErrorURL      string
	StateStrategy string

	Clock  func() time.Time
	Random io.Reader
	Logger *logger.Logger

	ResolveBaseURL  func(contract.Request) (string, error)
	IsTrustedOrigin func(contract.Request, string, bool) (bool, error)
	Cookie          func(contract.Request, string, string) (string, cookies.Options)

	EncryptSecret func([]byte) (string, error)
	DecryptSecret func(string) ([]byte, error)

	SocialProvider  func(string) *providers.Provider
	HandleOAuthUser func(*engine.Context, singleauth.PluginOAuthUserInput) (singleauth.PluginOAuthUserResult, error)
	RefreshSession  func(*engine.Context, singleauth.PluginSessionState, bool) error

	FindVerification    func(context.Context, string) (storage.Record, error)
	ConsumeVerification func(context.Context, string) (storage.Record, error)
}
```

