---
title: "github.com/pers0na2dev/single-auth/plugins/customsession"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/customsession.

- Import path: `github.com/pers0na2dev/single-auth/plugins/customsession`
- Package name: `customsession`

Package customsession implements the single-auth 1.6.26 custom-session
plugin. It replaces get-session with a caller-defined projection and can
apply the same projection to multi-session device listings.

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

New validates and snapshots a single-auth custom-session descriptor.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds the custom session projection to the final root runtime.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

## Types

### `EnrichFunc`

EnrichFunc projects one public single-auth session into the response shape
returned by get-session. The callback receives the active endpoint context,
matching GenericEndpointContext in the upstream plugin.

```go
type EnrichFunc func(SessionData, *engine.Context) (any, error)
```

### `GetSessionFunc`

GetSessionFunc invokes the unmodified core get-session implementation in an
isolated response context. Its returned headers are copied to the outer
custom-session response only after Enrich succeeds.

```go
type GetSessionFunc func(*engine.Context) (contract.Response, error)
```

### `Options`

Options configures the single-auth-compatible custom-session plugin.

```go
type Options struct {
	Enrich EnrichFunc

	// ShouldMutateListDeviceSessionsEndpoint applies Enrich concurrently to
	// every successful multi-session list-device-sessions result.
	ShouldMutateListDeviceSessionsEndpoint bool

	Runtime Runtime
}
```

### `Runtime`

Runtime contains the one core service that single-auth injects implicitly.
NewFactory supplies it from PluginHost; standalone descriptors provide it
explicitly for deterministic transport-neutral use.

```go
type Runtime struct {
	GetSession GetSessionFunc
}
```

### `SessionData`

SessionData is the serialized session/user pair supplied to Enrich. The
records already passed through the host's public output serializers.

```go
type SessionData struct {
	User    storage.Record `json:"user"`
	Session storage.Record `json:"session"`
}
```

### `TypedAuth`

TypedAuth retains the concrete custom-session projection on the server-side
direct API while embedding the complete HTTP Auth runtime.

```go
type TypedAuth[Projection any] struct {
	*singleauth.Auth
}
```

## Methods on `TypedAuth`

### `API`

API returns the custom get-session override plus every promoted base direct
API method, including sign-up, sign-in, and sign-out.

```go
func (auth *TypedAuth[Projection]) API() TypedDirectAPI[Projection]
```

### `TypedDirectAPI`

TypedDirectAPI explicitly replaces GetSession's result type while embedding
the stable base API so unrelated endpoints remain available.

```go
type TypedDirectAPI[Projection any] struct {
	singleauth.DirectAPI
}
```

## Methods on `TypedDirectAPI`

### `GetSession`

GetSession invokes the production overridden endpoint and decodes its exact
JSON response into Projection.

```go
func (api TypedDirectAPI[Projection]) GetSession(
	ctx context.Context,
	input singleauth.GetSessionInput,
) (*TypedSessionResult[Projection], error)
```

### `TypedEnrichFunc`

TypedEnrichFunc is the statically typed form of EnrichFunc.

```go
type TypedEnrichFunc[Projection any] func(SessionData, *engine.Context) (Projection, error)
```

### `TypedFactory`

TypedFactory is both a regular production PluginFactory and the type token
from which server custom-session projections are bound.

```go
type TypedFactory[Projection any] struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedFactory`

### `NewTypedFactory`

NewTypedFactory preserves the Enrich return type without changing the
runtime custom-session plugin contract.

```go
func NewTypedFactory[Projection any](options TypedOptions[Projection]) *TypedFactory[Projection]
```

## Methods on `TypedFactory`

### `BindAuth`

BindAuth attaches the factory's projection type to an initialized runtime.

```go
func (factory *TypedFactory[Projection]) BindAuth(auth *singleauth.Auth) (*TypedAuth[Projection], error)
```

### `Build`

```go
func (factory *TypedFactory[Projection]) Build(host singleauth.PluginHost) (engine.Plugin, error)
```

### `PluginID`

```go
func (*TypedFactory[Projection]) PluginID() string
```

### `Schema`

```go
func (*TypedFactory[Projection]) Schema() (storage.Schema, error)
```

### `TypedOptions`

TypedOptions binds the custom-session callback's concrete return type to the
server factory.

```go
type TypedOptions[Projection any] struct {
	Enrich                                 TypedEnrichFunc[Projection]
	ShouldMutateListDeviceSessionsEndpoint bool
}
```

### `TypedSessionResult`

TypedSessionResult is the concrete custom-session response and its response
headers. Projection is never decoded through any.

```go
type TypedSessionResult[Projection any] struct {
	Data    Projection
	Headers contract.Headers
}
```

