---
title: "github.com/pers0na2dev/single-auth/core/engine"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/core/engine.

- Import path: `github.com/pers0na2dev/single-auth/core/engine`
- Package name: `engine`

Package engine implements the immutable endpoint registry, router, and
dispatch pipeline used by single-auth transports and direct server calls.

It is HTTP implementation agnostic and does not import net/http, fasthttp,
or Fiber.

## Constants

```go
const (
	EndpointScopeMetadataKey  = "scope"
	EndpointActionMetadataKey = "isAction"
	EndpointScopeServer       = "server"
	EndpointScopeHTTP         = "http"
)
```

ServerOnlyMetadataKey is the reference implementation's defense-in-depth marker for endpoints
that are available to trusted direct callers but must never occupy an HTTP
route, even when a path is accidentally present on the declaration.

```go
const ServerOnlyMetadataKey = "SERVER_ONLY"
```

## Functions

### `RunEndpointIsolated`

RunEndpointIsolated invokes one endpoint handler using request-local state
cloned from source, without running registry hooks, path-scoped middleware,
or response stages. Endpoint-local Use middleware still runs because it is
part of the endpoint itself. Response headers accumulated by the middleware
or handler are merged into the returned response, never into source. This is
the the reference implementation-compatible primitive used when a plugin wraps an original
core endpoint.

```go
func RunEndpointIsolated(
	source *Context,
	request contract.Request,
	endpoint Endpoint,
) (contract.Response, error)
```

### `SetShouldSkipSessionRefresh`

SetShouldSkipSessionRefresh stores the reference implementation's request-local session
refresh guard. Framework integrations use it when the active rendering
context cannot mutate response cookies.

```go
func SetShouldSkipSessionRefresh(c *Context, skip bool)
```

### `ShouldSkipSessionRefresh`

ShouldSkipSessionRefresh reports the request-local framework refresh guard.

```go
func ShouldSkipSessionRefresh(c *Context) bool
```

## Types

### `AfterHook`

AfterHook is a matched post-endpoint hook.

```go
type AfterHook struct {
	Name    string
	Matcher Matcher
	Handler AfterHookFunc
}
```

### `AfterHookFunc`

AfterHookFunc runs after the endpoint (including typed endpoint errors). A
non-nil response replaces the current response while preserving accumulated
response headers.

```go
type AfterHookFunc func(*Context, contract.Response) (*contract.Response, error)
```

### `BeforeHook`

BeforeHook is a matched pre-endpoint hook.

```go
type BeforeHook struct {
	Name    string
	Matcher Matcher
	Handler BeforeHookFunc
}
```

### `BeforeHookFunc`

BeforeHookFunc runs before the endpoint. A non-nil response short-circuits
the remaining before hooks and the endpoint; after hooks are not run.

```go
type BeforeHookFunc func(*Context) (*contract.Response, error)
```

### `ConflictError`

ConflictError aggregates all endpoint conflicts discovered during registry
construction so initialization can fail once with complete diagnostics.

```go
type ConflictError struct {
	Conflicts []EndpointConflict
}
```

## Methods on `ConflictError`

### `Error`

```go
func (e *ConflictError) Error() string
```

### `Context`

Context is request-local dispatch state. A new value is created for every
dispatch and is never shared between concurrent calls.

```go
type Context struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Context`

### `ContextFrom`

ContextFrom returns the endpoint context associated with a storage or
background callback context. It returns nil outside an engine dispatch.

```go
func ContextFrom(ctx context.Context) *Context
```

## Methods on `Context`

### `AddResponseHeader`

AddResponseHeader appends one response header line.

```go
func (c *Context) AddResponseHeader(name, value string)
```

### `AddSetCookie`

AddSetCookie appends a Set-Cookie line without ever joining it with another.

```go
func (c *Context) AddSetCookie(value string)
```

### `Endpoint`

Endpoint returns an independent endpoint descriptor when routing has
completed.

```go
func (c *Context) Endpoint() (Endpoint, bool)
```

### `GoContext`

GoContext returns the cancellation/deadline context carried by the request.

```go
func (c *Context) GoContext() context.Context
```

### `IsDirect`

IsDirect reports whether this dispatch was invoked through the direct API.

```go
func (c *Context) IsDirect() bool
```

### `Param`

Param returns one decoded dynamic route parameter.

```go
func (c *Context) Param(name string) (string, bool)
```

### `Params`

Params returns an independent parameter map.

```go
func (c *Context) Params() map[string]string
```

### `Path`

Path returns the endpoint route pattern after matching. Before matching it
returns RoutePath. Pathless direct endpoints use the reference implementation's /:virtual
diagnostic path.

```go
func (c *Context) Path() string
```

### `RemoveResponseHeaderValues`

RemoveResponseHeaderValues removes exact header lines that have already
been accumulated for the current response. It is primarily useful for
security-sensitive after hooks that must replace a cookie written by the
endpoint without leaving the earlier value on the wire.

Values added after this call are unaffected, so a hook can remove an old
Set-Cookie line and then append an expiring replacement for the same cookie.

```go
func (c *Context) RemoveResponseHeaderValues(name string, values ...string)
```

### `ReplaceRequest`

ReplaceRequest installs an independent request snapshot for subsequent
stages. It is intended for onRequest hooks.

```go
func (c *Context) ReplaceRequest(request contract.Request)
```

### `Request`

Request returns an independent request snapshot.

```go
func (c *Context) Request() contract.Request
```

### `ResponseHeaderValues`

ResponseHeaderValues returns the currently accumulated values for name,
including values already attached to the endpoint response and values added
by the active hook. The returned slice is independent from the context.

```go
func (c *Context) ResponseHeaderValues(name string) []string
```

### `Returned`

Returned returns the current endpoint/after-hook response and error.

```go
func (c *Context) Returned() (contract.Response, error, bool)
```

### `RoutePath`

RoutePath returns the actual path after base-path removal.

```go
func (c *Context) RoutePath() string
```

### `Set`

Set stores request-local data for later stages.

```go
func (c *Context) Set(key string, value any)
```

### `SetResponseHeader`

SetResponseHeader replaces every accumulated field with name.

```go
func (c *Context) SetResponseHeader(name, value string)
```

### `Value`

Value retrieves request-local data.

```go
func (c *Context) Value(key string) (any, bool)
```

### `ContextInitializer`

ContextInitializer installs runtime-owned request-local dependencies before
HTTP routing or direct endpoint dispatch.

```go
type ContextInitializer func(*Context) error
```

### `DELETE`

```go
type DELETE struct{}
```

### `DirectInput`

DirectInput is the request-local input for direct endpoint dispatch. Direct
dispatch runs user and plugin before/after hooks, but deliberately skips the
HTTP-only onRequest, route middleware, and onResponse stages.

```go
type DirectInput struct {
	Request contract.Request
	Params  map[string]string
	Values  map[string]any
}
```

### `Dispatcher`

Dispatcher is an immutable, goroutine-safe dispatch pipeline.

```go
type Dispatcher struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Dispatcher`

### `NewDispatcher`

NewDispatcher validates and snapshots all pipeline declarations. Subsequent
mutation of the caller's slices, plugin descriptors, or endpoint method
slices cannot affect the dispatcher.

```go
func NewDispatcher(registry *Registry, options DispatcherOptions) (*Dispatcher, error)
```

## Methods on `Dispatcher`

### `Dispatch`

Dispatch executes the HTTP pipeline. Response is always suitable for a
transport to write, including when err is non-nil. The error is returned as
well so hosts can inspect typed API errors and log unknown failures.

```go
func (d *Dispatcher) Dispatch(request contract.Request) (contract.Response, error)
```

### `Invoke`

Invoke dispatches an endpoint by direct API name. Server-only endpoints are
intentionally available here and impossible to reach through Dispatch.

```go
func (d *Dispatcher) Invoke(name string, input DirectInput) (contract.Response, error)
```

### `Registry`

Registry returns the dispatcher's immutable endpoint registry.

```go
func (d *Dispatcher) Registry() *Registry
```

### `DispatcherOptions`

DispatcherOptions configures the immutable HTTP pipeline around a registry.

```go
type DispatcherOptions struct {
	// BasePath is removed before endpoint and middleware matching. It must be a
	// static absolute path such as /api/auth.
	BasePath string

	// DisabledPaths are endpoint-relative paths checked before plugin
	// onRequest hooks, matching the reference implementation's router order.
	DisabledPaths []string

	// Middleware runs before plugin route middleware, in declared order.
	Middleware []Middleware

	// Hooks run before plugin hooks. User before and after hooks each preserve
	// declaration order.
	Hooks Hooks

	// OnRequest runs after disabled-path rejection and before plugin
	// OnRequest hooks. It is used by core request gates such as rate limiting.
	OnRequest []OnRequestFunc
	// InitializeContext installs runtime-owned request-local dependencies for
	// both HTTP and direct dispatch before endpoint middleware execute.
	InitializeContext ContextInitializer

	// SkipTrailingSlashes allows an endpoint or middleware route declared with
	// a trailing slash to match a request without one, and vice versa. The
	// request-local RoutePath remains unchanged so hooks continue to observe the
	// path that arrived on the wire.
	SkipTrailingSlashes bool
}
```

### `Endpoint`

Endpoint declares one direct API operation and, unless ServerOnly is true,
one HTTP route. An empty Methods slice means all methods.

```go
type Endpoint struct {
	Name       string
	Path       string
	Methods    []string
	ServerOnly bool
	// Use contains endpoint-local middleware. Unlike path-scoped router
	// middleware, these functions are part of the endpoint declaration and run
	// for every dispatch mode, including direct API and isolated invocation.
	Use []EndpointMiddlewareFunc
	// Metadata carries immutable, transport-neutral endpoint annotations for
	// consumers such as the OpenAPI generator. SERVER_ONLY is interpreted as a
	// routing guard; all other values remain opaque to the engine. The outer map
	// is snapshotted whenever an endpoint is cloned.
	Metadata map[string]any
	// Override replaces an earlier endpoint with the same name. It is intended
	// for the reference implementation plugins such as custom-session whose endpoint object is
	// spread over the core API object. The replacement must retain the same
	// route path and may only narrow the original method set.
	Override    bool
	OperationID string
	Handler     HandlerFunc
	// contains filtered or unexported fields
}
```

### `EndpointConflict`

EndpointConflict describes an indistinguishable route/method pair.

```go
type EndpointConflict struct {
	Path             string
	Method           string
	ExistingEndpoint string
	ExistingPlugin   string
	NewEndpoint      string
	NewPlugin        string
}
```

### `EndpointConflictLogger`

EndpointConflictLogger is the logging surface used by
CheckEndpointConflicts. logger.Logger satisfies this interface.

```go
type EndpointConflictLogger interface {
	Error(message string, args ...any)
}
```

### `EndpointMethodSpec`

EndpointMethodSpec is the sealed compile-time description of one or more
HTTP methods accepted by a TypedEndpoint. The concrete marker is retained in
the generic endpoint type while the production router receives a mutable
[]string snapshot through Endpoint.

```go
type EndpointMethodSpec interface {
	// contains filtered or unexported methods
}
```

### `EndpointMiddlewareFunc`

EndpointMiddlewareFunc prepares request-local context for one endpoint.
Endpoint middleware run sequentially in declaration order for HTTP, direct,
and isolated endpoint invocation.

```go
type EndpointMiddlewareFunc func(*Context) (EndpointMiddlewareResult, error)
```

### `EndpointMiddlewareResult`

EndpointMiddlewareResult is merged into the request-local endpoint context
before the next endpoint middleware runs. A non-nil Response short-circuits
the remaining endpoint middleware and handler after Values are merged.
This mirrors Better Call's sequential endpoint `use` context composition.

```go
type EndpointMiddlewareResult struct {
	Values   map[string]any
	Response *contract.Response
}
```

### `ErrorDefinition`

ErrorDefinition describes a plugin error code without coupling it to a
particular endpoint status.

```go
type ErrorDefinition struct {
	Code    string
	Message string
}
```

### `GET`

GET, POST, PUT, PATCH, DELETE, HEAD, and OPTIONS are zero-sized literal
method markers. Their concrete Go type is the analogue of a TypeScript
string-literal method type.

```go
type GET struct{}
```

### `HEAD`

```go
type HEAD struct{}
```

### `HandlerFunc`

HandlerFunc handles one matched endpoint.

```go
type HandlerFunc func(*Context) (contract.Response, error)
```

### `Hooks`

Hooks groups hooks while preserving their declared order.

```go
type Hooks struct {
	Before []BeforeHook
	After  []AfterHook
}
```

### `Matcher`

Matcher decides whether a hook applies. Returning an error produces a
redacted typed internal error while retaining the original cause.

```go
type Matcher func(*Context) (bool, error)
```

### `MethodSet2`

MethodSet2 preserves a two-method union in its concrete generic type. The
contained values are retained so future method markers can carry immutable
declaration data without changing the constructor contract.

```go
type MethodSet2[First, Second EndpointMethodSpec] struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `MethodSet2`

### `Methods2`

Methods2 constructs a statically typed two-method set. The returned
endpoint's Methods method still exposes an ordinary independently mutable
[]string, matching the reference implementation's mutable union-array normalization.

```go
func Methods2[First, Second EndpointMethodSpec](first First, second Second) MethodSet2[First, Second]
```

### `MethodSet3`

MethodSet3 preserves a three-method union for integrations whose endpoint
accepts more than the two-method combination exercised upstream.

```go
type MethodSet3[First, Second, Third EndpointMethodSpec] struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `MethodSet3`

### `Methods3`

Methods3 constructs a statically typed three-method set.

```go
func Methods3[First, Second, Third EndpointMethodSpec](
	first First,
	second Second,
	third Third,
) MethodSet3[First, Second, Third]
```

### `Middleware`

Middleware is a path-scoped router middleware. Path accepts the same dynamic
parameter syntax as endpoints and a final wildcard such as /oauth/**.

```go
type Middleware struct {
	Name    string
	Path    string
	Handler MiddlewareFunc
}
```

### `MiddlewareFunc`

MiddlewareFunc wraps route matching and endpoint dispatch.

```go
type MiddlewareFunc func(*Context, Next) (contract.Response, error)
```

### `Next`

Next invokes the next middleware or the matched endpoint pipeline.

```go
type Next func() (contract.Response, error)
```

### `OPTIONS`

```go
type OPTIONS struct{}
```

### `OnRequestFunc`

OnRequestFunc runs before route middleware and matching.

```go
type OnRequestFunc func(*Context) (OnRequestResult, error)
```

### `OnRequestResult`

OnRequestResult either replaces the request, short-circuits with a response,
or does neither. Setting both is a configuration/runtime error.

```go
type OnRequestResult struct {
	Request  *contract.Request
	Response *contract.Response
}
```

### `OnResponseFunc`

OnResponseFunc runs after the complete HTTP pipeline. Returning nil preserves
the current response; returning a response replaces it.

```go
type OnResponseFunc func(*Context, contract.Response) (*contract.Response, error)
```

### `PATCH`

```go
type PATCH struct{}
```

### `POST`

```go
type POST struct{}
```

### `PUT`

```go
type PUT struct{}
```

### `Plugin`

Plugin is the transport-neutral portion of a the reference implementation plugin descriptor.
Storage schemas, migrations, and adapter extensions live in their respective
packages; lifecycle and endpoint ordering is defined here.

```go
type Plugin struct {
	ID         string
	Version    string
	Schema     storage.Schema
	Endpoints  []Endpoint
	Middleware []Middleware
	Hooks      Hooks
	OnRequest  OnRequestFunc
	OnResponse OnResponseFunc
	RateLimit  []ratelimit.MatcherRule
	ErrorCodes map[string]ErrorDefinition

	// TrustedOrigins and ResolveTrustedOrigins are merged with user options in
	// plugin order, matching the reference implementation plugin init() option contributions.
	TrustedOrigins        []string
	ResolveTrustedOrigins func(context.Context, contract.Request) ([]string, error)
	// SkipOriginCheckPaths contributes exact route prefixes that receive
	// external protocol POSTs and therefore cannot use browser Origin/CSRF
	// validation. SAML ACS/SLO endpoints validate their own signed messages.
	SkipOriginCheckPaths []string
}
```

### `PluginEndpointConflict`

PluginEndpointConflict is the path-level conflict report emitted by Better
Auth before its router is built. Unlike EndpointConflict, this value keeps
the plugin-oriented shape and method ordering used by the upstream
checkEndpointConflicts helper.

```go
type PluginEndpointConflict struct {
	Path               string
	Plugins            []string
	ConflictingMethods []string
}
```

## Constructors and functions for `PluginEndpointConflict`

### `CheckEndpointConflicts`

CheckEndpointConflicts detects exact-path overlaps between plugin endpoints
with the reference implementation's method semantics. An endpoint without methods occupies the
wildcard method. Pathless endpoints are direct-only declarations for this
preflight and are ignored.

When one or more conflicts are found, logger receives exactly one aggregate
error message. The returned slice is a Go convenience; the reference implementation exposes
the same information only through that log entry.

```go
func CheckEndpointConflicts(plugins []Plugin, logger EndpointConflictLogger) []PluginEndpointConflict
```

### `Registry`

Registry is an immutable collection of direct endpoints and routable HTTP
endpoints. It is safe for concurrent reads.

```go
type Registry struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Registry`

### `NewRegistry`

NewRegistry validates and snapshots core endpoints followed by plugins in
registration order. Conflicting dynamic parameter names are treated as the
same route shape: /users/:id conflicts with /users/:userID for an overlapping
method.

```go
func NewRegistry(core []Endpoint, plugins ...Plugin) (*Registry, error)
```

## Methods on `Registry`

### `Endpoint`

Endpoint returns a cloned endpoint descriptor by direct API name.

```go
func (r *Registry) Endpoint(name string) (Endpoint, bool)
```

### `Endpoints`

Endpoints returns all direct endpoints, including server-only entries, in
deterministic registration order.

```go
func (r *Registry) Endpoints() []Endpoint
```

### `ErrorCodes`

ErrorCodes returns a copy of all plugin error definitions. Later plugins
override earlier definitions, matching the reference implementation's object-spread behavioral compatibility.

```go
func (r *Registry) ErrorCodes() map[string]ErrorDefinition
```

### `Match`

Match resolves a non-server-only endpoint and decoded parameters.

```go
func (r *Registry) Match(method, rawPath string) (RouteMatch, error)
```

### `RegistryError`

RegistryError reports one invalid registry declaration.

```go
type RegistryError struct {
	Kind       RegistryErrorKind
	PluginID   string
	Endpoint   string
	Middleware string
	Message    string
	Cause      error
}
```

## Methods on `RegistryError`

### `Error`

```go
func (e *RegistryError) Error() string
```

### `Unwrap`

Unwrap exposes the parsing/validation cause.

```go
func (e *RegistryError) Unwrap() error
```

### `RegistryErrorKind`

RegistryErrorKind classifies initialization failures.

```go
type RegistryErrorKind string
```

## Constants associated with `RegistryErrorKind`

```go
const (
	RegistryErrorInvalidEndpoint       RegistryErrorKind = "INVALID_ENDPOINT"
	RegistryErrorDuplicateEndpointName RegistryErrorKind = "DUPLICATE_ENDPOINT_NAME"
	RegistryErrorDuplicatePluginID     RegistryErrorKind = "DUPLICATE_PLUGIN_ID"
	RegistryErrorEndpointConflict      RegistryErrorKind = "ENDPOINT_CONFLICT"
	RegistryErrorInvalidMiddleware     RegistryErrorKind = "INVALID_MIDDLEWARE"
)
```

### `RouteMatch`

RouteMatch is one deterministic route result.

```go
type RouteMatch struct {
	Endpoint Endpoint
	Params   map[string]string
}
```

### `ServerAPI2`

ServerAPI2 is a compile-time filtered pair of server-visible endpoints. The
generic constraints make it impossible to add TypedHTTPScopedEndpoint or
TypedNonActionEndpoint accidentally.

```go
type ServerAPI2[First, Second ServerVisibleEndpoint] struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `ServerAPI2`

### `NewServerAPI2`

```go
func NewServerAPI2[First, Second ServerVisibleEndpoint](first First, second Second) ServerAPI2[First, Second]
```

## Methods on `ServerAPI2`

### `First`

```go
func (api ServerAPI2[First, Second]) First() First
```

### `Second`

```go
func (api ServerAPI2[First, Second]) Second() Second
```

### `ServerVisibleEndpoint`

ServerVisibleEndpoint is implemented only by typed declarations that Better
Auth includes in auth.api: pathless virtual endpoints and endpoints whose
metadata scope is server. HTTP-scoped and non-action declarations expose
their runtime Endpoint but intentionally do not implement this interface.

```go
type ServerVisibleEndpoint interface {
	Endpoint() Endpoint
	// contains filtered or unexported methods
}
```

### `TypedEndpoint`

TypedEndpoint retains its method declaration as a static type while wrapping
the exact production Endpoint consumed by Registry and Dispatcher.

```go
type TypedEndpoint[Methods EndpointMethodSpec] struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedEndpoint`

### `NewTypedEndpoint`

NewTypedEndpoint constructs a routable endpoint without erasing its method
marker type. Runtime validation remains centralized in NewRegistry.

```go
func NewTypedEndpoint[Methods EndpointMethodSpec](
	name,
	path string,
	methods Methods,
	handler HandlerFunc,
) TypedEndpoint[Methods]
```

### `NewTypedPathlessEndpoint`

NewTypedPathlessEndpoint is the direct/server-only overload. Pathlessness is
preserved at runtime and the method marker remains part of the static type.

```go
func NewTypedPathlessEndpoint[Methods EndpointMethodSpec](
	name string,
	methods Methods,
	handler HandlerFunc,
) TypedEndpoint[Methods]
```

## Methods on `TypedEndpoint`

### `Endpoint`

Endpoint returns an independent production endpoint declaration suitable
for Options.Endpoints or Plugin.Endpoints.

```go
func (endpoint TypedEndpoint[Methods]) Endpoint() Endpoint
```

### `Methods`

Methods returns an independently mutable method slice. Mutating it cannot
alter the typed declaration or a previously returned Endpoint snapshot.

```go
func (endpoint TypedEndpoint[Methods]) Methods() []string
```

### `TypedHTTPScopedEndpoint`

TypedHTTPScopedEndpoint remains routable but is intentionally omitted from
the server-side typed API.

```go
type TypedHTTPScopedEndpoint[Methods EndpointMethodSpec] struct {
	TypedEndpoint[Methods]
}
```

## Constructors and functions for `TypedHTTPScopedEndpoint`

### `NewTypedHTTPScopedEndpoint`

```go
func NewTypedHTTPScopedEndpoint[Methods EndpointMethodSpec](
	name,
	path string,
	methods Methods,
	handler HandlerFunc,
) TypedHTTPScopedEndpoint[Methods]
```

### `TypedNonActionEndpoint`

TypedNonActionEndpoint remains available to the runtime registry but is
omitted from the typed direct API when isAction is false.

```go
type TypedNonActionEndpoint[Methods EndpointMethodSpec] struct {
	TypedEndpoint[Methods]
}
```

## Constructors and functions for `TypedNonActionEndpoint`

### `NewTypedNonActionEndpoint`

```go
func NewTypedNonActionEndpoint[Methods EndpointMethodSpec](
	name,
	path string,
	methods Methods,
	handler HandlerFunc,
) TypedNonActionEndpoint[Methods]
```

### `TypedServerScopedEndpoint`

TypedServerScopedEndpoint is routable over HTTP and is also retained in the
typed direct/server API because its metadata scope is server.

```go
type TypedServerScopedEndpoint[Methods EndpointMethodSpec] struct {
	TypedEndpoint[Methods]
}
```

## Constructors and functions for `TypedServerScopedEndpoint`

### `NewTypedServerScopedEndpoint`

```go
func NewTypedServerScopedEndpoint[Methods EndpointMethodSpec](
	name,
	path string,
	methods Methods,
	handler HandlerFunc,
) TypedServerScopedEndpoint[Methods]
```

### `TypedVirtualEndpoint`

TypedVirtualEndpoint is a pathless direct/server-only endpoint.

```go
type TypedVirtualEndpoint[Methods EndpointMethodSpec] struct {
	TypedEndpoint[Methods]
}
```

## Constructors and functions for `TypedVirtualEndpoint`

### `NewTypedVirtualEndpoint`

```go
func NewTypedVirtualEndpoint[Methods EndpointMethodSpec](
	name string,
	methods Methods,
	handler HandlerFunc,
) TypedVirtualEndpoint[Methods]
```

