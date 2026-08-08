package engine

import (
	"context"
	"strings"
	"sync"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
)

// HandlerFunc handles one matched endpoint.
type HandlerFunc func(*Context) (contract.Response, error)

// Next invokes the next middleware or the matched endpoint pipeline.
type Next func() (contract.Response, error)

// MiddlewareFunc wraps route matching and endpoint dispatch.
type MiddlewareFunc func(*Context, Next) (contract.Response, error)

// EndpointMiddlewareResult is merged into the request-local endpoint context
// before the next endpoint middleware runs. A non-nil Response short-circuits
// the remaining endpoint middleware and handler after Values are merged.
// This mirrors Better Call's sequential endpoint `use` context composition.
type EndpointMiddlewareResult struct {
	Values   map[string]any
	Response *contract.Response
}

// EndpointMiddlewareFunc prepares request-local context for one endpoint.
// Endpoint middleware run sequentially in declaration order for HTTP, direct,
// and isolated endpoint invocation.
type EndpointMiddlewareFunc func(*Context) (EndpointMiddlewareResult, error)

// ContextInitializer installs runtime-owned request-local dependencies before
// HTTP routing or direct endpoint dispatch.
type ContextInitializer func(*Context) error

// Matcher decides whether a hook applies. Returning an error produces a
// redacted typed internal error while retaining the original cause.
type Matcher func(*Context) (bool, error)

// BeforeHookFunc runs before the endpoint. A non-nil response short-circuits
// the remaining before hooks and the endpoint; after hooks are not run.
type BeforeHookFunc func(*Context) (*contract.Response, error)

// AfterHookFunc runs after the endpoint (including typed endpoint errors). A
// non-nil response replaces the current response while preserving accumulated
// response headers.
type AfterHookFunc func(*Context, contract.Response) (*contract.Response, error)

// BeforeHook is a matched pre-endpoint hook.
type BeforeHook struct {
	Name    string
	Matcher Matcher
	Handler BeforeHookFunc
}

// AfterHook is a matched post-endpoint hook.
type AfterHook struct {
	Name    string
	Matcher Matcher
	Handler AfterHookFunc
}

// Hooks groups hooks while preserving their declared order.
type Hooks struct {
	Before []BeforeHook
	After  []AfterHook
}

// Middleware is a path-scoped router middleware. Path accepts the same dynamic
// parameter syntax as endpoints and a final wildcard such as /oauth/**.
type Middleware struct {
	Name    string
	Path    string
	Handler MiddlewareFunc
}

// OnRequestResult either replaces the request, short-circuits with a response,
// or does neither. Setting both is a configuration/runtime error.
type OnRequestResult struct {
	Request  *contract.Request
	Response *contract.Response
}

// OnRequestFunc runs before route middleware and matching.
type OnRequestFunc func(*Context) (OnRequestResult, error)

// OnResponseFunc runs after the complete HTTP pipeline. Returning nil preserves
// the current response; returning a response replaces it.
type OnResponseFunc func(*Context, contract.Response) (*contract.Response, error)

// Endpoint declares one direct API operation and, unless ServerOnly is true,
// one HTTP route. An empty Methods slice means all methods.
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

	pluginID string
}

// ServerOnlyMetadataKey is the reference implementation's defense-in-depth marker for endpoints
// that are available to trusted direct callers but must never occupy an HTTP
// route, even when a path is accidentally present on the declaration.
const ServerOnlyMetadataKey = "SERVER_ONLY"

// RunEndpointIsolated invokes one endpoint handler using request-local state
// cloned from source, without running registry hooks, path-scoped middleware,
// or response stages. Endpoint-local Use middleware still runs because it is
// part of the endpoint itself. Response headers accumulated by the middleware
// or handler are merged into the returned response, never into source. This is
// the the reference implementation-compatible primitive used when a plugin wraps an original
// core endpoint.
func RunEndpointIsolated(
	source *Context,
	request contract.Request,
	endpoint Endpoint,
) (contract.Response, error) {
	if source == nil {
		err := contract.NewAPIError(
			contract.StatusInternalServerError,
			"ENDPOINT_CONTEXT_REQUIRED",
			"Endpoint context is required",
		)
		return contract.ResponseFromError(err), err
	}
	if endpoint.Handler == nil {
		err := contract.NewAPIError(
			contract.StatusInternalServerError,
			"ENDPOINT_HANDLER_REQUIRED",
			"Endpoint handler is required",
		)
		return contract.ResponseFromError(err), err
	}
	endpoint = cloneEndpoint(endpoint)

	inner := newContext(request, source.IsDirect())
	inner.setRoutePath(endpoint.Path)
	inner.setEndpoint(endpoint, source.Params())
	source.mu.RLock()
	for key, value := range source.values {
		inner.values[key] = value
	}
	source.mu.RUnlock()

	response, err := runEndpointHandler(inner, endpoint)
	if response.IsZero() {
		if err != nil {
			response = contract.ResponseFromError(err)
		} else {
			response = contract.NewResponse(contract.StatusOK, contract.Headers{}, nil)
		}
	}
	if pending := inner.takeResponseHeaders(); pending.Len() > 0 {
		response = response.WithMergedHeaders(pending)
	}
	return response, err
}

// Plugin is the transport-neutral portion of a the reference implementation plugin descriptor.
// Storage schemas, migrations, and adapter extensions live in their respective
// packages; lifecycle and endpoint ordering is defined here.
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

// ErrorDefinition describes a plugin error code without coupling it to a
// particular endpoint status.
type ErrorDefinition struct {
	Code    string
	Message string
}

// DirectInput is the request-local input for direct endpoint dispatch. Direct
// dispatch runs user and plugin before/after hooks, but deliberately skips the
// HTTP-only onRequest, route middleware, and onResponse stages.
type DirectInput struct {
	Request contract.Request
	Params  map[string]string
	Values  map[string]any
}

// Context is request-local dispatch state. A new value is created for every
// dispatch and is never shared between concurrent calls.
type Context struct {
	request contract.Request
	direct  bool

	mu              sync.RWMutex
	routePath       string
	endpoint        Endpoint
	hasEndpoint     bool
	params          map[string]string
	values          map[string]any
	responseHeaders contract.Headers
	returned        contract.Response
	hasReturned     bool
	returnedErr     error
}

type endpointContextKey struct{}

const shouldSkipSessionRefreshKey = "single-auth.should-skip-session-refresh"

func newContext(request contract.Request, direct bool) *Context {
	ctx := &Context{
		direct: direct,
		params: make(map[string]string),
		values: make(map[string]any),
	}
	ctx.request = request.Clone().WithContext(context.WithValue(
		request.Context(), endpointContextKey{}, ctx,
	))
	return ctx
}

// ContextFrom returns the endpoint context associated with a storage or
// background callback context. It returns nil outside an engine dispatch.
func ContextFrom(ctx context.Context) *Context {
	if ctx == nil {
		return nil
	}
	value, _ := ctx.Value(endpointContextKey{}).(*Context)
	return value
}

// GoContext returns the cancellation/deadline context carried by the request.
func (c *Context) GoContext() context.Context {
	if c == nil {
		return context.Background()
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.request.Context()
}

// Request returns an independent request snapshot.
func (c *Context) Request() contract.Request {
	if c == nil {
		return contract.Request{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.request.Clone()
}

// ReplaceRequest installs an independent request snapshot for subsequent
// stages. It is intended for onRequest hooks.
func (c *Context) ReplaceRequest(request contract.Request) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.request = request.Clone().WithContext(context.WithValue(
		request.Context(), endpointContextKey{}, c,
	))
	c.mu.Unlock()
}

// IsDirect reports whether this dispatch was invoked through the direct API.
func (c *Context) IsDirect() bool {
	return c != nil && c.direct
}

// RoutePath returns the actual path after base-path removal.
func (c *Context) RoutePath() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.routePath
}

// Path returns the endpoint route pattern after matching. Before matching it
// returns RoutePath. Pathless direct endpoints use the reference implementation's /:virtual
// diagnostic path.
func (c *Context) Path() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.hasEndpoint {
		if c.endpoint.Path == "" {
			return "/:virtual"
		}
		return c.endpoint.Path
	}
	return c.routePath
}

// Endpoint returns an independent endpoint descriptor when routing has
// completed.
func (c *Context) Endpoint() (Endpoint, bool) {
	if c == nil {
		return Endpoint{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.hasEndpoint {
		return Endpoint{}, false
	}
	return cloneEndpoint(c.endpoint), true
}

// Param returns one decoded dynamic route parameter.
func (c *Context) Param(name string) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, ok := c.params[name]
	return value, ok
}

// Params returns an independent parameter map.
func (c *Context) Params() map[string]string {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneStringMap(c.params)
}

// Set stores request-local data for later stages.
func (c *Context) Set(key string, value any) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	c.values[key] = value
	c.mu.Unlock()
}

// Value retrieves request-local data.
func (c *Context) Value(key string) (any, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, ok := c.values[key]
	return value, ok
}

// SetShouldSkipSessionRefresh stores the reference implementation's request-local session
// refresh guard. Framework integrations use it when the active rendering
// context cannot mutate response cookies.
func SetShouldSkipSessionRefresh(c *Context, skip bool) {
	if c == nil {
		return
	}
	c.Set(shouldSkipSessionRefreshKey, skip)
}

// ShouldSkipSessionRefresh reports the request-local framework refresh guard.
func ShouldSkipSessionRefresh(c *Context) bool {
	if c == nil {
		return false
	}
	value, exists := c.Value(shouldSkipSessionRefreshKey)
	skip, valid := value.(bool)
	return exists && valid && skip
}

// AddResponseHeader appends one response header line.
func (c *Context) AddResponseHeader(name, value string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.responseHeaders.Add(name, value)
	c.mu.Unlock()
}

// SetResponseHeader replaces every accumulated field with name.
func (c *Context) SetResponseHeader(name, value string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.responseHeaders.Set(name, value)
	c.mu.Unlock()
}

// RemoveResponseHeaderValues removes exact header lines that have already
// been accumulated for the current response. It is primarily useful for
// security-sensitive after hooks that must replace a cookie written by the
// endpoint without leaving the earlier value on the wire.
//
// Values added after this call are unaffected, so a hook can remove an old
// Set-Cookie line and then append an expiring replacement for the same cookie.
func (c *Context) RemoveResponseHeaderValues(name string, values ...string) {
	if c == nil || name == "" || len(values) == 0 {
		return
	}
	removed := make(map[string]struct{}, len(values))
	for _, value := range values {
		removed[value] = struct{}{}
	}
	filter := func(headers contract.Headers) contract.Headers {
		filtered := contract.Headers{}
		for _, field := range headers.Fields() {
			if strings.EqualFold(field.Name, name) {
				if _, drop := removed[field.Value]; drop {
					continue
				}
			}
			filtered.Add(field.Name, field.Value)
		}
		return filtered
	}

	c.mu.Lock()
	c.responseHeaders = filter(c.responseHeaders)
	if c.hasReturned {
		c.returned = c.returned.WithHeaders(filter(c.returned.Headers()))
	}
	c.mu.Unlock()
}

// ResponseHeaderValues returns the currently accumulated values for name,
// including values already attached to the endpoint response and values added
// by the active hook. The returned slice is independent from the context.
func (c *Context) ResponseHeaderValues(name string) []string {
	if c == nil || name == "" {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	values := make([]string, 0)
	if c.hasReturned {
		values = append(values, c.returned.Headers().Values(name)...)
	}
	values = append(values, c.responseHeaders.Values(name)...)
	return values
}

// AddSetCookie appends a Set-Cookie line without ever joining it with another.
func (c *Context) AddSetCookie(value string) {
	c.AddResponseHeader("Set-Cookie", value)
}

// Returned returns the current endpoint/after-hook response and error.
func (c *Context) Returned() (contract.Response, error, bool) {
	if c == nil {
		return contract.Response{}, nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.hasReturned {
		return contract.Response{}, nil, false
	}
	return c.returned.Clone(), c.returnedErr, true
}

func (c *Context) setRoutePath(path string) {
	c.mu.Lock()
	c.routePath = path
	c.mu.Unlock()
}

func (c *Context) setEndpoint(endpoint Endpoint, params map[string]string) {
	c.mu.Lock()
	c.endpoint = cloneEndpoint(endpoint)
	c.hasEndpoint = true
	c.params = cloneStringMap(params)
	c.mu.Unlock()
}

func (c *Context) takeResponseHeaders() contract.Headers {
	c.mu.Lock()
	defer c.mu.Unlock()
	headers := c.responseHeaders.Clone()
	c.responseHeaders = contract.Headers{}
	return headers
}

func (c *Context) setReturned(response contract.Response, err error) {
	c.mu.Lock()
	c.returned = response.Clone()
	c.hasReturned = true
	c.returnedErr = err
	c.mu.Unlock()
}

func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return make(map[string]string)
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func cloneAnyMap(source map[string]any) map[string]any {
	if len(source) == 0 {
		return make(map[string]any)
	}
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func cloneEndpoint(endpoint Endpoint) Endpoint {
	clone := endpoint
	clone.Methods = append([]string(nil), endpoint.Methods...)
	clone.Use = append([]EndpointMiddlewareFunc(nil), endpoint.Use...)
	clone.Metadata = cloneAnyMap(endpoint.Metadata)
	return clone
}

func runEndpointHandler(ctx *Context, endpoint Endpoint) (contract.Response, error) {
	for _, middleware := range endpoint.Use {
		if middleware == nil {
			return contract.Response{}, contract.NewAPIError(
				contract.StatusInternalServerError,
				"ENDPOINT_MIDDLEWARE_REQUIRED",
				"Endpoint middleware is required",
			)
		}
		result, err := middleware(ctx)
		if err != nil {
			return contract.Response{}, err
		}
		for key, value := range cloneAnyMap(result.Values) {
			ctx.Set(key, value)
		}
		if result.Response != nil {
			return result.Response.Clone(), nil
		}
	}
	return endpoint.Handler(ctx)
}

func cloneBeforeHooks(hooks []BeforeHook) []BeforeHook {
	return append([]BeforeHook(nil), hooks...)
}

func cloneAfterHooks(hooks []AfterHook) []AfterHook {
	return append([]AfterHook(nil), hooks...)
}

func cloneMiddleware(middleware []Middleware) []Middleware {
	return append([]Middleware(nil), middleware...)
}
