package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/observability/instrumentation"
)

// DispatcherOptions configures the immutable HTTP pipeline around a registry.
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

type compiledMiddleware struct {
	Middleware
	pattern routePattern
	source  string
}

type compiledBeforeHook struct {
	hook   BeforeHook
	source string
}

type compiledAfterHook struct {
	hook   AfterHook
	source string
}

type namedOnRequest struct {
	name       string
	source     string
	instrument bool
	handler    OnRequestFunc
}

type namedOnResponse struct {
	name       string
	source     string
	instrument bool
	handler    OnResponseFunc
}

// Dispatcher is an immutable, goroutine-safe dispatch pipeline.
type Dispatcher struct {
	registry            *Registry
	basePath            string
	disabled            map[string]struct{}
	skipTrailingSlashes bool
	initializeContext   ContextInitializer

	middleware  []compiledMiddleware
	beforeHooks []compiledBeforeHook
	afterHooks  []compiledAfterHook
	onRequest   []namedOnRequest
	onResponse  []namedOnResponse
}

// NewDispatcher validates and snapshots all pipeline declarations. Subsequent
// mutation of the caller's slices, plugin descriptors, or endpoint method
// slices cannot affect the dispatcher.
func NewDispatcher(registry *Registry, options DispatcherOptions) (*Dispatcher, error) {
	if registry == nil {
		return nil, &RegistryError{
			Kind:    RegistryErrorInvalidEndpoint,
			Message: "registry must not be nil",
		}
	}
	basePath, err := normalizeBasePath(options.BasePath)
	if err != nil {
		return nil, &RegistryError{
			Kind:    RegistryErrorInvalidEndpoint,
			Message: "invalid base path",
			Cause:   err,
		}
	}
	dispatcher := &Dispatcher{
		registry:            registry,
		basePath:            basePath,
		disabled:            make(map[string]struct{}, len(options.DisabledPaths)),
		skipTrailingSlashes: options.SkipTrailingSlashes,
		initializeContext:   options.InitializeContext,
	}
	for _, disabledPath := range options.DisabledPaths {
		if _, err := compileRoutePattern(disabledPath); err != nil {
			return nil, &RegistryError{
				Kind:    RegistryErrorInvalidEndpoint,
				Message: "invalid disabled path " + disabledPath,
				Cause:   err,
			}
		}
		dispatcher.disabled[disabledPath] = struct{}{}
	}

	if err := dispatcher.addMiddleware(options.Middleware, "user"); err != nil {
		return nil, err
	}
	if err := validateHooks(options.Hooks, "user"); err != nil {
		return nil, err
	}
	for _, hook := range cloneBeforeHooks(options.Hooks.Before) {
		dispatcher.beforeHooks = append(dispatcher.beforeHooks, compiledBeforeHook{
			hook: hook, source: "user",
		})
	}
	for _, hook := range cloneAfterHooks(options.Hooks.After) {
		dispatcher.afterHooks = append(dispatcher.afterHooks, compiledAfterHook{
			hook: hook, source: "user",
		})
	}
	for _, handler := range options.OnRequest {
		if handler == nil {
			return nil, &RegistryError{
				Kind:    RegistryErrorInvalidMiddleware,
				Message: "user onRequest handler must not be nil",
			}
		}
		dispatcher.onRequest = append(dispatcher.onRequest, namedOnRequest{
			name: "user", source: "user", handler: handler,
		})
	}

	for _, plugin := range registry.plugins {
		if err := dispatcher.addMiddleware(plugin.Middleware, "plugin:"+plugin.ID); err != nil {
			return nil, err
		}
		if err := validateHooks(plugin.Hooks, "plugin:"+plugin.ID); err != nil {
			return nil, err
		}
		for _, hook := range plugin.Hooks.Before {
			if hook.Name == "" {
				hook.Name = "plugin:" + plugin.ID
			}
			dispatcher.beforeHooks = append(dispatcher.beforeHooks, compiledBeforeHook{
				hook: hook, source: "plugin:" + plugin.ID,
			})
		}
		for _, hook := range plugin.Hooks.After {
			if hook.Name == "" {
				hook.Name = "plugin:" + plugin.ID
			}
			dispatcher.afterHooks = append(dispatcher.afterHooks, compiledAfterHook{
				hook: hook, source: "plugin:" + plugin.ID,
			})
		}
		if plugin.OnRequest != nil {
			dispatcher.onRequest = append(dispatcher.onRequest, namedOnRequest{
				name: plugin.ID, source: "plugin:" + plugin.ID, instrument: true,
				handler: plugin.OnRequest,
			})
		}
		if plugin.OnResponse != nil {
			dispatcher.onResponse = append(dispatcher.onResponse, namedOnResponse{
				name: plugin.ID, source: "plugin:" + plugin.ID, instrument: true,
				handler: plugin.OnResponse,
			})
		}
	}

	return dispatcher, nil
}

func normalizeBasePath(basePath string) (string, error) {
	if basePath == "" || basePath == "/" {
		return "", nil
	}
	basePath = strings.TrimRight(basePath, "/")
	pattern, err := compileRoutePattern(basePath)
	if err != nil {
		return "", err
	}
	for _, segment := range pattern.segments {
		if segment.kind != segmentStatic {
			return "", fmt.Errorf("base path must not contain parameters or wildcards")
		}
	}
	return basePath, nil
}

func (d *Dispatcher) addMiddleware(middleware []Middleware, source string) error {
	for _, declaration := range middleware {
		if declaration.Handler == nil {
			return &RegistryError{
				Kind:       RegistryErrorInvalidMiddleware,
				Middleware: declaration.Name,
				Message:    source + " middleware handler must not be nil",
			}
		}
		pattern, err := compileRoutePattern(declaration.Path)
		if err != nil {
			return &RegistryError{
				Kind:       RegistryErrorInvalidMiddleware,
				Middleware: declaration.Name,
				Message:    source + " middleware path is invalid",
				Cause:      err,
			}
		}
		clone := declaration
		if clone.Name == "" {
			clone.Name = source
		}
		d.middleware = append(d.middleware, compiledMiddleware{
			Middleware: clone,
			pattern:    pattern,
			source:     source,
		})
	}
	return nil
}

func validateHooks(hooks Hooks, source string) error {
	for _, hook := range hooks.Before {
		if hook.Handler == nil {
			return &RegistryError{
				Kind:     RegistryErrorInvalidEndpoint,
				Endpoint: hook.Name,
				Message:  source + " before hook handler must not be nil",
			}
		}
	}
	for _, hook := range hooks.After {
		if hook.Handler == nil {
			return &RegistryError{
				Kind:     RegistryErrorInvalidEndpoint,
				Endpoint: hook.Name,
				Message:  source + " after hook handler must not be nil",
			}
		}
	}
	return nil
}

// Registry returns the dispatcher's immutable endpoint registry.
func (d *Dispatcher) Registry() *Registry {
	if d == nil {
		return nil
	}
	return d.registry
}

// Dispatch executes the HTTP pipeline. Response is always suitable for a
// transport to write, including when err is non-nil. The error is returned as
// well so hosts can inspect typed API errors and log unknown failures.
func (d *Dispatcher) Dispatch(request contract.Request) (contract.Response, error) {
	if d == nil || d.registry == nil {
		err := contract.NewAPIError(
			contract.StatusInternalServerError,
			"DISPATCHER_NOT_INITIALIZED",
			"Dispatcher is not initialized",
		)
		return contract.ResponseFromError(err), err
	}
	ctx := newContext(request, false)
	if d.initializeContext != nil {
		if err := d.initializeContext(ctx); err != nil {
			return d.finishHTTP(ctx, contract.Response{}, err)
		}
	}
	routePath, outsideBasePath, pathErr := d.onRequestRoutePath(request.RawPath())
	if pathErr != nil && !outsideBasePath {
		return d.finishHTTP(ctx, contract.Response{}, pathErr)
	}
	ctx.setRoutePath(routePath)
	if _, disabled := d.disabled[routePath]; disabled && !outsideBasePath {
		err := contract.NewAPIError(
			contract.StatusNotFound,
			"NOT_FOUND",
			"Not Found",
		)
		return d.finishHTTP(ctx, contract.Response{}, err)
	}

	for _, hook := range d.onRequest {
		if err := contextError(ctx); err != nil {
			return d.finishHTTP(ctx, contract.Response{}, err)
		}
		var result OnRequestResult
		var hookErr error
		if hook.instrument {
			result, hookErr = withEngineSpan(
				ctx,
				"onRequest "+hook.name,
				map[string]any{
					instrumentation.AttrHookType: "onRequest",
					instrumentation.AttrContext:  hook.source,
				},
				func() (OnRequestResult, error) { return hook.handler(ctx) },
			)
		} else {
			result, hookErr = hook.handler(ctx)
		}
		if hookErr != nil {
			return d.finishHTTP(ctx, contract.Response{}, hookErr)
		}
		if result.Request != nil && result.Response != nil {
			err := contract.NewAPIError(
				contract.StatusInternalServerError,
				"INVALID_ON_REQUEST_RESULT",
				"onRequest must return either a request or a response",
			).WithCause(errors.New(hook.name + " returned both request and response"))
			return d.finishHTTP(ctx, contract.Response{}, err)
		}
		if result.Request != nil {
			ctx.ReplaceRequest(*result.Request)
			routePath, outsideBasePath, pathErr = d.onRequestRoutePath(result.Request.RawPath())
			if pathErr != nil && !outsideBasePath {
				return d.finishHTTP(ctx, contract.Response{}, pathErr)
			}
			ctx.setRoutePath(routePath)
		}
		if result.Response != nil {
			return d.finishHTTP(ctx, result.Response.Clone(), nil)
		}
	}
	if outsideBasePath {
		return d.finishHTTP(ctx, contract.Response{}, pathErr)
	}

	response, dispatchErr := d.runMiddleware(ctx)
	return d.finishHTTP(ctx, response, dispatchErr)
}

// onRequestRoutePath lets plugin onRequest hooks claim standards-defined
// aliases outside BasePath, such as RFC 8414 path-insertion discovery URLs.
// Requests that no hook claims retain the original base-path 404 and never
// enter endpoint middleware or route matching.
func (d *Dispatcher) onRequestRoutePath(rawPath string) (string, bool, error) {
	routePath, err := d.relativePath(rawPath)
	if err == nil {
		return routePath, false, nil
	}
	if queryIndex := strings.IndexByte(rawPath, '?'); queryIndex >= 0 {
		rawPath = rawPath[:queryIndex]
	}
	if rawPath == "" || rawPath[0] != '/' {
		return "", false, err
	}
	return rawPath, true, err
}

// Invoke dispatches an endpoint by direct API name. Server-only endpoints are
// intentionally available here and impossible to reach through Dispatch.
func (d *Dispatcher) Invoke(name string, input DirectInput) (contract.Response, error) {
	if d == nil || d.registry == nil {
		err := contract.NewAPIError(
			contract.StatusInternalServerError,
			"DISPATCHER_NOT_INITIALIZED",
			"Dispatcher is not initialized",
		)
		return contract.ResponseFromError(err), err
	}
	endpoint, ok := d.registry.Endpoint(name)
	if !ok {
		err := contract.NewAPIError(
			contract.StatusNotFound,
			"ENDPOINT_NOT_FOUND",
			"Endpoint not found",
		)
		return contract.ResponseFromError(err), err
	}
	request := input.Request.Clone()
	if request.Method() == "" {
		method := "POST"
		if len(endpoint.Methods) > 0 && endpoint.Methods[0] != anyMethod {
			method = endpoint.Methods[0]
		}
		request = request.WithMethod(method)
	}
	ctx := newContext(request, true)
	ctx.setRoutePath(endpoint.Path)
	ctx.setEndpoint(endpoint, input.Params)
	for key, value := range cloneAnyMap(input.Values) {
		ctx.Set(key, value)
	}
	if d.initializeContext != nil {
		if err := d.initializeContext(ctx); err != nil {
			return contract.ResponseFromError(err), err
		}
	}
	return d.runEndpoint(ctx)
}

func (d *Dispatcher) relativePath(rawPath string) (string, error) {
	if queryIndex := strings.IndexByte(rawPath, '?'); queryIndex >= 0 {
		rawPath = rawPath[:queryIndex]
	}
	if rawPath == "" || rawPath[0] != '/' {
		return "", contract.NewAPIError(
			contract.StatusBadRequest,
			"INVALID_PATH",
			"Invalid request path",
		)
	}
	if d.basePath == "" {
		return rawPath, nil
	}
	if strings.HasPrefix(rawPath, d.basePath+"/") {
		return strings.TrimPrefix(rawPath, d.basePath), nil
	}
	return "", contract.NewAPIError(
		contract.StatusNotFound,
		"NOT_FOUND",
		"Not Found",
	)
}

func (d *Dispatcher) runMiddleware(ctx *Context) (contract.Response, error) {
	segments, err := decodeRequestPath(ctx.RoutePath())
	if err != nil {
		apiError := contract.NewAPIError(
			contract.StatusBadRequest,
			"INVALID_PATH",
			"Invalid request path",
		).WithCause(err)
		return contract.ResponseFromError(apiError), apiError
	}
	matching := make([]compiledMiddleware, 0, len(d.middleware))
	for _, middleware := range d.middleware {
		if _, matches := middleware.pattern.matchRequest(segments, d.skipTrailingSlashes); matches {
			matching = append(matching, middleware)
		}
	}

	var next Next
	next = func() (contract.Response, error) {
		request := ctx.Request()
		match, matchErr := d.registry.match(
			request.Method(),
			ctx.RoutePath(),
			d.skipTrailingSlashes,
		)
		if matchErr != nil {
			return contract.ResponseFromError(matchErr), matchErr
		}
		ctx.setEndpoint(match.Endpoint, match.Params)
		return d.runEndpoint(ctx)
	}
	for index := len(matching) - 1; index >= 0; index-- {
		middleware := matching[index]
		following := next
		next = func() (contract.Response, error) {
			if err := contextError(ctx); err != nil {
				return contract.ResponseFromError(err), err
			}
			if !strings.HasPrefix(middleware.source, "plugin:") {
				return middleware.Handler(ctx, following)
			}
			pluginID := strings.TrimPrefix(middleware.source, "plugin:")
			return runInstrumentedMiddleware(
				ctx,
				fmt.Sprintf("middleware %s %s", middleware.Path, pluginID),
				map[string]any{
					instrumentation.AttrHookType:  "middleware",
					instrumentation.AttrHTTPRoute: middleware.Path,
					instrumentation.AttrContext:   middleware.source,
				},
				middleware.Handler,
				following,
			)
		}
	}
	return next()
}

type endpointRunResult struct {
	response    contract.Response
	dispatchErr error
	spanErr     error
}

func (d *Dispatcher) runEndpoint(ctx *Context) (contract.Response, error) {
	endpoint, ok := ctx.Endpoint()
	if !ok {
		err := contract.NewAPIError(
			contract.StatusInternalServerError,
			"ENDPOINT_NOT_MATCHED",
			"Endpoint was not matched",
		)
		return contract.ResponseFromError(err), err
	}

	route := endpointSpanRoute(endpoint)
	operationID := endpointSpanOperationID(endpoint)
	method := endpointSpanMethod(ctx, endpoint)
	result, _ := withEngineSpan(
		ctx,
		method+" "+route,
		map[string]any{
			instrumentation.AttrHTTPRoute:   route,
			instrumentation.AttrOperationID: operationID,
		},
		func() (endpointRunResult, error) {
			result := d.runEndpointPipeline(ctx, endpoint, route, operationID)
			return result, result.spanErr
		},
	)
	return result.response, result.dispatchErr
}

func (d *Dispatcher) runEndpointPipeline(
	ctx *Context,
	endpoint Endpoint,
	route,
	operationID string,
) endpointRunResult {
	for _, registered := range d.beforeHooks {
		hook := registered.hook
		matched, err := matchHook(hook.Matcher, ctx, hook.Name)
		if err != nil {
			response := combinePendingBefore(ctx, contract.ResponseFromError(err))
			return endpointRunResult{response: response, dispatchErr: err, spanErr: err}
		}
		if !matched {
			continue
		}
		if err := contextError(ctx); err != nil {
			response := combinePendingBefore(ctx, contract.ResponseFromError(err))
			return endpointRunResult{response: response, dispatchErr: err, spanErr: err}
		}
		response, hookErr := withEngineSpan(
			ctx,
			fmt.Sprintf("hook before %s %s", route, registered.source),
			map[string]any{
				instrumentation.AttrHookType:    "before",
				instrumentation.AttrHTTPRoute:   route,
				instrumentation.AttrContext:     registered.source,
				instrumentation.AttrOperationID: operationID,
			},
			func() (*contract.Response, error) { return hook.Handler(ctx) },
		)
		if hookErr != nil {
			wire := combinePendingBefore(ctx, contract.ResponseFromError(hookErr))
			return endpointRunResult{response: wire, dispatchErr: hookErr, spanErr: hookErr}
		}
		if response != nil {
			return endpointRunResult{response: combinePendingBefore(ctx, response.Clone())}
		}
	}

	if err := contextError(ctx); err != nil {
		response := combinePendingBefore(ctx, contract.ResponseFromError(err))
		return endpointRunResult{response: response, dispatchErr: err, spanErr: err}
	}
	response, endpointErr := withEngineSpan(
		ctx,
		"handler "+route,
		map[string]any{
			instrumentation.AttrHTTPRoute:   route,
			instrumentation.AttrOperationID: operationID,
		},
		func() (contract.Response, error) { return runEndpointHandler(ctx, endpoint) },
	)
	if endpointErr != nil {
		response = contract.ResponseFromError(endpointErr)
	} else if response.IsZero() {
		response = contract.NewResponse(contract.StatusOK, contract.Headers{}, nil)
	}
	response = combinePendingBefore(ctx, response)
	ctx.setReturned(response, endpointErr)
	if endpointErr != nil {
		if _, typed := contract.AsAPIError(endpointErr); !typed {
			// the reference implementation only converts APIError into an after-hook value. Unknown
			// handler failures escape directly and therefore skip after hooks.
			return endpointRunResult{
				response: response, dispatchErr: endpointErr, spanErr: endpointErr,
			}
		}
	}

	currentErr := endpointErr
	var pipelineFailure error
	for _, registered := range d.afterHooks {
		hook := registered.hook
		matched, matcherErr := matchHook(hook.Matcher, ctx, hook.Name)
		if matcherErr != nil {
			response = replaceResponsePreservingHeaders(
				response,
				ctx.takeResponseHeaders(),
				contract.ResponseFromError(matcherErr),
			)
			currentErr = matcherErr
			pipelineFailure = matcherErr
			ctx.setReturned(response, currentErr)
			break
		}
		if !matched {
			continue
		}
		if err := contextError(ctx); err != nil {
			response = replaceResponsePreservingHeaders(
				response,
				ctx.takeResponseHeaders(),
				contract.ResponseFromError(err),
			)
			currentErr = err
			pipelineFailure = err
			ctx.setReturned(response, currentErr)
			break
		}
		replacement, hookErr := withEngineSpan(
			ctx,
			fmt.Sprintf("hook after %s %s", route, registered.source),
			map[string]any{
				instrumentation.AttrHookType:    "after",
				instrumentation.AttrHTTPRoute:   route,
				instrumentation.AttrContext:     registered.source,
				instrumentation.AttrOperationID: operationID,
			},
			func() (*contract.Response, error) {
				return hook.Handler(ctx, response.Clone())
			},
		)
		// After hooks may deliberately scrub header values that were accumulated
		// by the endpoint (for example, a credential session cookie that must not
		// survive a pending 2FA challenge). Preserve the current context snapshot,
		// which reflects those removals, rather than the pre-hook local copy.
		preserved := response
		if returned, _, ok := ctx.Returned(); ok {
			preserved = returned
		}
		pending := ctx.takeResponseHeaders()
		switch {
		case hookErr != nil:
			response = replaceResponsePreservingHeaders(
				preserved,
				pending,
				contract.ResponseFromError(hookErr),
			)
			currentErr = hookErr
			// the reference implementation continues after a typed API error so a later after hook
			// may deliberately replace it. Unknown errors abort the pipeline.
			if _, typed := contract.AsAPIError(hookErr); !typed {
				ctx.setReturned(response, currentErr)
				return endpointRunResult{
					response: response, dispatchErr: currentErr, spanErr: currentErr,
				}
			}
		case replacement != nil:
			response = replaceResponsePreservingHeaders(preserved, pending, replacement.Clone())
			currentErr = nil
		default:
			response = preserved.WithMergedHeaders(pending)
		}
		ctx.setReturned(response, currentErr)
	}

	spanErr := pipelineFailure
	if spanErr == nil && ctx.IsDirect() {
		spanErr = currentErr
	}
	return endpointRunResult{
		response: response, dispatchErr: currentErr, spanErr: spanErr,
	}
}

func endpointSpanRoute(endpoint Endpoint) string {
	if endpoint.Path == "" {
		return "/:virtual"
	}
	return endpoint.Path
}

func endpointSpanOperationID(endpoint Endpoint) string {
	if endpoint.OperationID != "" {
		return endpoint.OperationID
	}
	if endpoint.Name != "" {
		return endpoint.Name
	}
	return endpointSpanRoute(endpoint)
}

func endpointSpanMethod(ctx *Context, endpoint Endpoint) string {
	if method := ctx.Request().Method(); method != "" {
		return method
	}
	if len(endpoint.Methods) > 0 && endpoint.Methods[0] != anyMethod {
		return endpoint.Methods[0]
	}
	return "?"
}

func withEngineSpan[T any](
	ctx *Context,
	name string,
	attributes map[string]any,
	callback func() (T, error),
) (T, error) {
	parentContext := ctx.GoContext()
	return instrumentation.WithSpanContextErr(
		parentContext,
		name,
		attributes,
		func(spanContext context.Context) (T, error) {
			ctx.ReplaceRequest(ctx.Request().WithContext(spanContext))
			defer func() {
				ctx.ReplaceRequest(ctx.Request().WithContext(parentContext))
			}()
			return callback()
		},
	)
}

func runInstrumentedMiddleware(
	ctx *Context,
	name string,
	attributes map[string]any,
	handler MiddlewareFunc,
	following Next,
) (response contract.Response, err error) {
	parentContext := ctx.GoContext()
	spanContext, span := instrumentation.StartSpanContext(
		parentContext,
		name,
		attributes,
	)
	ctx.ReplaceRequest(ctx.Request().WithContext(spanContext))

	defer func() {
		ctx.ReplaceRequest(ctx.Request().WithContext(parentContext))
		if failure := recover(); failure != nil {
			span.EndWithFailure(failure)
			panic(failure)
		}
		if err != nil {
			span.EndWithFailure(err)
			return
		}
		span.End()
	}()

	nextAfterMiddleware := func() (contract.Response, error) {
		// better-call runs matched router middleware to completion before the
		// independently instrumented endpoint handler. End and detach the
		// middleware span at the continuation boundary while preserving Go's
		// wrapping MiddlewareFunc contract and the exact downstream result.
		span.End()
		ctx.ReplaceRequest(ctx.Request().WithContext(parentContext))
		return following()
	}
	return handler(ctx, nextAfterMiddleware)
}

func matchHook(matcher Matcher, ctx *Context, name string) (bool, error) {
	if matcher == nil {
		return true, nil
	}
	matched, err := matcher(ctx)
	if err == nil {
		return matched, nil
	}
	if name == "" {
		name = "unknown"
	}
	return false, contract.NewAPIError(
		contract.StatusInternalServerError,
		"HOOK_MATCHER_ERROR",
		"An error occurred during hook matcher execution. Check the logs for more details.",
	).WithCause(fmt.Errorf("%s hook matcher: %w", name, err))
}

func contextError(ctx *Context) error {
	if err := ctx.GoContext().Err(); err != nil {
		return contract.NewAPIError(
			contract.StatusInternalServerError,
			"REQUEST_CANCELLED",
			"Request cancelled",
		).WithCause(err)
	}
	return nil
}

func combinePendingBefore(ctx *Context, response contract.Response) contract.Response {
	headers := ctx.takeResponseHeaders()
	headers.MergeResponse(response.Headers())
	return response.WithHeaders(headers)
}

func replaceResponsePreservingHeaders(
	current contract.Response,
	pending contract.Headers,
	replacement contract.Response,
) contract.Response {
	headers := current.Headers()
	headers.MergeResponse(pending)
	headers.MergeResponse(replacement.Headers())
	return replacement.WithHeaders(headers)
}

func (d *Dispatcher) finishHTTP(
	ctx *Context,
	response contract.Response,
	dispatchErr error,
) (contract.Response, error) {
	if response.IsZero() {
		if dispatchErr != nil {
			response = combinePendingBefore(ctx, contract.ResponseFromError(dispatchErr))
		} else {
			response = contract.NewResponse(contract.StatusOK, contract.Headers{}, nil)
		}
	}
	if pending := ctx.takeResponseHeaders(); pending.Len() > 0 {
		response = response.WithMergedHeaders(pending)
	}
	for _, hook := range d.onResponse {
		if err := contextError(ctx); err != nil {
			return replaceResponsePreservingHeaders(
				response,
				ctx.takeResponseHeaders(),
				contract.ResponseFromError(err),
			), err
		}
		var replacement *contract.Response
		var hookErr error
		if hook.instrument {
			replacement, hookErr = withEngineSpan(
				ctx,
				"onResponse "+hook.name,
				map[string]any{
					instrumentation.AttrHookType:               "onResponse",
					instrumentation.AttrContext:                hook.source,
					instrumentation.AttrHTTPResponseStatusCode: response.Status(),
				},
				func() (*contract.Response, error) {
					return hook.handler(ctx, response.Clone())
				},
			)
		} else {
			replacement, hookErr = hook.handler(ctx, response.Clone())
		}
		if hookErr != nil {
			wire := replaceResponsePreservingHeaders(
				response,
				ctx.takeResponseHeaders(),
				contract.ResponseFromError(hookErr),
			)
			return wire, hookErr
		}
		if replacement != nil {
			response = replacement.Clone()
		}
		if pending := ctx.takeResponseHeaders(); pending.Len() > 0 {
			response = response.WithMergedHeaders(pending)
		}
	}
	return response, dispatchErr
}
