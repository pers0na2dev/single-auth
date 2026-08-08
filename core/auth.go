package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sync"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	secondaryruntime "github.com/pers0na2dev/single-auth/internal/secondary"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

// Auth is an immutable upstream implementation-compatible runtime. It is safe for
// concurrent HTTP and direct API calls.
type Auth struct {
	options       runtimeOptions
	adapter       storage.Adapter
	registry      *engine.Registry
	dispatcher    *engine.Dispatcher
	httpHandler   http.Handler
	rateLimiter   *ratelimit.Limiter
	logger        *logger.Logger
	secondary     *secondaryruntime.Runtime
	dbHooks       *databaseHookRegistry
	passwordHash  *passwordHashChain
	contextMeta   authContextMetadata
	runMigrations func(context.Context) error

	verificationLocks [64]sync.Mutex
	accountLocks      [64]sync.Mutex
}

// New validates options, snapshots configuration, and constructs the shared
// dispatcher used by every transport and the direct API.
func New(options Options) (*Auth, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	for _, plugin := range normalized.Plugins {
		mergePluginTrustedOrigins(&normalized, plugin)
	}

	schema := storage.CoreSchema()
	// upstream implementation only materializes rateLimit when database-backed rate
	// limiting is selected.
	delete(schema.Models, "rateLimit")
	if rateLimitStorageMode(normalized) == "database" {
		schema, err = schema.Merge(configuredRateLimitSchema(normalized.RateLimit))
		if err != nil {
			return nil, err
		}
	}
	if len(normalized.Schema.Models) != 0 {
		schema, err = schema.Merge(normalized.Schema)
		if err != nil {
			return nil, err
		}
	}
	for _, plugin := range normalized.Plugins {
		if len(plugin.Schema.Models) == 0 {
			continue
		}
		schema, err = schema.Merge(plugin.Schema)
		if err != nil {
			return nil, err
		}
	}
	for index, factory := range normalized.PluginFactories {
		if nilPluginFactory(factory) {
			return nil, errors.New("single-auth: plugin factory must not be nil")
		}
		if factory.PluginID() == "" {
			return nil, errors.New("single-auth: plugin factory ID must not be empty")
		}
		factorySchema, schemaErr := factory.Schema()
		if schemaErr != nil {
			return nil, fmt.Errorf("single-auth: plugin factory schema at index %d: %w", index, schemaErr)
		}
		if len(factorySchema.Models) == 0 {
			continue
		}
		schema, err = schema.Merge(factorySchema)
		if err != nil {
			return nil, fmt.Errorf("single-auth: plugin factory schema at index %d: %w", index, err)
		}
	}
	if err := schema.Validate(); err != nil {
		return nil, err
	}
	normalized.Schema = schema.Clone()

	adapter := normalized.Database
	contextMeta := authContextMetadataForAdapter(adapter)
	runMigrations := unsupportedFullMigration
	if initializer := normalized.databaseInitializer; initializer != nil {
		if adapter != nil {
			return nil, errors.New("single-auth: database adapter and raw database are mutually exclusive")
		}
		initialized, initializeErr := initializer(normalized, schema)
		if initializeErr != nil {
			return nil, initializeErr
		}
		if initialized.adapter == nil {
			return nil, errors.New("single-auth: raw database initializer returned a nil adapter")
		}
		adapter = initialized.adapter
		contextMeta = initialized.metadata
		if initialized.runMigrations != nil {
			runMigrations = initialized.runMigrations
		}
		normalized.Database = adapter
		normalized.databaseInitializer = nil
	}
	if adapter == nil {
		adapter, err = memory.New(
			memory.WithSchema(schema),
			memory.WithClock(normalized.Clock),
			memory.WithIDGenerator(func(model string) (any, error) {
				value, generated, generateErr := generateIdentifier(normalized, model, 32)
				if generateErr != nil {
					return nil, generateErr
				}
				if !generated {
					return nil, errors.New("single-auth: memory adapter requires generated IDs")
				}
				return value, nil
			}),
		)
		if err != nil {
			return nil, err
		}
	}
	if ensurer, ok := adapter.(storage.SchemaEnsurer); ok {
		runMigrations = ensurer.EnsureSchema
	}
	if contextMeta.adapterID == "" {
		contextMeta = authContextMetadataForAdapter(adapter)
	}

	dbHooks := newDatabaseHookRegistry()
	adapter = newHookedAdapter(adapter, dbHooks)
	secondary := secondaryruntime.New(
		normalized.SecondaryStorage,
		normalized.SecondaryValueStorage,
		normalized.logger,
	)
	auth := &Auth{
		options: normalized, adapter: adapter, logger: normalized.logger, dbHooks: dbHooks,
		secondary:     secondary,
		passwordHash:  newPasswordHashChain(normalized.EmailAndPassword.Password.Hash),
		contextMeta:   contextMeta,
		runMigrations: runMigrations,
	}
	boundPlugins := append([]engine.Plugin(nil), normalized.Plugins...)
	for _, factory := range normalized.PluginFactories {
		plugin, buildErr := factory.Build(auth.pluginHost(&normalized, factory.PluginID()))
		if buildErr != nil {
			return nil, fmt.Errorf("single-auth: initialize plugin %s: %w", factory.PluginID(), buildErr)
		}
		if plugin.ID == "" {
			plugin.ID = factory.PluginID()
		}
		if plugin.ID != factory.PluginID() {
			return nil, errors.New("single-auth: plugin factory " + factory.PluginID() + " built mismatched plugin " + plugin.ID)
		}
		mergePluginTrustedOrigins(&normalized, plugin)
		boundPlugins = append(boundPlugins, plugin)
		normalized.Plugins = boundPlugins
		auth.options = normalized
	}
	normalized.Plugins = boundPlugins
	auth.options = normalized
	auth.passwordHash.freeze()
	if err := dbHooks.add("user", normalized.DatabaseHooks); err != nil {
		return nil, err
	}
	dbHooks.freeze()
	limiter, err := buildRateLimiter(normalized, adapter, secondary)
	if err != nil {
		return nil, err
	}
	auth.rateLimiter = limiter
	endpoints := append(auth.coreEndpoints(), normalized.Endpoints...)
	registry, err := engine.NewRegistry(endpoints, normalized.Plugins...)
	if err != nil {
		return nil, err
	}
	middleware := make([]engine.Middleware, 0, len(normalized.Middleware)+1)
	middleware = append(middleware, auth.securityMiddleware())
	middleware = append(middleware, normalized.Middleware...)
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{
		BasePath:            normalized.BasePath,
		DisabledPaths:       normalized.DisabledPaths,
		Middleware:          middleware,
		Hooks:               normalized.Hooks,
		OnRequest:           []engine.OnRequestFunc{auth.rateLimitOnRequest},
		InitializeContext:   auth.initializeEndpointContext,
		SkipTrailingSlashes: normalized.Advanced.SkipTrailingSlashes,
	})
	if err != nil {
		return nil, err
	}
	auth.registry = registry
	auth.dispatcher = dispatcher
	auth.httpHandler = nethttptransport.NewHandler(dispatcher)
	return auth, nil
}

func nilPluginFactory(factory PluginFactory) bool {
	if factory == nil {
		return true
	}
	value := reflect.ValueOf(factory)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// MustNew constructs an Auth or panics. It is intended for static application
// setup where configuration errors cannot be recovered.
func MustNew(options Options) *Auth {
	auth, err := New(options)
	if err != nil {
		panic(err)
	}
	return auth
}

// Dispatch runs the transport-neutral HTTP pipeline.
func (a *Auth) Dispatch(request contract.Request) (contract.Response, error) {
	if a == nil || a.dispatcher == nil {
		err := contract.NewAPIError(
			contract.StatusInternalServerError,
			"AUTH_NOT_INITIALIZED",
			"Auth is not initialized",
		)
		return contract.ResponseFromError(err), err
	}
	return a.dispatcher.Dispatch(request)
}

// Invoke calls an endpoint by its direct API name. Server-only endpoints are
// available here but cannot be reached through HTTP routing.
func (a *Auth) Invoke(name string, input engine.DirectInput) (contract.Response, error) {
	if a == nil || a.dispatcher == nil {
		err := contract.NewAPIError(
			contract.StatusInternalServerError,
			"AUTH_NOT_INITIALIZED",
			"Auth is not initialized",
		)
		return contract.ResponseFromError(err), err
	}
	if a.options.DynamicBaseURL != nil {
		if _, err := a.resolveBaseURLForRequest(input.Request); err != nil {
			// A direct API caller has no HTTP request from which the dynamic
			// base URL can be recovered. upstream implementation surfaces this configuration
			// error verbatim so callers know to forward request headers or add a
			// fallback; returning the generic wire-safe message here makes the
			// failure impossible to act on.
			apiErr := contract.NewAPIError(
				contract.StatusInternalServerError,
				"INTERNAL_SERVER_ERROR",
				err.Error(),
			).WithCause(err)
			return contract.ResponseFromError(apiErr), apiErr
		}
	}
	return a.dispatcher.Invoke(name, input)
}

// ResolveBaseURL returns the request-scoped public auth URL, including the
// configured base path. It is useful to integrations that need the same
// dynamic allowed-host and trusted-proxy semantics as core OAuth routes.
func (a *Auth) ResolveBaseURL(request contract.Request) (string, error) {
	if a == nil {
		return "", errors.New("single-auth: auth is not initialized")
	}
	return a.resolveBaseURLForRequest(request)
}

// Registry returns the immutable endpoint registry.
func (a *Auth) Registry() *engine.Registry {
	if a == nil {
		return nil
	}
	return a.registry
}

// ErrorCodes returns the merged plugin error catalog. The map is an
// independent snapshot and every definition includes its effective code.
func (a *Auth) ErrorCodes() map[string]engine.ErrorDefinition {
	if a == nil || a.registry == nil {
		return nil
	}
	return a.registry.ErrorCodes()
}

// Dispatcher returns the immutable transport-neutral dispatcher. It is the
// input accepted by transport/fasthttp and transport/fiber.
func (a *Auth) Dispatcher() *engine.Dispatcher {
	if a == nil {
		return nil
	}
	return a.dispatcher
}

// Adapter returns the configured persistence adapter.
func (a *Auth) Adapter() storage.Adapter {
	if a == nil {
		return nil
	}
	return a.adapter
}

// RateLimiter returns the immutable limiter used by the HTTP request path.
// Direct API calls intentionally bypass it, matching upstream implementation.
func (a *Auth) RateLimiter() *ratelimit.Limiter {
	if a == nil {
		return nil
	}
	return a.rateLimiter
}

// Logger returns the configured immutable upstream implementation-compatible logger.
func (a *Auth) Logger() *logger.Logger {
	if a == nil {
		return nil
	}
	return a.logger
}

func (a *Auth) warn(message string) {
	if a != nil && a.logger != nil {
		a.logger.Warn(message)
	}
}

// Options returns an independent public configuration snapshot.
func (a *Auth) Options() Options {
	if a == nil {
		return Options{}
	}
	return cloneOptions(a.options.Options)
}

// Handler exposes Auth as a standard-library HTTP handler.
func (a *Auth) Handler() http.Handler { return a }

// ServeHTTP adapts net/http to the same immutable request contract used by
// fasthttp and Fiber. Transport-specific packages expose the same conversion
// independently for hosts that do not use the canonical Auth type.
func (a *Auth) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if a == nil || a.httpHandler == nil {
		nethttptransport.NewHandler(nil).ServeHTTP(writer, request)
		return
	}
	a.httpHandler.ServeHTTP(writer, request)
}
