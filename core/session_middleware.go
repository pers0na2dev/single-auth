package core

import (
	"errors"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	endpointSessionResolverKey = "single-auth.endpoint.session-resolver"
	endpointSessionStateKey    = "single-auth.endpoint.session"
)

type endpointSessionResolver func(*engine.Context) (*PluginSessionState, error)

// SessionMiddleware is the endpoint-local equivalent of upstream implementation's
// sessionMiddleware. It resolves a valid logical session and merges the
// session/user pair into request-local endpoint context for later middleware
// and the handler.
func SessionMiddleware(ctx *engine.Context) (engine.EndpointMiddlewareResult, error) {
	if ctx == nil {
		return engine.EndpointMiddlewareResult{}, unauthorized()
	}
	value, ok := ctx.Value(endpointSessionResolverKey)
	resolver, ok := value.(endpointSessionResolver)
	if !ok || resolver == nil {
		return engine.EndpointMiddlewareResult{}, contract.NewAPIError(
			contract.StatusInternalServerError,
			"SESSION_MIDDLEWARE_NOT_BOUND",
			"Session middleware is not bound to an auth runtime",
		).WithCause(errors.New("session middleware resolver is missing"))
	}
	state, err := resolver(ctx)
	if err != nil {
		return engine.EndpointMiddlewareResult{}, err
	}
	if state == nil || state.Session == nil || state.User == nil {
		return engine.EndpointMiddlewareResult{}, unauthorized()
	}
	bound := PluginSessionState{
		Session: cloneStorageRecord(state.Session),
		User:    cloneStorageRecord(state.User),
	}
	return engine.EndpointMiddlewareResult{Values: map[string]any{
		endpointSessionStateKey: bound,
	}}, nil
}

// SessionFromEndpointContext returns the logical session/user pair established
// by SessionMiddleware. Returned records are independent copies.
func SessionFromEndpointContext(ctx *engine.Context) (*PluginSessionState, bool) {
	if ctx == nil {
		return nil, false
	}
	value, ok := ctx.Value(endpointSessionStateKey)
	state, ok := value.(PluginSessionState)
	if !ok || state.Session == nil || state.User == nil {
		return nil, false
	}
	return &PluginSessionState{
		Session: cloneStorageRecord(state.Session),
		User:    cloneStorageRecord(state.User),
	}, true
}

// SetEndpointSession installs a logical session/user pair for the remainder of
// the current dispatch. Authentication plugins use it when a non-cookie
// credential has already been validated by a before hook.
func SetEndpointSession(ctx *engine.Context, state *PluginSessionState) {
	if ctx == nil {
		return
	}
	if state == nil || state.Session == nil || state.User == nil {
		ctx.Set(endpointSessionStateKey, nil)
		return
	}
	ctx.Set(endpointSessionStateKey, PluginSessionState{
		Session: cloneStorageRecord(state.Session),
		User:    cloneStorageRecord(state.User),
	})
}

func (a *Auth) initializeEndpointContext(ctx *engine.Context) error {
	if a == nil {
		return errors.New("single-auth: auth is not initialized")
	}
	requestContext, err := a.requestAuthContext(ctx)
	if err != nil {
		return err
	}
	ctx.Set(endpointAuthContextKey, requestContext)
	ctx.Set(endpointSessionResolverKey, endpointSessionResolver(func(endpoint *engine.Context) (*PluginSessionState, error) {
		return a.resolvePluginSession(endpoint, PluginSessionRequired)
	}))
	return nil
}
