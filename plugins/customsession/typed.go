package customsession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

// TypedEnrichFunc is the statically typed form of EnrichFunc.
type TypedEnrichFunc[Projection any] func(SessionData, *engine.Context) (Projection, error)

// TypedOptions binds the custom-session callback's concrete return type to the
// server factory.
type TypedOptions[Projection any] struct {
	Enrich                                 TypedEnrichFunc[Projection]
	ShouldMutateListDeviceSessionsEndpoint bool
}

// TypedFactory is both a regular production PluginFactory and the type token
// from which server custom-session projections are bound.
type TypedFactory[Projection any] struct {
	options TypedOptions[Projection]
}

// NewTypedFactory preserves the Enrich return type without changing the
// runtime custom-session plugin contract.
func NewTypedFactory[Projection any](options TypedOptions[Projection]) *TypedFactory[Projection] {
	return &TypedFactory[Projection]{options: options}
}

func (*TypedFactory[Projection]) PluginID() string { return "custom-session" }

func (*TypedFactory[Projection]) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *TypedFactory[Projection]) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	if factory == nil || factory.options.Enrich == nil {
		return engine.Plugin{}, errors.New("customsession: typed Enrich is required")
	}
	return New(Options{
		Enrich: func(data SessionData, ctx *engine.Context) (any, error) {
			return factory.options.Enrich(data, ctx)
		},
		ShouldMutateListDeviceSessionsEndpoint: factory.options.ShouldMutateListDeviceSessionsEndpoint,
		Runtime:                                Runtime{GetSession: host.GetSession},
	})
}

// TypedAuth retains the concrete custom-session projection on the server-side
// direct API while embedding the complete HTTP Auth runtime.
type TypedAuth[Projection any] struct {
	*singleauth.Auth
}

// BindAuth attaches the factory's projection type to an initialized runtime.
func (factory *TypedFactory[Projection]) BindAuth(auth *singleauth.Auth) (*TypedAuth[Projection], error) {
	if factory == nil || auth == nil {
		return nil, errors.New("customsession: typed auth requires an initialized auth")
	}
	return &TypedAuth[Projection]{Auth: auth}, nil
}

// API returns the custom get-session override plus every promoted base direct
// API method, including sign-up, sign-in, and sign-out.
func (auth *TypedAuth[Projection]) API() TypedDirectAPI[Projection] {
	if auth == nil || auth.Auth == nil {
		return TypedDirectAPI[Projection]{}
	}
	return TypedDirectAPI[Projection]{DirectAPI: auth.Auth.API()}
}

// TypedDirectAPI explicitly replaces GetSession's result type while embedding
// the stable base API so unrelated endpoints remain available.
type TypedDirectAPI[Projection any] struct {
	singleauth.DirectAPI
}

// TypedSessionResult is the concrete custom-session response and its response
// headers. Projection is never decoded through any.
type TypedSessionResult[Projection any] struct {
	Data    Projection
	Headers contract.Headers
}

// GetSession invokes the production overridden endpoint and decodes its exact
// JSON response into Projection.
func (api TypedDirectAPI[Projection]) GetSession(
	ctx context.Context,
	input singleauth.GetSessionInput,
) (*TypedSessionResult[Projection], error) {
	result, err := api.DirectAPI.Call(ctx, "getSession", singleauth.DirectCallInput{
		Method: http.MethodGet, Headers: input.Headers,
	})
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(result.Response.Body()), []byte("null")) {
		return nil, nil
	}
	var projection Projection
	if err := json.Unmarshal(result.Response.Body(), &projection); err != nil {
		return nil, err
	}
	return &TypedSessionResult[Projection]{
		Data: projection, Headers: result.Response.Headers(),
	}, nil
}

var _ singleauth.PluginFactory = (*TypedFactory[struct{}])(nil)
