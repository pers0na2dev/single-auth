// Package customplugin contains a compile-checked PluginFactory example.
package customplugin

import (
	"fmt"
	"net/http"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

// Factory contributes an authenticated who-am-I endpoint.
type Factory struct{}

// NewFactory returns one immutable plugin factory.
func NewFactory() *Factory { return &Factory{} }

// PluginID is the stable plugin registry identity.
func (*Factory) PluginID() string { return "who-am-i" }

// Schema runs before the root adapter is created. This plugin stores no data.
func (*Factory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

// Build binds the descriptor to root session and serialization services.
func (*Factory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	if host.ResolveSession == nil || host.SerializeUser == nil {
		return engine.Plugin{}, fmt.Errorf("who-am-i: session host is incomplete")
	}

	return engine.Plugin{
		ID:      "who-am-i",
		Version: "1.0.0",
		Endpoints: []engine.Endpoint{{
			Name:        "whoAmI",
			Path:        "/who-am-i",
			Methods:     []string{http.MethodGet},
			OperationID: "whoAmI",
			Handler: func(ctx *engine.Context) (contract.Response, error) {
				state, err := host.ResolveSession(ctx, singleauth.PluginSessionAuthoritative)
				if err != nil {
					return contract.Response{}, err
				}
				return contract.JSONResponse(http.StatusOK, map[string]any{
					"user": host.SerializeUser(state.User),
				})
			},
		}},
	}, nil
}

var _ singleauth.PluginFactory = (*Factory)(nil)
